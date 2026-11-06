"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .execution.gce_image_build import validate_gce_image_build_policy
from .execution.gce_image import (
    validate_gce_image_release_manifest,
    verify_dsse_slsa_provenance_envelope,
    verify_gce_image_release_manifest_signature,
)
from .llm import create_plan
from .policy.scope import authorize_task
from .reporting import write_run_report
from .sandbox import SandboxError, run_task
from .task import ResearchTask


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnresearch")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("validate", "plan", "run", "validate-image-build-policy", "validate-image-manifest", "verify-image-manifest", "verify-image-provenance"):
        item = sub.add_parser(action)
        if action in ("validate-image-manifest", "verify-image-manifest", "verify-image-provenance"):
            item.add_argument("manifest_file")
            if action == "verify-image-manifest":
                item.add_argument("signature_file")
                item.add_argument("public_key_file")
                item.add_argument("--trusted-key-sha256", required=True)
            elif action == "verify-image-provenance":
                item.add_argument("envelope_file")
                item.add_argument("public_key_file")
                item.add_argument("--trusted-key-sha256", required=True)
                item.add_argument("--expected-builder-id", required=True)
        else:
            item.add_argument("task_file")
        if action == "run":
            item.add_argument(
                "--allow-execution",
                action="store_true",
                help="Explicitly authorize running the approved local fixture in Docker",
            )
            item.add_argument(
                "--output-dir",
                default="artifacts/runs",
                help="Directory for run reports and bounded output artifacts",
            )
    args = parser.parse_args()
    try:
        if args.action in ("validate-image-manifest", "verify-image-manifest", "verify-image-provenance"):
            manifest = json.loads(Path(args.manifest_file).read_text(encoding="utf-8"))
            if args.action == "verify-image-provenance":
                envelope = json.loads(Path(args.envelope_file).read_text(encoding="utf-8"))
                release = verify_dsse_slsa_provenance_envelope(
                    envelope,
                    release_manifest=manifest,
                    expected_builder_id=args.expected_builder_id,
                    public_key_pem=Path(args.public_key_file).read_bytes(),
                    expected_public_key_sha256=args.trusted_key_sha256,
                )
            elif args.action == "verify-image-manifest":
                release = verify_gce_image_release_manifest_signature(
                    manifest,
                    signature_base64=Path(args.signature_file).read_text(encoding="ascii").strip(),
                    public_key_pem=Path(args.public_key_file).read_bytes(),
                    expected_public_key_sha256=args.trusted_key_sha256,
                )
            else:
                release = validate_gce_image_release_manifest(manifest)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "signature_verified": args.action == "verify-image-manifest",
                        "provenance_verified": args.action == "verify-image-provenance",
                        "image_self_link": release.image_self_link,
                        "source_image_self_link": release.source_image_self_link,
                        "build_commit": release.build_commit,
                        "build_id": release.build_id,
                        "artifact_sha256": release.artifact_sha256,
                        "provenance_uri": release.provenance_uri,
                        "scanner": release.scanner,
                        "scan_timestamp": release.scan_timestamp,
                        "critical_findings": 0,
                        "high_findings": 0,
                    },
                    indent=2,
                )
            )
            return
        task = ResearchTask.from_file(args.task_file)
        decision = authorize_task(task)
        if args.action == "validate":
            print(
                json.dumps(
                    {
                        "valid": True,
                        "task": task.name,
                        "policy_allowed": decision.allowed,
                        "policy_reason": decision.reason,
                    },
                    indent=2,
                )
            )
            if not decision.allowed:
                sys.exit(2)
        elif args.action == "plan":
            if not decision.allowed:
                parser.exit(2, f"blocked by policy: {decision.reason}\n")
            print(json.dumps(create_plan(task.name, task.description).to_dict(), indent=2))
        elif args.action == "run":
            if not decision.allowed:
                parser.exit(2, f"blocked by policy: {decision.reason}\n")
            if not args.allow_execution:
                parser.error("run requires --allow-execution; execution is opt-in")
            result = run_task(task)
            report_path = write_run_report(task, result, args.output_dir)
            print(
                json.dumps(
                    {
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "stdout_truncated": result.stdout_truncated,
                        "stderr_truncated": result.stderr_truncated,
                        "duration_seconds": result.duration_seconds,
                        "report": str(report_path),
                    },
                    indent=2,
                )
            )
            if result.returncode:
                sys.exit(result.returncode)
    except (ValueError, OSError, SandboxError, KeyError, RuntimeError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
