"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .execution.gce_image import (
    validate_gce_image_release_manifest,
    verify_dsse_slsa_provenance_envelope,
    verify_dsse_slsa_provenance_for_build_policy,
    verify_gce_image_release_manifest_signature,
)
from .execution.gce_image_recipe import validate_gce_image_reproducibility_recipe
from .execution.gce_image_build import (
    validate_gce_image_build_policy,
    verify_gce_image_build_lock,
)
from .llm import create_plan
from .policy.scope import authorize_task
from .reporting import write_run_report
from .sandbox import SandboxError, run_task
from .task import ResearchTask


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous JSON objects instead of silently keeping the last key."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant is not permitted: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnresearch")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("validate", "plan", "run", "validate-image-build-policy", "validate-image-build-lock", "validate-image-manifest", "verify-image-manifest", "verify-image-provenance", "verify-image-build-evidence"):
        item = sub.add_parser(action)
        if action == "validate-image-build-recipe":
            item.add_argument("recipe_file")
        elif action in ("validate-image-build-policy", "validate-image-build-lock"):
            item.add_argument("policy_file")
            if action == "validate-image-build-lock":
                item.add_argument("lock_file")
        elif action == "verify-image-build-evidence":
            item.add_argument("policy_file")
            item.add_argument("manifest_file")
            item.add_argument("envelope_file")
            item.add_argument("public_key_file")
            item.add_argument("--trusted-key-sha256", required=True)
        elif action in ("validate-image-manifest", "verify-image-manifest", "verify-image-provenance", "validate-image-build-recipe"):
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
        if args.action == "validate-image-build-recipe":
            recipe_data = json.loads(
                Path(args.recipe_file).read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_constant,
            )
            recipe = validate_gce_image_reproducibility_recipe(recipe_data)
            print(json.dumps({
                "valid": True,
                "schema_version": recipe.schema_version,
                "base_image_self_link": recipe.base_image_self_link,
                "source_commit": recipe.source_commit,
                "input_lock_sha256": recipe.input_lock_sha256,
                "builder_image": recipe.builder_image,
                "toolchain_version": recipe.toolchain_version,
                "build_type": recipe.build_type,
                "source_date_epoch": recipe.source_date_epoch,
                "platform": recipe.platform,
                "recipe_sha256": recipe.recipe_sha256,
                "build_executed": False,
            }, indent=2))
            return
        if args.action in ("validate-image-build-policy", "validate-image-build-lock"):
            policy_data = json.loads(
                Path(args.policy_file).read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_constant,
            )
            if args.action == "validate-image-build-lock":
                lock_bytes = Path(args.lock_file).read_bytes()
                policy = verify_gce_image_build_lock(policy_data, lock_bytes)
                lock_result = {
                    "lock_verified": True,
                    "lock_bytes": len(lock_bytes),
                }
            else:
                policy = validate_gce_image_build_policy(policy_data)
                lock_result = {}
            print(json.dumps({
                "valid": True,
                **lock_result,
                "schema_version": policy.schema_version,
                "base_image_self_link": policy.base_image_self_link,
                "source_commit": policy.source_commit,
                "input_lock_sha256": policy.input_lock_sha256,
                "builder_id": policy.builder_id,
                "build_type": policy.build_type,
                "scanner_name": policy.scanner_name,
                "scanner_version": policy.scanner_version,
                "max_critical_findings": policy.max_critical_findings,
                "max_high_findings": policy.max_high_findings,
            }, indent=2))
            return
        if args.action == "verify-image-build-evidence":
            policy = json.loads(
                Path(args.policy_file).read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_constant,
            )
            manifest = json.loads(
                Path(args.manifest_file).read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_constant,
            )
            envelope = json.loads(
                Path(args.envelope_file).read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_constant,
            )
            release = verify_dsse_slsa_provenance_for_build_policy(
                envelope,
                release_manifest=manifest,
                build_policy=policy,
                public_key_pem=Path(args.public_key_file).read_bytes(),
                expected_public_key_sha256=args.trusted_key_sha256,
            )
            print(json.dumps({
                "valid": True,
                "build_policy_verified": True,
                "provenance_verified": True,
                "image_self_link": release.image_self_link,
                "build_commit": release.build_commit,
                "artifact_sha256": release.artifact_sha256,
                "builder_id": policy["builder_id"],
                "build_type": policy["build_type"],
                "input_lock_sha256": policy["input_lock_sha256"],
            }, indent=2))
            return
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
