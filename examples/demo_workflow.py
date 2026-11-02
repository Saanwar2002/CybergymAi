"""Run a fully local, harmless patch-review workflow demonstration."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnresearch.reporting import write_run_report
from vulnresearch.sandbox import SandboxError, run_task
from vulnresearch.task import ResearchTask
from vulnresearch.workflow.evidence import create_evidence_bundle
from vulnresearch.workflow.lifecycle import ActorRole, LifecycleState
from vulnresearch.workflow.session import WorkflowSession


def _relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _write_run_bundle(
    task: ResearchTask,
    output_root: Path,
    report_directory: Path,
    bundle_path: Path,
):
    result = run_task(task)
    report_path = write_run_report(task, result, report_directory)
    bundle = create_evidence_bundle(
        task.task_id,
        {
            "report": _relative_path(report_path, output_root),
            "stdout": _relative_path(report_path.parent / "stdout.txt", output_root),
            "stderr": _relative_path(report_path.parent / "stderr.txt", output_root),
        },
        artifact_root=output_root,
        output_path=bundle_path,
    )
    return bundle, result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Demonstrate a human-governed workflow using harmless local fixtures."
    )
    parser.add_argument(
        "--allow-execution",
        action="store_true",
        help="Explicitly opt in to the two offline Docker fixture runs.",
    )
    parser.add_argument("--reviewer", required=True, help="Human reviewer identifier.")
    parser.add_argument("--approval-note", required=True, help="Human plan approval note.")
    parser.add_argument(
        "--evidence-review-note",
        help="Optional scripted reviewer input; omit to prompt interactively after the baseline run.",
    )
    parser.add_argument(
        "--final-decision",
        choices=("accepted", "rejected"),
        help="Optional scripted final decision; omit to prompt after candidate evidence is shown.",
    )
    parser.add_argument(
        "--final-note",
        help="Optional scripted final review note; omit to prompt interactively.",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/demo",
        help="New output directory beneath the repository root.",
    )
    args = parser.parse_args()
    if not args.allow_execution:
        parser.error("the demo runs Docker fixtures and requires --allow-execution")
    scripted_inputs = (
        args.evidence_review_note,
        args.final_decision,
        args.final_note,
    )
    if any(value is not None for value in scripted_inputs) and not all(
        value is not None for value in scripted_inputs
    ):
        parser.error(
            "provide all of --evidence-review-note, --final-decision, and --final-note together"
        )

    repo_root = Path(__file__).resolve().parents[1]
    output_root = (repo_root / args.output_dir).resolve()
    try:
        output_root.relative_to(repo_root)
    except ValueError as exc:
        parser.error(f"--output-dir must remain beneath the repository: {exc}")

    baseline_task = ResearchTask.from_file(
        repo_root / "examples/fixtures/patch_demo/baseline_task.json",
        workspace_root=repo_root,
    )
    candidate_task = ResearchTask.from_file(
        repo_root / "examples/fixtures/patch_demo/candidate_task.json",
        workspace_root=repo_root,
    )
    if baseline_task.task_id != candidate_task.task_id:
        parser.error("baseline and candidate fixture task IDs must match")

    try:
        session = WorkflowSession.create(
            baseline_task.task_id, output_root / "audit.jsonl"
        )
        session = session.advance(
            LifecycleState.TRIAGED,
            actor="demo-workflow",
            actor_role=ActorRole.SYSTEM,
        )
        session = session.advance(
            LifecycleState.PLAN_APPROVED,
            actor=args.reviewer,
            actor_role=ActorRole.HUMAN,
            decision_note=args.approval_note,
        )

        baseline_bundle, baseline_result = _write_run_bundle(
            baseline_task,
            repo_root,
            output_root / "runs",
            output_root / "baseline-evidence.json",
        )
        baseline_ref = f"bundle:{baseline_bundle.relative_to(repo_root).as_posix()}"
        session = session.advance(
            LifecycleState.REPRODUCTION_ATTEMPTED,
            actor="sandbox-runner",
            actor_role=ActorRole.SYSTEM,
            evidence_refs=[baseline_ref],
            decision_note=f"Baseline fixture exited with code {baseline_result.returncode}.",
        )
        print(
            json.dumps(
                {
                    "baseline_exit_code": baseline_result.returncode,
                    "baseline_stdout": baseline_result.stdout,
                    "baseline_stderr": baseline_result.stderr,
                    "baseline_evidence": baseline_ref,
                },
                indent=2,
            )
        )
        evidence_review_note = (
            args.evidence_review_note
            if args.evidence_review_note is not None
            else input("Review the baseline evidence above. Enter your review note: ").strip()
        )
        if not evidence_review_note:
            raise ValueError("baseline evidence review note cannot be empty")
        expected_baseline_failure = (
            baseline_result.returncode == 1
            and "baseline mismatch" in baseline_result.stderr
        )
        if not expected_baseline_failure:
            session = session.advance(
                LifecycleState.EVIDENCE_REVIEWED,
                actor=args.reviewer,
                actor_role=ActorRole.HUMAN,
                evidence_refs=[baseline_ref],
                decision_note=evidence_review_note,
            )
            session = session.advance(
                LifecycleState.INCONCLUSIVE,
                actor=args.reviewer,
                actor_role=ActorRole.HUMAN,
                evidence_refs=[baseline_ref],
                decision_note="The baseline result was inconclusive; no patch decision was made.",
            )
            print(
                json.dumps(
                    {
                        "state": session.record.state.value,
                        "baseline_exit_code": baseline_result.returncode,
                        "audit": str(session.audit_path),
                    },
                    indent=2,
                )
            )
            return
        session = session.advance(
            LifecycleState.EVIDENCE_REVIEWED,
            actor=args.reviewer,
            actor_role=ActorRole.HUMAN,
            evidence_refs=[baseline_ref],
            decision_note=evidence_review_note,
        )

        session = session.propose_patch(
            "examples/fixtures/patch_demo/fix.diff",
            artifact_root=repo_root,
            bundle_path=output_root / "patch-proposal.json",
            actor=args.reviewer,
            actor_role=ActorRole.HUMAN,
            decision_note="Reviewed the harmless fixture diff; the candidate workspace contains the proposed change.",
        )
        patch_ref = session.record.events[-1].evidence_refs[0]
        patch_text = (
            repo_root / "examples/fixtures/patch_demo/fix.diff"
        ).read_text(encoding="utf-8")
        print(json.dumps({"patch_proposal": patch_ref, "diff": patch_text}, indent=2))

        candidate_bundle, candidate_result = _write_run_bundle(
            candidate_task,
            repo_root,
            output_root / "runs",
            output_root / "candidate-evidence.json",
        )
        session = session.record_patch_test(candidate_bundle, artifact_root=repo_root)
        candidate_ref = f"bundle:{candidate_bundle.relative_to(repo_root).as_posix()}"
        print(
            json.dumps(
                {
                    "candidate_exit_code": candidate_result.returncode,
                    "candidate_stdout": candidate_result.stdout,
                    "candidate_stderr": candidate_result.stderr,
                    "candidate_evidence": candidate_ref,
                },
                indent=2,
            )
        )
        final_decision = (
            args.final_decision
            if args.final_decision is not None
            else input("After reviewing candidate evidence, enter ACCEPT or REJECT: ").strip().lower()
        )
        if final_decision not in {"accepted", "rejected", "accept", "reject"}:
            raise ValueError("final decision must be ACCEPT or REJECT")
        final_note = (
            args.final_note
            if args.final_note is not None
            else input("Enter your final human review note: ").strip()
        )
        if not final_note:
            raise ValueError("final decision note cannot be empty")
        if final_decision in {"accept", "accepted"}:
            if (
                candidate_result.returncode != 0
                or "candidate regression check passed" not in candidate_result.stdout
            ):
                raise ValueError(
                    "cannot accept the patch: candidate regression fixture did not pass"
                )
            final_state = LifecycleState.HUMAN_ACCEPTED
        else:
            final_state = LifecycleState.HUMAN_REJECTED
        session = session.advance(
            final_state,
            actor=args.reviewer,
            actor_role=ActorRole.HUMAN,
            evidence_refs=[candidate_ref],
            decision_note=final_note,
        )
        print(
            json.dumps(
                {
                    "task_id": session.record.task_id,
                    "state": session.record.state.value,
                    "baseline_exit_code": baseline_result.returncode,
                    "candidate_exit_code": candidate_result.returncode,
                    "audit": str(session.audit_path),
                    "baseline_evidence": baseline_ref,
                    "candidate_evidence": candidate_ref,
                },
                indent=2,
            )
        )
    except (ValueError, OSError, SandboxError, RuntimeError) as exc:
        parser.exit(2, f"demo failed: {exc}\n")


if __name__ == "__main__":
    main()
