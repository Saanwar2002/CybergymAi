"""Run a fully local, harmless patch-review workflow demonstration."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnresearch.reporting import write_run_report
from vulnresearch.sandbox import SandboxError, run_task
from vulnresearch.task import ResearchTask
from vulnresearch.workflow.evidence import create_evidence_bundle
from vulnresearch.workflow.lifecycle import ActorRole, LifecycleState
from vulnresearch.workflow.session import WorkflowSession


def _write_run_bundle(
    task: ResearchTask,
    output_root: Path,
    report_directory: Path,
    bundle_path: Path,
) -> tuple[Path, int]:
    result = run_task(task)
    report_path = write_run_report(task, result, report_directory)
    relative = lambda path: path.resolve().relative_to(output_root).as_posix()
    bundle = create_evidence_bundle(
        task.task_id,
        {
            "report": relative(report_path),
            "stdout": relative(report_path.parent / "stdout.txt"),
            "stderr": relative(report_path.parent / "stderr.txt"),
        },
        artifact_root=output_root,
        output_path=bundle_path,
    )
    return bundle, result.returncode


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
        required=True,
        help="Human note confirming review of the baseline evidence.",
    )
    parser.add_argument(
        "--final-decision",
        choices=("accepted", "rejected"),
        required=True,
        help="Human patch decision after reviewing the candidate test evidence.",
    )
    parser.add_argument("--final-note", required=True, help="Human final decision note.")
    parser.add_argument(
        "--output-dir",
        default="artifacts/demo",
        help="New output directory beneath the repository root.",
    )
    args = parser.parse_args()
    if not args.allow_execution:
        parser.error("the demo runs Docker fixtures and requires --allow-execution")

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

        baseline_bundle, baseline_exit = _write_run_bundle(
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
            decision_note=f"Baseline fixture exited with code {baseline_exit}.",
        )
        session = session.advance(
            LifecycleState.EVIDENCE_REVIEWED,
            actor=args.reviewer,
            actor_role=ActorRole.HUMAN,
            evidence_refs=[baseline_ref],
            decision_note=args.evidence_review_note,
        )

        if baseline_exit == 0:
            session = session.advance(
                LifecycleState.INCONCLUSIVE,
                actor=args.reviewer,
                actor_role=ActorRole.HUMAN,
                evidence_refs=[baseline_ref],
                decision_note="The baseline unexpectedly passed; no regression was demonstrated.",
            )
            print(json.dumps({"state": session.record.state.value, "audit": str(session.audit_path)}, indent=2))
            return

        session = session.propose_patch(
            "examples/fixtures/patch_demo/fix.diff",
            artifact_root=repo_root,
            bundle_path=output_root / "patch-proposal.json",
            actor=args.reviewer,
            actor_role=ActorRole.HUMAN,
            decision_note="Reviewed the harmless fixture diff; the candidate workspace contains the proposed change.",
        )

        candidate_bundle, candidate_exit = _write_run_bundle(
            candidate_task,
            repo_root,
            output_root / "runs",
            output_root / "candidate-evidence.json",
        )
        session = session.record_patch_test(candidate_bundle, artifact_root=repo_root)

        if args.final_decision == "accepted":
            if candidate_exit != 0:
                raise ValueError(
                    "cannot accept the patch: candidate regression fixture did not pass"
                )
            final_state = LifecycleState.HUMAN_ACCEPTED
        else:
            final_state = LifecycleState.HUMAN_REJECTED
        candidate_ref = f"bundle:{candidate_bundle.relative_to(repo_root).as_posix()}"
        session = session.advance(
            final_state,
            actor=args.reviewer,
            actor_role=ActorRole.HUMAN,
            evidence_refs=[candidate_ref],
            decision_note=args.final_note,
        )
        print(
            json.dumps(
                {
                    "task_id": session.record.task_id,
                    "state": session.record.state.value,
                    "baseline_exit_code": baseline_exit,
                    "candidate_exit_code": candidate_exit,
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
