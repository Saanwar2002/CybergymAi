# Harmless end-to-end workflow demonstration

This demo exercises the local workflow with a deliberately failing baseline and a passing
candidate for a trivial string-normalization fixture. It is **not** a vulnerability
reproduction, an official benchmark, or an exploit demonstration.

## Prerequisites

- Install the project: `pip install -e ".[dev]"`.
- Configure `VULNRESEARCH_SANDBOX_IMAGE` with a reviewed
  `python:3.11-slim@sha256:<digest>` reference.
- Ensure Docker is running in a local development environment.
- Run from the repository root in an interactive terminal.

## Run

```bash
python examples/demo_workflow.py \
  --allow-execution \
  --reviewer "local-reviewer" \
  --approval-note "I reviewed and approve this harmless local fixture plan."
```

The script requires explicit execution opt-in and a human plan-approval note before it
starts. It runs two separate offline Docker jobs:

1. The baseline fixture is expected to fail with a normalization mismatch.
2. The candidate fixture is expected to pass after the proposed change.

After the baseline run, the script displays its output and evidence reference and asks the
human reviewer to enter an evidence-review note. After the candidate run, it displays the
candidate report/log evidence and asks the reviewer to enter `ACCEPT` or `REJECT`, plus a
final decision note. An acceptance is refused unless the candidate exits successfully and
emits the expected test marker.

The diff is captured as a patch proposal artifact; the script does not apply it. The
candidate workspace is a separate, pre-prepared harmless fixture containing the
corresponding change. The final accepted state is written only after the human enters
`ACCEPT` following the candidate evidence display. Choose `REJECT` if the human review
does not accept the candidate result.

If the baseline result differs from the expected failure, the workflow is marked
inconclusive and no patch is accepted.

## Outputs

A new `artifacts/demo/` directory contains the hash-chained `audit.jsonl`, run reports,
bounded stdout/stderr artifacts, reproduction and candidate evidence bundles, and the
patch-proposal bundle. The output directory is exclusive: use a new directory for each
demo run or archive/remove the previous local demo artifacts first.

All commands execute against checked-in local fixture directories. Networking is disabled
inside Docker. The demo does not access external targets, download benchmark datasets,
generate PoCs, or invoke an upstream evaluator.
