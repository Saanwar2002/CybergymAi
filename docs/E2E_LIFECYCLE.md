# CyberGym-E2E-style lifecycle workflow

This project implements a local, auditable workflow inspired by the defensive
lifecycle described by CyberGym-E2E. It is not an official benchmark runner and
does not reproduce the upstream evaluation protocol.

## States and decision gates

`imported -> triaged -> plan_approved -> reproduction_attempted -> evidence_reviewed
-> patch_proposed -> patch_tested -> human_accepted | human_rejected | inconclusive`

- Only a human may approve a plan, review evidence, or make a final decision.
- Reproduction and patch-test completion must be recorded by the system actor.
- An agent may propose a patch but cannot approve its own plan or result.
- Evidence review and patch-test completion require evidence references. Final
  acceptance/rejection also requires a written decision note and evidence references.
- Terminal states cannot be reopened; create a new task/run record for a fresh attempt.

## Persisted workflow sessions

`WorkflowSession.create(task_id, audit_path)` creates a new lifecycle record and
its exclusive JSONL audit store. `advance(...)` validates one transition and
persists its event before returning a new immutable session view.
`WorkflowSession.open(audit_path)` verifies the complete hash chain and every
transition before restoring a session.

### Patch proposal and test evidence

- `propose_patch(...)` accepts a local `.patch` or `.diff` artifact, creates a
  bounded evidence bundle, and records its bundle reference in the patch-proposal
  event. It does not apply the patch.
- `record_patch_test(...)` verifies a task-matched evidence bundle containing
  `report`, `stdout`, and `stderr`. It checks that the report's task ID,
  status, and exit code are consistent before recording a system-owned
  `patch_tested` event.
- A failed test is still recorded as a test attempt; it is not treated as patch
  acceptance. A human must make the final decision.

See [local evidence bundle handling](EVIDENCE_BUNDLES.md) for bounded manifests
that record relative artifact paths, sizes, and SHA-256 digests. Evidence
references remain identifiers; reviewers must inspect the underlying evidence.

## Audit guarantees and limitations

The JSONL event store verifies a SHA-256 hash chain and revalidates each event
against actor-role and lifecycle policy. This detects edits but is not tamper-proof:
a person able to rewrite the entire file can recompute the chain. Protect files
with filesystem permissions and trusted archival storage. The store is
single-writer; concurrent writers must be serialized by the caller.

The workflow records metadata and verifies supplied reports only. It does not
apply patches, execute project regression tests, run the official benchmark
evaluator, generate PoCs, or interpret vulnerability claims. A regression report
must come from a separately approved sandbox run; human review remains required.
