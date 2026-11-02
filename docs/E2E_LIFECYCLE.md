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
- Evidence review requires evidence references. Final acceptance/rejection also
  requires a written decision note and evidence references.
- Terminal states cannot be reopened; create a new task/run record for a fresh attempt.

Every successful transition appends an immutable event to the returned record.
Events include the prior and new state, actor and role, UTC timestamp, evidence
references, and decision note. Invalid transitions fail closed.

## Persistent audit store

The `vulnresearch.workflow.store` module provides a JSON Lines event store:

1. `create_lifecycle_store(task_id, path)` creates a new file with exclusive
   creation and owner-only file permissions; it never overwrites an existing file.
2. `append_lifecycle_event(path, record)` appends exactly one new event, after
   verifying that the supplied immutable record extends the stored history.
3. `verify_lifecycle_store(path)` verifies the hash chain and revalidates every
   event against the lifecycle transition and actor-role policy.

Each event includes the previous event hash and its own SHA-256 hash. This makes
edits detectable, but is not tamper-proof storage: a person able to rewrite the
entire file can recompute the chain. Use filesystem access controls and trusted
archival storage for stronger audit guarantees. The store is intended for a
single writer; concurrent writers must be serialized by the caller.

## Scope and limitations

This is a local workflow primitive. It does not execute benchmark tasks, generate
PoCs, apply patches, run project test suites, or implement the upstream four-stage
evaluator. Evidence references are opaque identifiers; this module does not
copy or verify referenced artifact contents.
