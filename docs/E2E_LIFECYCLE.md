# CyberGym-E2E-style lifecycle workflow

This project implements a local, auditable workflow inspired by the defensive
lifecycle described by CyberGym-E2E. It is not an official benchmark runner and
does not reproduce the upstream evaluation protocol.

## States

`imported -> triaged -> plan_approved -> reproduction_attempted -> evidence_reviewed
-> patch_proposed -> patch_tested -> human_accepted | human_rejected | inconclusive`

An evidence review may also conclude `inconclusive`. Terminal states cannot be
reopened; create a new task/run record for a fresh attempt.

## Human decision gates

- Only a human may approve a plan.
- Only a human may mark evidence as reviewed.
- Only a human may accept or reject a patch, or mark a final result inconclusive.
- Final acceptance/rejection requires both a written decision note and evidence
  references.
- An agent may submit a patch proposal but cannot approve its own plan or result.
- System actors may record mechanical workflow steps, but cannot make human decisions.

Every successful transition returns a new immutable record and appends an event
containing the prior state, new state, actor, role, UTC timestamp, evidence
references, and decision note. Invalid transitions fail closed.

## Scope

The current implementation is an in-memory state-transition primitive. It does
not yet persist events to disk, execute benchmark tasks, generate PoCs, apply
patches, run project test suites, or implement the upstream four-stage evaluator.
The next integration step is to connect these records to run reports and a
reviewable artifact store.

## References

- [Official CyberGym-E2E repository](https://github.com/sunblaze-ucb/cybergym-e2e)
- [CyberGym-E2E overview](https://www.cybergym.io/cybergym-e2e/)
