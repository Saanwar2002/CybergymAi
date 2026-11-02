# Independent security review checklist

**Status: Not yet reviewed.**

This checklist is a handoff for an independent security reviewer. It is not a completed
audit, certification, or assertion that the controls below are sufficient. Do not mark
the review complete until a reviewer has examined the code at a specific commit, recorded
evidence, and signed off.

## Review scope

- [ ] Record the reviewed commit SHA, date, reviewer identity, and review environment.
- [ ] Confirm the intended scope remains explicitly authorized local fixtures only.
- [ ] Confirm no public-target scanning, benchmark submission, PoC generation, or autonomous
  patch application has been introduced.
- [ ] Review all dependencies and the provenance of the pinned Docker image digest.

## Execution boundary

- [ ] Inspect `authorize_task` and task-manifest parsing for fail-open paths, malformed
  inputs, unknown/duplicate JSON fields, and workspace-root escapes.
- [ ] Inspect Docker command construction: network isolation, read-only root/workspace,
  non-root identity, capability drop, no-new-privileges, private IPC, PID/memory/swap/CPU/
  file-size/tmpfs limits, timeout, output bounds, and cleanup.
- [ ] Confirm `--pull never` fails closed when the exact pinned image is absent.
- [ ] Assess Docker daemon privilege, host-kernel sharing, bind mounts, and the need for a
  disposable VM or stronger runtime boundary.
- [ ] Verify the workload cannot access host credentials, Docker socket, cloud metadata,
  unrelated filesystem paths, or sensitive environment variables.
- [ ] Test path edge cases including symlinks, unusual path characters, long paths, and
  concurrent filesystem changes.
- [ ] Assess whether process timeout and cleanup remain reliable if the Docker CLI or daemon
  becomes unresponsive.

## Data, model, and evidence handling

- [ ] Review LLM prompt construction, provider error handling, secret redaction, and
  prompt-injection boundaries.
- [ ] Confirm remote LLM endpoints require HTTPS, URL credentials/query/fragment values
  are rejected, loopback HTTP is limited to local development, and request timeouts are bounded.
- [ ] Confirm model output cannot authorize execution or directly invoke tools, and all structured plan fields have explicit item-count and character limits.
- [ ] Review run-report contents for secrets and sensitive path disclosure.
- [ ] Confirm duplicate JSON keys are rejected in task manifests, evidence manifests,
  run reports, and lifecycle audit events.
- [ ] Review evidence-bundle path confinement, size limits, hashing, and file-race behavior.
- [ ] Review audit-chain verification, append failure behavior, permissions, and the
  documented single-writer limitation.
- [ ] Confirm actor roles are not mistaken for authenticated human identity or signed
  approvals.
- [ ] Review data retention, backups, and any external LLM provider data-processing terms.

## Benchmark adapters and workflow

- [ ] Confirm CyberGym and CyberGym-E2E adapters only expose the intended metadata.
- [ ] Confirm ground-truth patch fields, PoCs, scripts, archives, and benchmark execution
  are not exposed or invoked by metadata adapters.
- [ ] Review upstream code, dataset, and underlying-project license obligations separately.
- [ ] Confirm patch-test reports are task-matched, status/exit-code consistent, and their
  stdout/stderr paths, sizes, and hashes match the bundled evidence artifacts.
- [ ] Confirm failed tests cannot lead to automatic acceptance and final decisions remain
  human-controlled.
- [ ] Run the complete harmless baseline/candidate workflow demo and inspect its audit
  events and evidence bundles.

## Findings

For each finding, record: severity, affected file/line or component, reproduction steps,
impact, evidence, recommendation, owner, and disposition. Do not silently waive a finding.

## Reviewer sign-off

- Reviewer:
- Organization / role:
- Reviewed commit SHA:
- Review date:
- Overall verdict: **Not reviewed**
- Open critical/high findings:
- Accepted residual risks:
- Conditions before any real benchmark workload:

A positive sign-off must be recorded by the independent reviewer. Project maintainers
must not mark this checklist complete solely because CI passes.
