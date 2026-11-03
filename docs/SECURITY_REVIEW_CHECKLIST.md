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
- [ ] Inspect `build_docker_command` caller-supplied workspace handling; confirm no override can
  widen or redirect the manifest-approved workspace bind mount.
- [ ] Inspect `execution/runner.py` and the provider-neutral backend contract; verify that
  declared VM capabilities are backed by the actual deployment, not configuration
  assertions alone. Confirm the runner has no fallback to host execution or host-Docker
  when a VM capability is missing.
- [ ] Verify the backend enforces CPU, memory, disk, process, staged-input, and output
  limits during execution; confirm reported usage metrics come from trusted host-side
  measurements and cannot be forged by the guest.
- [ ] Verify every staged input matches its manifest SHA-256 and size, is placed only at
  its canonical guest-relative path, and is mounted/read-only; reject path collisions,
  traversal, symlinks, and unlisted host files.
- [ ] Verify output collection reads only from the fixed guest output root, rejects
  symlinks/path traversal, hashes the exact collected bytes, limits the manifest to 64
  artifacts, and enforces the combined stdout/stderr/artifact output limit before
  publishing artifacts to the host.
- [ ] Persist the versioned JSON execution manifest with every run record and lifecycle
  evidence reference; recompute its canonical SHA-256 from the exact command, policy,
  limits, and input manifest. Treat the digest as correlation metadata, not authentication.
- [ ] Verify local-fixture run reports, benchmark reports, evidence bundle manifests, and
  lifecycle store creation
  are atomic and crash-durable: fsync staged file contents and the staging directory
  before publication, then fsync the parent directory after rename/link and staging
  cleanup. Stdout/stderr evidence must be capped at 5 MiB each with accurate
  truncation flags and hashes over the exact stored bytes; do not claim uncollected output
  artifact payloads are present.
- [ ] At lifecycle ingestion, validate backend terminal status against report status and
  exit code; validate finite duration, every resource metric against the approved manifest,
  staged-input byte totals, output artifact schema/path uniqueness, and combined output
  bytes before accepting benchmark reproduction or patch-test evidence.
- [ ] Verify benchmark reproduction and patch-test lifecycle events reference verified
  evidence bundles containing the exact report and logs; reconstruct the versioned
  execution specification, enforce mandatory disposable-VM requirements, recompute its
  digest, and reject modified reports/logs before appending lifecycle events.
- [ ] Confirm the report and log bytes parsed/hashed before evidence-bundle creation are
  exactly the bytes recorded in the resulting bundle manifest; test mutation between
  validation and bundle publication for every referenced artifact.
- [ ] Enforce the absolute 10 MiB UTF-8 byte ceiling on each backend stdout/stderr field
  before any policy-layer encoding, logging, or report processing; retain the stricter
  per-run limit from the approved execution specification.
- [ ] Confirm unverified cleanup blocks acceptance of a run result; completed/failed
  results have matching zero/non-zero exit codes, timed-out results never claim exit 0,
  and blocked results never claim a process exit code.
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
- [ ] Confirm normal Docker exits are followed by an explicit container-removal check;
  a lingering container is force-removed and any uncertain cleanup blocks result acceptance.
- [ ] Assess whether process timeout and cleanup remain reliable if the Docker CLI or daemon
  becomes unresponsive.

## Data, model, and evidence handling

- [ ] Review LLM prompt construction, provider error handling, secret redaction, and
  prompt-injection boundaries.
- [ ] Confirm provider response bodies are streamed and capped before JSON parsing.
- [ ] Confirm remote LLM endpoints require HTTPS, URL credentials/query/fragment values
  are rejected, loopback HTTP is limited to local development, and request timeouts are bounded.
- [ ] Confirm model output cannot authorize execution or directly invoke tools, and all structured plan fields have explicit item-count and character limits.
- [ ] Review run-report contents for secrets and sensitive path disclosure; confirm stdout/
  stderr artifact bytes and SHA-256 values preserve the exact captured process bytes,
  including invalid UTF-8 sequences and NUL bytes.
- [ ] Confirm duplicate JSON keys are rejected in task manifests, evidence manifests,
  run reports, and lifecycle audit events.
- [ ] Review evidence-bundle path confinement, size limits, hashing, file-race behavior,
  and atomic no-overwrite manifest publication; failed writes must not leave a partial
  destination manifest.
- [ ] Review audit-chain verification, append failure behavior, permissions, and the
  documented single-writer limitation.
- [ ] Confirm lifecycle evidence references include the exact evidence-bundle manifest
  SHA-256, and consumers reject a replaced manifest before trusting its artifact list.
- [ ] Confirm actor roles are not mistaken for authenticated human identity or signed
  approvals.
- [ ] Review data retention, backups, and any external LLM provider data-processing terms.

## Benchmark adapters and workflow

- [ ] Confirm CyberGym and CyberGym-E2E adapters only expose the intended metadata.
- [ ] Confirm ground-truth patch fields, PoCs, scripts, archives, and benchmark execution
  are not exposed or invoked by metadata adapters.
- [ ] Review upstream code, dataset, and underlying-project license obligations separately.
- [ ] Confirm patch-test reports are task-matched, status/exit-code consistent, and their
  stdout/stderr paths, sizes, and hashes match the bundled evidence artifacts; re-read
  exact log bytes after bundle verification and re-verify the manifest before lifecycle append.
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
