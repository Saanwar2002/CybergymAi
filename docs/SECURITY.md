# Security model and threat assessment

## Security posture

VulnResearch AI is a local defensive research prototype. It is **not production-ready**
and is not a complete isolation boundary for hostile benchmark workloads. The current
execution policy supports explicitly approved local fixtures only. Do not use it to
test arbitrary public targets or to run untrusted benchmark projects on a personal or
production workstation.

## Assets to protect

- Host files, credentials, developer accounts, Docker daemon, and local services.
- Benchmark source, task metadata, evidence artifacts, and vulnerability reports.
- LLM API credentials and any task context sent to an external provider.
- Integrity and provenance of run reports, patch proposals, and review decisions.

## Threats and current controls

| Threat | Current mitigation | Residual risk |
|---|---|---|
| Unapproved or remote task execution | Policy permits only approved `local_fixture` tasks with `local_fixture_only` scope and `offline_readonly` profile; execution is opt-in | Authorization metadata is self-asserted and is not identity or legal authorization proof |
| Container network access | Docker uses `--network none` and private IPC | Docker daemon/host networking remains trusted; this does not constrain host-side tools |
| Container privilege escalation | Non-root UID/GID, all capabilities dropped, `no-new-privileges`, read-only root filesystem | Container shares the host kernel; Docker is not a VM or complete boundary |
| Host workspace modification | Workspace is mounted read-only | The container can still read the mounted source; kernel/container escape remains possible |
| Resource exhaustion | PID, memory and swap, CPU, file-size, tmpfs, timeout, and bounded-log limits; timeout triggers a generated-name Docker force-removal fallback | No independent host disk quota or VM-level resource isolation is provided; cleanup cannot be confirmed if the Docker daemon is unavailable |
| Mutable image supply chain | Image reference must include a SHA-256 digest | Digest pinning does not establish image provenance; operators must approve the digest. Runtime uses pull policy `never` so a missing image fails instead of triggering an implicit host-side pull |
| Output flooding | Concurrent pipe draining with at most 1 MiB retained per stream | The process can still consume CPU and I/O until timeout |
| Input amplification / LLM cost abuse | Task manifests are capped at 64 KiB; text/argv fields, evidence manifests (256 KiB/64 artifacts), audit stores (1 MiB), provider response bodies (1 MiB), model output (2,048 tokens; 2,048-character objective, 32 items per list, 1,024 characters per item), and provider timeout (3,600 seconds) are bounded | Tokenization and provider-side billing behavior vary by provider |
| Workspace escape at sandbox API boundary | Validated tasks retain their trusted workspace root; the policy gate re-resolves the workspace and the Docker command builder rejects caller overrides unless they exactly match the manifest-approved path | Filesystem races and hostile host-level actors are outside the prototype threat model |
| Path traversal in adapters/artifacts | Resolve paths beneath configured roots; reject escapes and symlink artifacts | Filesystem races and hostile host-level actors are outside the prototype threat model |
| Evidence tampering | SHA-256 artifact digests and hash-chained audit events | Hashes are not signatures; a writer able to rewrite all records can recompute hashes |
| Agent self-approval | Lifecycle transition roles reserve approval/review/final decisions for humans and execution events for the system | Actor roles are application-level assertions, not authenticated identities |
| LLM API key interception | HTTPS is required for remote OpenAI-compatible endpoints; plain HTTP is accepted only for loopback hosts, and URL credentials/query strings/fragments are rejected | Custom provider TLS trust and provider-side retention are not independently validated |
| Prompt injection / false claims | Model output is structured and advisory; execution is separate and human opt-in | Model output may still be inaccurate or manipulated by supplied content |

## Required deployment boundary for hostile workloads

Before using any real benchmark code:

1. Implement a concrete backend for the provider-neutral execution contract in
   [ADR 0002](decisions/0002-disposable-vm-boundary.md), then move execution to a dedicated,
   disposable VM or equivalent isolated runner. No concrete backend is currently shipped.
2. Do not mount the host Docker socket into the workload container.
3. Do not expose the Docker daemon or benchmark services to public networks.
4. Keep host credentials, cloud metadata, SSH material, and API keys outside the workload.
5. Pin and independently review the container image digest and its provenance.
6. Add host-level disk quotas, monitoring, and cleanup verification.
7. Review the benchmark's data, code, and underlying-project licenses.
8. Require human authorization for each task and human review of each result.
9. Verify the VM identity, immutable guest image, resource limits, network policy, bounded input/output channels, and destruction before accepting any run result.
10. Keep the host Docker socket, hypervisor credentials, cloud credentials, and unrelated host files outside the guest.

The current project does not provision this VM boundary automatically.

## Data handling

- Never commit API keys, tokens, private keys, or personal data.
- Keep `.env`, run artifacts, benchmark datasets, and generated patches out of source control.
- Treat task manifests, repository files, logs, model responses, and patch files as untrusted input.
- Send only the minimum task context needed for planning to an external LLM provider.
- Review provider retention and data-processing terms before sending private source or reports.
- Run-report directories are created with mode `0700` and report/log files with mode `0600` on POSIX systems; keep their parent output directory and any copied artifacts access-controlled as well.
- Protect audit and evidence directories with restrictive filesystem permissions and trusted backups.

## Review and incident response

For suspected escape, secret exposure, unexpected network activity, or corrupted evidence:

1. Stop the run and isolate the runner host.
2. Preserve the task manifest, image digest, run report, and audit chain.
3. Do not reuse the affected runner or workspace until rebuilt and reviewed.
4. Rotate any credentials that may have been exposed.
5. Record the incident and review the threat model before resuming.

## Security status

This document describes current prototype controls and known gaps; it is not a third-party
security audit or a guarantee against container escape. The prototype must not be described
as safe for arbitrary untrusted code. An independent reviewer should complete the
[security review checklist](SECURITY_REVIEW_CHECKLIST.md) before any real benchmark workload.
