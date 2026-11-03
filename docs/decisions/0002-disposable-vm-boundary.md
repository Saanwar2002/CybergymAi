# ADR 0002: Disposable VM boundary for benchmark execution

- **Status:** Accepted architectural constraint; implementation and provider selection pending
- **Date:** 2026-11-02
- **Decision owners:** Project maintainers
- **Scope:** Future execution of untrusted CyberGym / CyberGym-E2E benchmark workloads

## Context

The current runner starts Docker containers through the host Docker daemon. It applies useful
container controls, but the workload still shares the host kernel and the Docker daemon is a
high-privilege host component. The current policy therefore remains restricted to harmless,
explicitly approved local fixtures.

The benchmark repositories describe workloads that execute vulnerable software, PoCs,
build systems, test suites, and task-provided scripts. Running those workloads directly on a
developer workstation or in a container controlled by the host Docker daemon would exceed
the prototype's current threat model. A disposable VM boundary is a prerequisite, not an
optional hardening flag.

## Decision

### 1. Separate the trusted control plane from the workload plane

A trusted host-side orchestrator may communicate with a hypervisor or isolated-runner
manager. It must not execute benchmark commands itself and must not expose its credentials,
Docker socket, filesystem, or management API to the guest workload.

Each benchmark attempt receives a fresh disposable VM, or a fresh VM restored from a
reviewed immutable base snapshot. The guest is destroyed after output collection. Reuse of
a running guest across unrelated tasks is prohibited.

### 2. Keep Docker inside the disposable guest when upstream tasks require it

Some upstream benchmark workflows depend on Docker images and containerized project
environments. If Docker is required, run a guest-local Docker Engine inside the disposable
VM. Never bind-mount the host Docker socket into the guest or workload container. The
hypervisor remains the outer isolation boundary; guest containers provide additional
defense-in-depth, not a replacement for the VM.

No benchmark server, Docker API, or management endpoint may bind to a public interface.
Any internal service needed by a task must be reachable only on a private guest-local
network and must be destroyed with the VM.

### 3. Use immutable, bounded input and output channels

- Stage only the approved task inputs into a read-only guest input area.
- Use a separate bounded output channel for reports and artifacts; do not share the host
  workspace as a writable guest mount.
- Prefer a hypervisor-supported host/guest channel such as vsock or an equivalent
  authenticated management channel over host TCP port forwarding.
- Do not forward guest ports to the host or internet.
- Enforce host-level limits for vCPU, RAM, disk capacity and I/O, process count where
  available, and wall-clock duration. Retain bounded stdout/stderr and bounded artifacts.
- Do not provide API keys, cloud credentials, SSH material, host environment variables,
  metadata-service routes, or unrelated host files to the guest.

### 4. Fail closed

The future VM backend must verify the VM identity, immutable base image/snapshot digest,
resource limits, network policy, input staging, and output destination before execution.
If any required capability is missing or cannot be verified, the run is blocked. It must
never fall back to host execution or the current host-Docker runner.

If execution times out or the hypervisor cannot confirm destruction, mark cleanup as
unconfirmed, quarantine the runner, and preserve a bounded incident record. Do not reuse
the VM or its storage.

### 5. Keep the backend provider-neutral until infrastructure is selected

The application-facing execution contract should describe a validated run specification
and typed lifecycle operations, not provider-specific shell commands:

1. Validate backend capabilities against the run's required isolation profile.
2. Provision a fresh VM from an approved immutable image.
3. Verify identity, image, resource, network, and storage policy.
4. Resolve only manifest-listed input artifact IDs; verify each SHA-256 digest and size.
5. Stage those inputs read-only beneath a fixed guest input root and enforce aggregate size.
6. Execute only the approved command identifier and argument vector.
7. Collect at most 64 artifacts beneath a fixed guest output root; hash exact bytes and
   enforce the combined stdout/stderr/artifact output limit.
8. Collect exit status, timing, resource usage, and cleanup evidence; echo the canonical
   execution-spec SHA-256 in the backend result so the result is bound to the approved
   command, policy, resource limits, and input manifest.
9. Destroy the VM and verify destruction.
10. Atomically persist the versioned JSON execution manifest, its canonical SHA-256,
    bounded stdout/stderr evidence, output artifact descriptors, complete lifecycle, and
    cleanup evidence in the run record.

The initial interface and tests may use a fake backend. Do not select Firecracker, QEMU,
cloud VMs, or another provider solely in application code before deployment requirements,
host compatibility, operational ownership, and security review are known.

## Consequences

### Positive

- Host-kernel isolation is no longer the only boundary around untrusted benchmark code.
- Docker remains available inside the guest for upstream compatibility without exposing
  the host Docker daemon.
- Backend selection can be made independently from task policy and benchmark adapters.
- Failure to enforce a required isolation property becomes an explicit blocked run.

### Costs and limitations

- VM provisioning, image maintenance, storage staging, monitoring, and cleanup add
  operational complexity and resource cost.
- A VM is not an absolute security guarantee; hypervisor vulnerabilities and misconfiguration
  remain residual risks.
- Network policy and host/guest channels need independent verification.
- Benchmark dataset and underlying project licensing must be reviewed separately.

## Implementation gates

### Gate A — Contract and fake backend

- [x] Define typed run specification, capability report, digest-pinned guest-relative input manifest, bounded 64-item output-artifact manifest, explicit CPU/memory/disk/process/input/output limits, reported resource usage, lifecycle result, and cleanup status.
- [x] Add deterministic fake-backend unit tests.
- [x] Prove that unsupported capabilities and missing cleanup confirmation fail closed.
- [x] Keep the current Docker runner explicitly limited to harmless local fixtures.

Implementation status: `vulnresearch/execution/base.py` defines the provider-neutral contract and
`tests/test_execution_backend.py` exercises its gates. No concrete VM provider exists, and the
contract is not yet wired into the CLI or current local-fixture Docker runner.

### Gate B — Disposable VM canary

- Select and document a VM technology and supported host environment.
- Build and pin a minimal guest image with verifiable provenance.
- Demonstrate one harmless canary task with no external network, no host mounts,
  bounded input/output, resource limits, and confirmed VM destruction.
- Test timeout, guest crash, orchestrator crash, storage cleanup, and failed destruction.

### Gate C — Independent review before benchmark workload

- Complete the independent security checklist against a specific commit and deployment.
- Review VM/hypervisor configuration, guest image provenance, host management credentials,
  network topology, benchmark data terms, and underlying project licenses.
- Obtain explicit human approval for a single controlled benchmark task.
- Preserve the benchmark's expected-result semantics and record exact upstream/data revisions.

**No real benchmark workload is authorized by this ADR.** Passing the harmless VM canary
and completing the independent review are prerequisites for a separate approval decision.
