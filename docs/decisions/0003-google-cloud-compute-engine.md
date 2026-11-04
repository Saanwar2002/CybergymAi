# ADR 0003: Google Cloud Compute Engine disposable VM provider

- **Status:** Accepted provider selection; deployment and implementation pending
- **Date:** 2026-11-04
- **Decision owners:** Project maintainers
- **Supersedes:** Provider-selection-pending language in ADR 0002
- **Scope:** Gate B harmless disposable-VM canary and the future benchmark VM backend

## Context

ADR 0002 established a provider-neutral execution contract and requires a disposable VM
for benchmark workloads. The project has selected Google Cloud as its first deployment
platform. This decision selects the infrastructure provider; it does not authorize
benchmark execution, create cloud resources, or imply that a GCP environment has been
configured or security-reviewed.

## Decision

Use Google Cloud Compute Engine (GCE) instances as the outer disposable-VM boundary.
The trusted control plane provisions and inspects instances through the Google Cloud
control plane. Workload code runs only inside a fresh guest instance and never receives
the provisioner's credentials or access to the control-plane API.

### Project and network boundary

- Use a dedicated GCP project for disposable research VMs; do not share the project
  with production services, personal workloads, or long-lived secrets.
- Use a dedicated custom VPC and subnet. Do not use the default VPC.
- Create instances without external IPv4 or IPv6 addresses.
- Apply explicit priority-zero deny-ingress and deny-egress firewall rules to all instances
  in the dedicated VPC. Do not create broad exceptions for package mirrors, the public
  internet, or general Google APIs.
- Delete the system-generated IPv4 default route after VPC creation and verify that no
  IPv4 or IPv6 default route or custom egress route remains. A deny firewall is retained
  as defense in depth; route removal is not a substitute for the firewall.
- Use an IPv4-only subnet and do not enable Private Google Access for the first canary.
- Do not create Cloud Router, Cloud NAT, VPC peering, VPN, or other egress/proxy paths.
  Verify that no such path is configured before starting the instance.
- Do not peer the sandbox VPC with production, office, or personal networks.
- The first canary uses a fixture baked into the reviewed guest image; it does not
  download task content or dependencies at runtime.

### Instance hardening

- Create one fresh instance per canary/run and delete it after bounded evidence capture.
- Pin a specific reviewed image resource, not an image family or mutable tag. Record
  the image identity and provenance evidence in the run record.
- Require Shielded VM protections: Secure Boot, virtual TPM, and integrity monitoring,
  subject to image compatibility verification.
- Use bounded machine type, boot disk size/type, startup duration, and wall-clock timeout.
- Do not attach a service account to the guest. Do not grant OAuth scopes to the guest.
- Do not place secrets, signed URLs, API keys, SSH keys, or sensitive startup metadata
  in instance metadata or guest-visible files.
- Disable interactive SSH access for the canary. No public management endpoint is
  exposed by the guest.
- Do not mount host filesystems, host Docker sockets, or persistent writable disks.
  Any Docker Engine needed by a future benchmark runs only inside the disposable guest.

### Control-plane identity

- The provisioner uses a dedicated workload identity/service account outside the guest.
- Grant only the Compute Engine permissions required to create, inspect, stop, and
  delete instances and to inspect the approved image. Avoid project Owner/Editor.
- Keep provisioning identity and credentials out of the guest and workload environment.
- Use audit logging for instance lifecycle operations. Restrict who can impersonate or
  deploy the provisioner identity.
- No credentials or project identifiers are committed to the repository.

### Canary communication and evidence

The first canary is intentionally narrow: a harmless, deterministic fixture is baked into
the approved guest image and runs at boot under a fixed, non-user-controlled command.
The trusted control plane collects a bounded serial-console transcript, validates the
expected fixture marker, inspects the instance configuration, requests deletion, and
confirms that the instance no longer exists.

Serial-console content is untrusted evidence. Parse it as data, enforce byte and time
limits, and never treat guest output as commands or trusted control messages. The canary
does not transfer arbitrary inputs or artifacts and does not prove that a general-purpose
guest command channel is safe.

Before general task execution is implemented, design and independently review a bounded
host/guest data channel for digest-verified read-only inputs and bounded outputs. It must
not grant the guest general network access, cloud credentials, or access to other runs'
artifacts. If this cannot be achieved without weakening isolation, keep the backend
disabled and fail closed.

### Failure handling

- If instance configuration differs from the reviewed policy, do not start the fixture;
  delete the instance and record the failure.
- If provisioning, evidence capture, timeout handling, or deletion is ambiguous, report
  cleanup as unconfirmed and quarantine the run. Never reuse the instance or its disk.
- Do not fall back to local Docker, host execution, another cloud, or a less isolated mode.
- Bound instance lifetime and apply project-level quotas/budgets and alerting before any
  repeated canary runs.
- Do not run real benchmark workloads until Gate C independent review and a separate
  explicit approval are complete.

## Consequences

### Positive

- Selects a managed VM platform while retaining the provider-neutral application contract.
- Separates the cloud provisioner identity from the untrusted guest.
- Makes the first cloud milestone testable without introducing a general command channel.
- Keeps the first canary offline and deterministic.

### Costs and limitations

- GCE, VPC, IAM, image provenance, serial-console handling, quotas, and billing add
  operational complexity.
- No arbitrary task inputs or outputs are supported by the first canary.
- A VM is not an absolute security guarantee; cloud configuration and hypervisor risks
  remain.
- A dedicated project, billing configuration, region, quotas, and IAM setup are still
  required.
- The first canary is not evidence that arbitrary benchmark execution is safe.

## Gate B implementation sequence

1. Add a GCE provider module behind the existing `ExecutionBackend` contract, with
   injectable cloud API clients so unit tests do not require a live project.
2. Add strict configuration validation for project, region/zone, approved image identity,
   machine type, disk ceiling, instance naming, and provisioner identity.
3. Create a dedicated custom-mode VPC and IPv4-only subnet; apply priority-zero deny-all
   ingress/egress rules, remove the generated default route, and verify there are no
   peering, Cloud NAT, Cloud Router, VPN, or proxy paths.
4. Implement create/inspect/serial-capture/delete lifecycle operations with bounded
   polling and fail-closed cleanup semantics.
5. Add unit tests for IAM/configuration omissions, public IPs, network rules, guest
   service accounts, mutable images, timeouts, malformed console output, and deletion
   uncertainty.
6. Add a reproducible image build and provenance process for the harmless canary fixture.
7. Add opt-in integration tests that require an explicitly configured dedicated sandbox
   project and enforce a small budget/quota ceiling.
8. Run the harmless canary; preserve configuration evidence and deletion confirmation.
9. Complete the independent security review before enabling any benchmark workload.

## Out of scope

This ADR does not provision GCP resources, store credentials, enable billing, implement a
general-purpose command channel, or authorize CyberGym/CyberGym-E2E benchmark execution.
