# GCP identity and IAM boundaries

## Status

This is a design contract, not an applied IAM policy. Exact Google Cloud IAM permission
names and API-method requirements must be checked against the current Compute Engine API
and IAM documentation before any role is created. No project ID, service account, key,
or cloud resource is required to review this design.

## Identity separation

Use distinct identities for distinct trust boundaries. Do not reuse a human identity,
CI identity, image-builder identity, network-provisioning identity, and runtime
orchestrator identity.

| Identity | Responsibility | Must not be able to |
| --- | --- | --- |
| Human project administrator | Bootstrap the dedicated project, enable approved APIs, configure billing/budget, and grant reviewed roles | Run unreviewed canary workloads or store long-lived service-account keys |
| Infrastructure deployer | Create/update/delete only the dedicated VPC, sole subnet, deny rules, and required project-level guardrails | Create VMs, attach guest identities, create routes/NAT/VPN/forwarding paths, or alter organization policy |
| Image factory | Build and publish the approved immutable canary image in the image-factory boundary | Access runtime canary data, change runtime network policy, or run arbitrary benchmark payloads |
| Runtime orchestrator | Read and verify the exact network policy; create one bounded canary VM; poll its operation; read bounded serial output; delete and confirm absence | Modify networks/firewalls/routes, create identities, attach service accounts, create forwarding paths, publish images, or access unrelated projects |
| Evidence reviewer | Read release manifests, scan reports, provenance and run summaries | Build or publish images, change IAM/network policy, or execute workloads |

The runtime VM receives **no guest service account**. The orchestrator identity
is external to the guest and must never be passed through instance metadata or startup
scripts.

## Runtime API surface to permission-map

The current REST adapter calls the following API operations. Before deployment, map each
operation to the narrowest supported IAM permission and verify the mapping against the
current Google API/IAM reference. Do not substitute a broad predefined role simply to
make a request succeed.

| API operation | Why it is needed | Required boundary |
| --- | --- | --- |
| `networks.get`, `subnetworks.get` | Read the dedicated VPC and subnet | Read-only, exact project |
| `firewalls.list`, `routes.list` | Reject unexpected allow rules and routes | Read-only, exact project |
| `networks.getEffectiveFirewalls` | Inspect inherited hierarchical firewall effects | Read-only, exact project |
| `regions.list`, regional router/forwarding/VPN list operations, global forwarding-rule list | Reject alternate egress/ingress paths | Read-only, exact project |
| `instances.insert` | Create the one deterministic canary VM | Create-only capability, exact project/zone and approved image/network |
| `zoneOperations.get` | Poll create/delete operations | Read-only, exact project/zone |
| `instances.get` | Verify actual VM configuration and confirm deletion | Read-only, exact project/zone |
| `instances.getSerialPortOutput` | Collect bounded canary evidence | Read-only, exact project/zone |
| `instances.delete` | Remove the disposable VM | Delete-only capability, exact project/zone |

The VM creation call also has dependent resource-use requirements (approved image,
boot disk, network and subnet). Identify the minimum required permissions for those
dependencies and scope them to the dedicated project/resources. The API method list is
not itself a complete IAM policy.

## Provisioning and image-build boundaries

- Terraform network deployment runs under a separate, short-lived deployer identity.
  It must not share credentials with the runtime orchestrator.
- Image creation runs in a separate image-factory project or equivalent isolated build
  boundary. The builder may create temporary build resources only in that boundary.
- Image publication is a separately approved operation. The runtime identity receives
  read/use access to the exact approved image, not image creation or deletion rights.
- Human project bootstrap and organization-policy administration remain separate from
  automated deployment identities.
- Prefer Workload Identity Federation or another short-lived workload credential flow.
  Do not create or commit service-account key files.
- Do not grant project Owner, Editor, Compute Admin, Service Account Admin, or broad
  Service Account User roles to automation identities.
- Do not grant the runtime identity service-account impersonation, IAM policy mutation,
  privilege escalation, firewall mutation, route mutation, router/NAT/VPN mutation, or
  image publication.
- No runtime guest identity, SSH key, startup script, OS Login path, IAP tunnel, or
  general command channel is introduced by this design.

## Pre-deployment verification checklist

1. Confirm the project is dedicated and has an owner-approved billing budget and alerts.
2. Confirm the organization/folder/project policy inheritance and effective firewall
   policy cannot introduce an allow path around the VPC deny rules.
3. Resolve every API method above to exact IAM permission names using current official
   documentation; include dependent image/disk/network use permissions.
4. Create separate custom roles only after reviewing the resolved permission set.
5. Inspect every role for wildcard permissions, IAM mutation, privilege escalation,
   key creation, unrelated project access, and unnecessary write operations.
6. Bind roles to dedicated identities at the narrowest supported resource scope.
7. Prefer short-lived federated credentials; verify audience, subject, repository/workflow
   conditions, token lifetime and revocation.
8. Test both expected allowed calls and forbidden calls using a non-production test
   project before any canary project is enabled.
9. Record role definitions, bindings, reviewer, approval date and rollback procedure.
10. Re-run the policy review whenever the REST adapter adds or removes an API operation.

## Fail-closed rule

If a required API call fails because permission is missing, stop. Do not respond by granting
Editor/Owner or a broad Compute role. Update this permission map, review the exact
permission delta, and require independent approval before changing IAM.
