# Isolated GCP canary network

This Terraform root module describes the **network foundation only** for a dedicated,
single-purpose Cybergym canary project. It does not create a VM, service account, image,
Cloud Router, Cloud NAT, VPN, forwarding rule, proxy, or benchmark execution path.

## Security properties

- Custom-mode VPC; automatic subnet creation is disabled.
- Default internet routes are deleted when the VPC is created.
- Exactly one IPv4-only subnet is declared.
- Private Google Access is disabled.
- Priority-zero ingress and egress firewall rules deny all IPv4 traffic.
- No allow rules, peering, NAT, router, VPN, or external IP are declared.
- The project ID is a required input; no project is hard-coded.
- The module is not applied by CI and does not contact GCP during validation.

The Python GCE preflight remains authoritative at canary time: it inspects the actual
project/network state and rejects unexpected routes, firewall rules, peerings, routers,
NAT, forwarding rules, VPN paths, and effective hierarchical firewall allows. Terraform
configuration alone is not proof of the deployed state.

## Local, offline validation

Install Terraform 1.6 or later, then run:

```sh
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

These commands format and validate configuration only. They do not create cloud
resources. CI runs the same checks in a version-pinned Terraform container without
credentials and with backend initialization disabled.

## Before any deployment

Do not run `terraform apply` until all of the following are true:

1. The owner has created and confirmed a dedicated, single-purpose GCP project.
2. The project has an explicit billing budget and alert thresholds approved by the owner.
3. The project is not shared with production, personal workloads, or unrelated services.
4. The deployment identity has been independently reviewed and granted only the minimum
   permissions needed for this network foundation.
5. The project-level organization policies and inherited hierarchical firewall policies
   have been reviewed; inherited allow rules must not weaken isolation.
6. The plan has been reviewed by a human and the expected resource list is understood.

Set the required input only after the project exists:

```sh
export TF_VAR_project_id="your-dedicated-project-id"
export TF_VAR_region="europe-west2"
terraform plan -out=canary-network.tfplan
terraform show canary-network.tfplan
```

Do not commit the plan, Terraform state, credentials, access tokens, or generated
provider files. Use a protected remote state backend with encryption, access controls,
versioning, and locking before a shared or production deployment. This initial module
intentionally does not configure a backend.

A successful plan is not approval to apply. Deployment remains a separate, explicitly
authorized step after budget, IAM, organization policy, and security review are complete.
