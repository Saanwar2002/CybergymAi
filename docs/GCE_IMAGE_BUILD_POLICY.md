# Offline GCE image build policy

`validate_gce_image_build_policy` defines the minimum inputs for a
future reproducible GCE image builder. It is deliberately an offline policy
validator, not a build pipeline.

The policy requires an explicit integer `schema_version` of `1`, followed by:

- an exact GCE base-image self-link (image families and mutable aliases are rejected);
- a full source Git commit SHA;
- a SHA-256 digest for the externally prepared dependency lock;
- an HTTPS builder identity and HTTPS build-type identity;
- an explicitly named scanner and scanner version; and
- zero allowed critical and high vulnerability findings.

The policy-only command validates the digest's syntax, but does not retrieve or
verify a lockfile. To verify the actual dependency lock bytes against the
policy pin, use the separate offline lock-verification command:

```bash
vulnresearch validate-image-build-lock image-build-policy.json requirements.lock
```

This command validates the full policy, reads the supplied lockfile as bytes,
and compares its SHA-256 digest with `input_lock_sha256`. It reports
`lock_verified: true` only after an exact match. It does not resolve
dependencies, install packages, build an image, or contact Google Cloud.
The file's bytes (including line endings) are part of the digest.

The builder identity and scanner identity/version remain declarations, not
proof that a trusted builder ran or that a scan is authentic. A production
pipeline must obtain scan results from an authenticated scanner execution and
bind them into signed release evidence. The existing manifest and DSSE
verification gates remain necessary.

No base image, builder, scanner, signing key, or production trust anchor is
selected by this policy. Operators must provision those independently through
reviewed configuration. No GCP project, credentials, network access, or cloud
resources are required to validate the policy.

This change does not claim reproducible builds: a future builder must also
control timestamps, environment, toolchain versions, dependency resolution,
and build inputs, then demonstrate repeatability by comparing independently
produced artifact digests.

## Offline policy CLI

Validate an operator-prepared policy document without contacting Google Cloud:

```bash
vulnresearch validate-image-build-policy image-build-policy.json
```

A successful policy-only result means only that the document satisfies the
local schema and fail-closed thresholds. It does not verify the lockfile,
run a build or scanner, attest builder identity, or create signed evidence.

Only schema version 1 is currently supported; missing, boolean, string, and
unknown version values are rejected. Future schema changes must be introduced
through an explicit versioned migration.

The validator also rejects every unknown field. This prevents misspelled or
unreviewed policy keys (including apparent override switches) from being
silently ignored. Extend the accepted schema only through a reviewed code
change with corresponding tests.
