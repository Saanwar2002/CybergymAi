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

The lock digest binds the intended lockfile value but this module does not
retrieve, parse, or independently verify the lockfile. Likewise, scanner
identity/version and zero finding thresholds are policy inputs, not proof
that a scan ran or that its results are authentic. A production pipeline must
obtain scan results from an authenticated scanner execution and bind them into
signed release evidence. The existing manifest and DSSE verification gates
remain necessary.

No base image, builder, scanner, signing key, or production trust anchor is
selected by this policy. Operators must provision those independently through
reviewed configuration. No GCP project, credentials, network access, or cloud
resources are required to validate the policy.

This change does not claim reproducible builds: a future builder must also
control timestamps, environment, toolchain versions, dependency resolution,
and build inputs, then demonstrate repeatability by comparing independently
produced artifact digests.

## Offline CLI

Validate an operator-prepared policy document without contacting Google Cloud:

```bash
vulnresearch validate-image-build-policy image-build-policy.json
```

The command reports the validated pinned inputs and policy thresholds. It does
not run a build or scanner, fetch the lockfile, attest builder identity, or
create signed evidence. A successful result means only that the policy document
satisfies the local schema and fail-closed thresholds described above.

Only schema version 1 is currently supported; missing, boolean, string, and\nunknown version values are rejected. Future schema changes must be introduced\nthrough an explicit versioned migration.\n\nThe validator also rejects every unknown field. This prevents misspelled or
unreviewed policy keys (including apparent override switches) from being
silently ignored. Extend the accepted schema only through a reviewed code
change with corresponding tests.
