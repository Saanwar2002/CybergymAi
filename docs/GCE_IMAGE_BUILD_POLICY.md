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


## Verify authenticated provenance against the build policy

After the dependency lock has been verified with
`validate-image-build-lock`, verify that the signed SLSA provenance binds the
release manifest to the same policy:

```bash
vulnresearch verify-image-build-evidence POLICY MANIFEST DSSE_ENVELOPE PUBLIC_KEY \
  --trusted-key-sha256 TRUSTED_KEY_SHA256
```

This command verifies the DSSE Ed25519 signature and pinned public-key
fingerprint, then requires the signed provenance to bind the manifest's source
commit and output image digest, plus the policy's exact base-image self-link,
dependency-lock SHA-256, build-type identity, and builder identity. A mismatch
blocks verification. The command does not itself prove that the lockfile was
used by a real build; use the lock-byte verification command as a separate
input check. It also does not run a builder or scanner, and does not provision
cloud resources.


## Deterministic build recipe contract

The offline recipe validator defines a separate, explicit contract for the
inputs a future image builder must control:

```bash
vulnresearch validate-image-build-recipe reproducible-image-recipe.json
```

Schema version 1 requires an exact GCE base-image self-link, full source
commit, dependency-lock digest, OCI builder image pinned by SHA-256 digest,
exact numeric toolchain version, HTTPS build-type identity, non-negative
`source_date_epoch`, and an explicit target platform. Network access must be
disabled. The process environment is fixed to `LANG=C.UTF-8`,
`LC_ALL=C.UTF-8`, `TZ=UTC`, and `umask=0022`; extra or changed environment
keys are rejected.

The validator returns a SHA-256 digest of canonical JSON (UTF-8, sorted keys,
compact separators). This digest can be recorded as a resolved dependency in
future signed provenance. The caller must select and preserve the epoch and
all recipe inputs; this validator does not prove the epoch matches the source
commit timestamp, inspect the builder image, execute the toolchain, or
demonstrate repeatability.

This is a contract validator only. It does not build an image, resolve or
install dependencies, contact registries, run scanners, create attestations,
or access Google Cloud. Reproducibility still requires independent builds
from the same pinned inputs and matching artifact digests.


## Bind the recipe digest into signed provenance

Use the combined verifier when the reproducibility recipe is available:

```bash
vulnresearch verify-image-build-recipe-evidence POLICY RECIPE MANIFEST DSSE_ENVELOPE PUBLIC_KEY \
  --trusted-key-sha256 TRUSTED_KEY_SHA256
```

In addition to the build-policy and release bindings, this command requires
the signed SLSA `resolvedDependencies` to contain the canonical recipe
SHA-256 digest and the exact digest-pinned builder image reference. The recipe
must itself agree with the policy's base image, source commit, dependency-lock
digest, and build type. Because the recipe digest covers the complete
canonical recipe, it also commits to the pinned toolchain version,
`SOURCE_DATE_EPOCH`, target platform, network-disabled requirement, and fixed
environment.

This is still evidence validation, not proof that a real builder obeyed the
recipe. The trusted provenance signer and builder identity must be provisioned
and governed out of band. Independent builds must still produce matching
artifact digests before reproducibility can be claimed.


## Verify two independent builds for reproducibility

After independently producing and signing two release manifests and SLSA
provenance envelopes, compare them offline:

```bash
vulnresearch verify-image-build-reproducibility POLICY RECIPE \
  FIRST_MANIFEST FIRST_MANIFEST_SIGNATURE FIRST_DSSE_ENVELOPE FIRST_ARTIFACT_FILE \
  SECOND_MANIFEST SECOND_MANIFEST_SIGNATURE SECOND_DSSE_ENVELOPE SECOND_ARTIFACT_FILE \
  MANIFEST_PUBLIC_KEY PROVENANCE_PUBLIC_KEY \
  --trusted-manifest-key-sha256 MANIFEST_KEY_SHA256 \
  --trusted-key-sha256 PROVENANCE_KEY_SHA256
```

Both detached release-manifest signatures are verified against the separately
pinned manifest-signing key. Each provenance signature is then verified against
the independently pinned provenance key and trusted builder policy. The two
key fingerprints must differ; reusing one signing key for both roles is rejected. Each signed manifest binds the release metadata, including the vulnerability
scan result. Each signed SLSA statement must bind its invocation ID to that release manifest's unique
`build_id`, in addition to the policy, recipe digest, pinned builder image,
source commit, and base image. The two build IDs must differ, while the source
commit, source base image, and resulting artifact SHA-256 must match. The
command also hashes both supplied artifact files incrementally in fixed-size
chunks and recomputes each SHA-256 locally, requiring each file to match its own signed release digest
before comparing the two builds. Empty files, symlinks, non-regular paths, and files that change while being
hashed are rejected. The helper opens without following symlinks where the
platform supports it, checks file identity and timestamps before and after the
read, and avoids loading large disk images into memory.

A successful result means two independently identified, authenticated build
records claim the same artifact digest under the same deterministic recipe.
It does not itself execute either build, prove physical or organizational
independence of the builders, inspect the artifact bytes, or establish that
the builder followed the recipe. Stronger assurance still requires genuinely
separate build environments and a trusted process for collecting and signing
each result.


## Bind vulnerability scan identity to release policy

The signed release manifest's `vulnerability_scan` object must include both
`scanner` and `scanner_version`. Policy-bound provenance verification
requires those values to match the build policy's `scanner_name` and
`scanner_version` exactly. The manifest signature authenticates the scan
metadata and zero-finding counts; the policy comparison prevents a manifest
from substituting a different scanner or scanner release than the approved
build policy. This does not itself authenticate the scanner execution: the
production pipeline must still collect scan evidence from a trusted scanner
and bind the results into the signed manifest.

The `vulnerability_scan` manifest object is strict: only `scanner`, `scanner_version`, `scanned_at`, `critical`, and `high` are accepted. Unknown fields are rejected rather than silently ignored.


## Verify an independently signed vulnerability scan attestation

A release manifest's detached publisher signature authenticates its declared
scanner metadata, but does not independently authenticate a scanner-produced
record. The offline verifier can additionally check a scanner-signed DSSE
SLSA provenance envelope:

```bash
vulnresearch verify-image-scan-attestation MANIFEST SCAN_DSSE_ENVELOPE \
  SCANNER_PUBLIC_KEY \
  --trusted-key-sha256 TRUSTED_SCANNER_KEY_SHA256 \
  --expected-scanner-id https://scanner.example.invalid/production \
  --expected-scan-build-type SCAN_BUILD_TYPE_URI
```

The scanner envelope must be signed by the separately pinned scanner key,
identify the expected scanner as its SLSA builder, bind the exact image
self-link and artifact SHA-256, bind the release build commit and build ID,
and declare the same scanner name, exact version, timestamp, and zero
critical/high findings as the signed release manifest. The scanner key and
scanner identity are operator-supplied trust inputs; do not trust a key merely
because its fingerprint accompanies the envelope.

This verifies an authenticated scanner claim, not the scanner's integrity,
coverage, configuration, or completeness. It does not execute a scan, fetch
a report, build an image, or contact GCP. A deployment workflow must require
this verification result as well as the independently signed build and
release evidence before any image can be approved.
