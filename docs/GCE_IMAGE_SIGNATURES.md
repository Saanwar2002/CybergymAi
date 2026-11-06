# GCE image release signature verification

The release-manifest structural validator is not an authenticity check. The
legacy `build_gce_canary_config_from_release_manifest` helper checks structure
and project identity only; it does not authenticate the publisher.

For the cryptographic path, use
`build_gce_canary_config_from_signed_release_manifest`. It verifies all of:

- the parsed manifest object;
- a detached Ed25519 signature encoded as strict base64;
- the publisher public key in PEM format; and
- the independently provisioned SHA-256 fingerprint of that public key's DER
  SubjectPublicKeyInfo representation.

The lower-level `verify_gce_image_release_manifest_signature` function is
available when callers need verification without constructing runtime config.

The signature covers canonical UTF-8 JSON: keys sorted lexicographically,
compact separators, Unicode preserved, and non-finite numbers rejected. The
manifest must also pass all existing release and vulnerability checks.

Install the optional verifier dependency with:

```bash
pip install -e ".[image-signing]"
```

**Trust-anchor requirement:** the expected fingerprint must come from an
independent, reviewed configuration channel. Do not calculate the expected
fingerprint from the same untrusted manifest or accept a key merely because its
signature verifies. A key supplied alongside an artifact without an independently
pinned fingerprint does not establish publisher identity.

This implementation verifies the detached manifest signature only. It does not
fetch provenance, validate an in-toto/SLSA statement, verify transparency-log
inclusion, establish scanner identity, prove reproducible builds, or verify the
GCE image bytes against `artifact_sha256`. No signer is trusted by default and
no GCP credentials or network calls are used.


## Offline CLI verification

Given a JSON manifest, a detached base64 signature file, a PEM public key, and
a fingerprint provisioned through a separate trusted channel:

```bash
vulnresearch verify-image-manifest image-release.json image-release.sig image-release.pub \
  --trusted-key-sha256 "<independently-pinned-lowercase-sha256-fingerprint>"
```

The command performs no network or GCP calls. It prints
`"signature_verified": true` only after the manifest passes structural and
vulnerability checks and the detached Ed25519 signature matches the pinned key.
The signature file is strict base64 text; the public key file must contain an
Ed25519 SubjectPublicKeyInfo PEM public key. Keep the trusted fingerprint out
of the untrusted artifact bundle.


## Offline SLSA provenance consistency checks

`validate_slsa_provenance_statement` checks an in-toto Statement v1 carrying
SLSA Provenance v1. It binds the sole subject name to the exact GCE image
self-link, the subject SHA-256 to the release manifest digest, a resolved
dependency's `gitCommit` to the manifest build commit, and
`predicate.runDetails.builder.id` to an independently configured expected
builder identity.

This function performs consistency and policy checks only. It does **not**
authenticate a raw JSON statement. Before relying on its result, obtain the
statement through an authenticated source or verify a DSSE/in-toto envelope
against an independently configured signer identity. A manifest's
`provenance_uri` string is not proof that the referenced statement is genuine.


## Authenticated DSSE SLSA provenance verification

`verify_dsse_slsa_provenance_envelope` verifies a DSSE v1 envelope containing
an in-toto JSON payload. It requires the exact in-toto payload type, exactly
one signature, an Ed25519 key whose DER SubjectPublicKeyInfo SHA-256 matches
the independently pinned fingerprint, and a DSSE `keyid` equal to that
fingerprint. It verifies the DSSE pre-authentication encoding (PAE), then
rejects duplicate JSON keys and validates the SLSA subject, digest, source
commit, and expected builder identity.

The function limits decoded payload size (1 MiB by default). This is an
offline verifier: it does not retrieve keys, provenance, transparency-log
entries, or image bytes. The pinned key fingerprint and expected builder ID
must be provisioned independently. It verifies one configured Ed25519 signer;
it does not implement key rotation, threshold signatures, certificate chains,
or transparency-log inclusion.


## Offline provenance verification CLI

Run the authenticated verifier with a manifest, DSSE envelope, PEM signer key,
and independently provisioned signer fingerprint and builder identity:

```bash
vulnresearch verify-image-provenance image-release.json provenance.dsse.json builder.pub \
  --trusted-key-sha256 "<pinned-public-key-fingerprint>" \
  --expected-builder-id "https://trusted-builder.example/production"
```

The command makes no network or GCP calls. It reports
`"provenance_verified": true` only after DSSE signature verification and SLSA
image, digest, commit, and builder checks pass.


## Combined deployment-evidence gate

`build_gce_canary_config_from_verified_release_evidence` is the strict
configuration-construction path. It requires both (1) a valid detached
Ed25519 signature over the release manifest using its independently pinned
manifest key and (2) an authenticated DSSE SLSA provenance envelope using its
independently pinned provenance key and expected builder identity. Only after
both checks pass does it construct a GCE canary config and enforce the
dedicated runtime project match.

The manifest-signing key and provenance-signing key are separate inputs and
may be independently managed. The older structural and single-evidence
helpers remain available for validation and testing; callers must use this
combined gate for a deployment decision. This still does not verify the
underlying GCE image bytes or transparency-log inclusion.
