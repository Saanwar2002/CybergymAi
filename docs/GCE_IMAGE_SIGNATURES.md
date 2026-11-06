# GCE image release signature verification

The release-manifest structural validator is not an authenticity check. For an
image to pass the cryptographic gate, callers must use
`verify_gce_image_release_manifest_signature` with all of:

- the parsed manifest object;
- a detached Ed25519 signature encoded as strict base64;
- the publisher public key in PEM format; and
- the independently provisioned SHA-256 fingerprint of that public key's DER
  SubjectPublicKeyInfo representation.

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
