# GCE canary image release contract

## Scope and current status

This document defines the evidence required before a boot image can be approved for the
offline canary. It does **not** build or publish a GCE image, sign an attestation, run a
vulnerability scanner, or provision cloud resources. No image is currently approved by
this contract.

The first image must contain only the fixed, harmless offline canary fixture. It must not
contain benchmark payloads, user-supplied code, credentials, SSH keys, cloud CLI
credentials, a guest service account, or a general-purpose remote command agent.

## Build requirements

A future image builder must:

1. Start from one exact, immutable GCE source image self-link. Do not use an image family,
   floating tag, mutable alias, or unpinned package repository snapshot.
2. Record the source image identity, source image creation timestamp, builder version,
   build tool version, package inventory, and exact source commit.
3. Build in a dedicated image-factory project or an explicitly isolated build boundary,
   separate from the runtime canary project. The builder identity must be short-lived and
   limited to image creation and temporary build resources.
4. Disable external IPs on build workers. Do not add a NAT, proxy, VPN, peering, or other
   general egress route as a build convenience. Any required package inputs must be
   mirrored, pinned and integrity-checked before the isolated build.
5. Bake the fixed canary fixture into the image. Runtime execution must not depend on
   startup scripts, instance metadata, package downloads, or an interactive command
   channel.
6. Produce an immutable image name and a SHA-256 digest for the exported build artifact
   or image representation. Record a full Git commit SHA and unique build ID.
7. Generate provenance/attestation linking the output image, source image, build recipe,
   builder identity, source commit and artifact digest.
8. Run vulnerability and malware checks against the final image. A release is blocked
   for any critical or high severity finding. Medium/low findings require documented
   review and an explicit disposition before approval.
9. Keep the complete scanner report, package inventory, build logs and provenance in
   access-controlled evidence storage. Do not put secrets or guest-controlled output in
   image labels or public metadata.
10. Have a second reviewer approve the image identity and evidence before the exact image
    self-link is added to the canary configuration.

## Required release manifest

The future pipeline must emit a JSON manifest with this shape:

```json
{
  "image_self_link": "projects/PROJECT_ID/global/images/EXACT_IMAGE_NAME",
  "source_image_self_link": "projects/BASE_PROJECT/global/images/EXACT_SOURCE_IMAGE",
  "build_commit": "full-40-or-64-character-git-sha",
  "build_id": "unique-build-id",
  "artifact_sha256": "64-character-lowercase-sha256",
  "provenance_uri": "https://approved-evidence-store.example/provenance/BUILD_ID",
  "vulnerability_scan": {
    "scanner": "approved-scanner-and-version",
    "scanned_at": "2026-11-06T12:00:00Z",
    "critical": 0,
    "high": 0
  }
}
```

The repository validator in `vulnresearch.execution.gce_image` rejects mutable image
families, malformed resource paths, incomplete provenance, invalid digests, timezone-free
scan timestamps, invalid scan counts, and any critical/high findings. It validates the
minimum release contract; it does not independently verify the referenced attestation or
scanner report. Those checks must be performed by the future trusted build/release system.

Runtime configuration must be constructed with
`build_gce_canary_config_from_release_manifest`. That factory validates the manifest,
requires the release image to belong to the dedicated runtime project, and copies the
exact image self-link into the GCE config. It rejects invalid manifests and critical/high
findings before a VM can be requested. This is a structural gate only: it does not verify
a provenance signature, prove that a scanner actually ran, or replace independent
release approval.

## Runtime requirements

- Configure the canary with the exact image self-link, never an image family.
- Verify image labels and immutable image identity against the approved release manifest.
- Verify the provenance signature and evidence independently before provisioning.
- Keep the VM network-isolated and service-account-free as specified in ADR 0003.
- Do not add startup scripts or metadata to pass runtime instructions.
- Delete the canary VM and confirm absence after every run.

## Approval gate

Image publication and canary execution remain disabled until the project owner has
reviewed the build boundary, builder IAM, evidence storage, scanner policy, signature
verification, image lifecycle/retention, and budget controls. A clean unit test or manifest
validation is not proof that an image is safe or that its provenance is authentic.


## Offline manifest validation command

After a future trusted image pipeline has produced the JSON release manifest, validate its
declared structure without loading GCP credentials or contacting Google Cloud:

```sh
vulnresearch validate-image-manifest path/to/image-release.json
```

The command exits with status 0 and prints the validated image identity and declared
zero-critical/zero-high scan counts. It exits with status 2 for malformed manifests or
blocked scan findings. It does not verify provenance signatures, retrieve the scanner
report, run a scanner, or prove that the manifest is authentic. A successful command is
necessary but not sufficient for release approval.
