# Local evidence bundles

The evidence bundle helper creates a JSON manifest that identifies files beneath
an explicitly configured local artifact root. It records relative paths, sizes,
and SHA-256 digests; it does not copy or upload artifact contents.

## Usage

```python
from vulnresearch.workflow.evidence import (
    create_evidence_bundle,
    verify_evidence_bundle,
)

bundle_path = create_evidence_bundle(
    "fixture-001",
    {"stdout": "runs/123/stdout.txt", "report": "runs/123/report.json"},
    artifact_root="artifacts",
    output_path="artifacts/bundles/fixture-001.json",
)
manifest = verify_evidence_bundle(bundle_path, artifact_root="artifacts")
```

## Safety and limitations

- Paths must be relative, remain beneath the trusted artifact root, and refer to
  regular non-symlink files.
- Each artifact is limited to 5 MiB; a bundle is limited to 20 MiB total.
- Bundle manifests are created exclusively with owner-only file permissions;
  existing manifests are never overwritten.
- Verification re-hashes each artifact and fails if content, size, path, or schema
  differs from the manifest.
- Hashes detect accidental or unauthorized content changes but do not prove who
  created an artifact. Protect the artifact root and bundle with filesystem
  permissions and trusted backups.
- This helper does not parse logs, interpret vulnerability claims, or decide
  whether evidence supports a finding. Human review remains required.
