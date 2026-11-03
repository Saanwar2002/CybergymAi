# Operations and local development

## Requirements

- Python 3.11 or newer.
- Docker Engine and Docker CLI for the opt-in fixture runner.
- A Linux host is recommended for the Docker isolation options used by the runner.
- An OpenAI-compatible API key only when using the live planning provider; CI uses a mock.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
cp .env.example .env
```

Set `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL` as required by the planning
provider. Remote base URLs must use HTTPS; plain HTTP is allowed only for loopback
endpoints used during local development. URL credentials, query strings, and fragments
are rejected. Never commit `.env` or place secrets in task manifests.

## Pin the sandbox image

The runner accepts only a `python:3.11-slim@sha256:<64-hex-digest>` reference. Pull the
image, inspect its repository digest, and explicitly approve the digest before running:

```bash
docker pull python:3.11-slim
docker image inspect --format='{{index .RepoDigests 0}}' python:3.11-slim
export VULNRESEARCH_SANDBOX_IMAGE='python:3.11-slim@sha256:<approved-digest>'
```

Replace the placeholder with the full digest returned by Docker. Do not use a mutable tag.
The runner uses Docker's `--pull never` policy: the exact digest must already be present
locally or the run fails closed. Digest pinning is not a substitute for reviewing image
provenance.

## Local fixture workflow

```bash
vulnresearch validate examples/task.json
vulnresearch plan examples/task.json
vulnresearch run examples/task.json --allow-execution --output-dir artifacts/runs
```

The run command is explicitly opt-in. The current policy accepts local fixtures only.
It starts a network-disabled Docker container with a read-only workspace, non-root user,
dropped capabilities, resource limits, bounded logs, and a pinned image. Task manifests are limited to 64 KiB; text fields and command arguments have explicit size
limits. Evidence bundles are limited to 64 artifacts, 256 KiB of manifest metadata, and 20 MiB
of content; lifecycle audit stores are capped at 1 MiB. LLM planning caps output at 2,048
tokens and provider timeouts at one hour. A successful command is not a vulnerability
finding; review the report and underlying evidence.

Each run creates a directory under `artifacts/runs/` containing `report.json`,
`stdout.txt`, and `stderr.txt`. The report records task identity, timestamps, duration,
exit code, output sizes, and SHA-256 hashes. Keep these files out of source control.

## Workflow sessions and evidence

The Python API supports persisted lifecycle sessions:

- `WorkflowSession.create(task_id, audit_path)` creates a new audit log.
- `advance(...)` validates and persists a single state transition.
- `propose_patch(...)` stores a bounded `.patch` or `.diff` evidence reference.
- `record_patch_test(...)` verifies a task-matched report/stdout/stderr bundle from a
  separately approved sandbox run before recording `patch_tested`.
- `WorkflowSession.open(audit_path)` verifies the audit hash chain before reopening.

See [E2E lifecycle](E2E_LIFECYCLE.md) and [evidence bundles](EVIDENCE_BUNDLES.md) for API
contracts and limitations. Lifecycle appends acquire an exclusive OS-level file lock so
cooperating processes serialize read/validate/append operations. Direct writers that ignore
the advisory lock can still corrupt the chain; hash chains detect edits but are not
tamper-proof.

## Repeatable harmless workflow demo

See [DEMO.md](DEMO.md) for a two-run offline example that demonstrates a failing baseline, a patch proposal artifact, a passing candidate test, and human review gates. It requires `--allow-execution`, a human plan-approval note, and interactive evidence/final-decision review. The diff is recorded, not applied; the candidate fixture is pre-prepared.

## Benchmark metadata adapters

CyberGym and CyberGym-E2E adapters resolve existing local metadata only. They do not
download datasets, generate PoCs, read/copy ground-truth patches into descriptors, run
benchmark scripts, or invoke upstream evaluators. See [benchmark adapter policy](BENCHMARK_ADAPTERS.md)
before acquiring any dataset.

## Quality checks

```bash
ruff check .
pytest -q
vulnresearch validate examples/task.json
```

GitHub Actions additionally pulls and pins the approved image and executes the harmless
offline fixture, and runs the full two-stage patch workflow demo with scripted human-review inputs. Do not merge a change while its required checks are pending or failing.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Image rejected | Tag-only or malformed digest | Inspect and set the full approved SHA-256 reference |
| Task blocked | Authorization/source/profile metadata is outside local fixture policy | Use only an explicitly approved local fixture; do not weaken the policy |
| Docker CLI/socket unavailable | Docker is not installed/running or socket is inaccessible | Start Docker in the isolated development environment; never expose the socket publicly |
| Timeout or interruption | Task exceeded its manifest timeout or the runner was interrupted unexpectedly | The runner sends a stop signal, force-removes the generated container, inspects again to confirm absence, and stops the Docker CLI; output-reader joins are bounded and an unresponsive reader fails closed; inspect any unconfirmed-cleanup warning before reusing the runner |
| Output marked truncated | A stream exceeded the 1 MiB retained-output limit | Use a test that emits bounded diagnostic output; do not remove the cap |
| Evidence verification fails | Artifact changed, path escaped, or bundle is malformed | Recreate the bundle from the correct local artifact and review the audit history |

## Known limitations

- No production deployment, multi-tenant service, or VM isolation manager. The provider-neutral backend contract and fake-backend tests are implemented, but no concrete VM backend is available or enabled. See [ADR 0002](decisions/0002-disposable-vm-boundary.md).
- If an injected benchmark backend raises before returning a result, cleanup is unconfirmed. Quarantine the run environment using the provider's independently verified procedure; do not retry or reuse it until destruction is confirmed.
- If report publication fails during the parent-directory fsync after atomic rename, the report path is included in `BenchmarkReportPersistenceError`, but crash durability is uncertain. Preserve the visible report, inspect the path, and do not treat it as durably published until independently verified.
- No official CyberGym or CyberGym-E2E scoring/evaluation compatibility claim.
- No automatic patch application or project regression-suite execution.
- No cryptographic identity/signatures for human approvals or audit records.
- No dataset download/redistribution workflow or license automation.
