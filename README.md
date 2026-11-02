# VulnResearch AI

A defensive vulnerability-research prototype combining selected workflow ideas from
CyberGym and CyberGym-E2E. It is a local prototype, not an official implementation of
either benchmark and not a production-ready autonomous vulnerability agent.

## Current status

Implemented:

- Versioned local task manifests and fail-closed local-fixture policy.
- Structured LLM planning with a deterministic mock provider for CI.
- Opt-in Docker execution with offline networking, read-only workspace, non-root user,
  dropped capabilities, resource limits, pinned image references, bounded logs, and
  JSON run reports.
- Read-only local metadata adapters for CyberGym and CyberGym-E2E.
- Human-governed lifecycle state machine, persistent hash-chained audit events, evidence
  bundles, patch artifact capture, and validation of sandbox test reports.
- Harmless-fixture lifecycle integration tests.

Not implemented:

- Official CyberGym or CyberGym-E2E scoring/evaluator compatibility.
- Benchmark dataset download or redistribution.
- Automatic patch application or project regression-suite execution.
- VM-level isolation or production deployment.

## Safety boundaries

- The current execution policy permits explicitly approved local fixtures only.
- A human must opt in to execution with `--allow-execution`.
- The model produces advisory plans; it cannot authorize or start execution.
- Docker networking is disabled and the workspace is mounted read-only.
- Docker shares the host kernel and is not a complete boundary for hostile code. Use a
  dedicated disposable VM before considering real benchmark workloads.
- Human approvals and lifecycle actor roles are application-level records, not
  cryptographic identities or proof of legal authorization.
- Benchmark adapters read local metadata only; they do not download, generate, submit,
  or execute benchmark artifacts.

Read [the security model](docs/SECURITY.md) before running code and the
[benchmark adapter policy](docs/BENCHMARK_ADAPTERS.md) before acquiring task data.

## Quick start

Requires Python 3.11+ and Docker for the optional fixture runner.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Set `OPENAI_API_KEY` and, optionally, `OPENAI_BASE_URL` and `OPENAI_MODEL` for live
planning. CI uses a deterministic mock and does not require API credentials.

### Pin the sandbox image

The runner accepts only `python:3.11-slim@sha256:<64-hex-digest>`. Pull the image,
inspect its digest, and approve its provenance before setting:

```bash
docker pull python:3.11-slim
docker image inspect --format='{{index .RepoDigests 0}}' python:3.11-slim
export VULNRESEARCH_SANDBOX_IMAGE='python:3.11-slim@sha256:<approved-digest>'
```

Replace the placeholder with the full digest returned by Docker. A digest pin is not
a substitute for reviewing image provenance.

### Validate, plan, and run the harmless fixture

```bash
vulnresearch validate examples/task.json
vulnresearch plan examples/task.json
vulnresearch run examples/task.json --allow-execution --output-dir artifacts/runs
```

Execution is opt-in. The runner retains at most 1 MiB of stdout and stderr and writes a
JSON report plus hashed output artifacts under `artifacts/runs/`. See the
[operations guide](docs/OPERATIONS.md) for troubleshooting and the
[architecture overview](docs/ARCHITECTURE.md) for component boundaries.

## Workflow and evidence

The Python API provides persisted lifecycle sessions via `WorkflowSession`. It supports
human approval gates, hash-chained audit events, local patch artifact references, and
verification of task-matched run-report bundles before recording a patch-test attempt.
It does not apply the patch or run the project test suite; a report must come from a
separately approved sandbox run.

See:
- [E2E lifecycle and patch evidence](docs/E2E_LIFECYCLE.md)
- [Evidence bundle format](docs/EVIDENCE_BUNDLES.md)
- [Benchmark adapter scope and licensing](docs/BENCHMARK_ADAPTERS.md)

## Development

```bash
ruff check .
pytest -q
vulnresearch validate examples/task.json
```

## Roadmap

- [x] M0–M3: project foundation, task core, structured planning, isolated local-fixture
  execution, bounded reports, and offline Docker CI fixture.
- [x] M5 workflow foundation: human-governed lifecycle, persistent audit store, evidence
  bundles, patch proposal capture, test-report validation, and harmless-fixture workflow.
- [x] M4/M5 metadata adapters: local read-only CyberGym and CyberGym-E2E task mapping.
- [ ] M4/M5 remaining: controlled benchmark conformance and real project regression runs
  inside a separately reviewed VM-level isolation boundary.
- [ ] M6 remaining: repeatable demonstration, independent security review, and release
  readiness assessment.

## License

To be decided before public redistribution.
