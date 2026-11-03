# VulnResearch AI

A defensive vulnerability-research prototype combining selected workflow ideas from
CyberGym and CyberGym-E2E. It is a local prototype, not an official implementation of
either benchmark and not a production-ready autonomous vulnerability agent.

## Current status

Implemented:

- Versioned local task manifests and fail-closed local-fixture policy.
- Structured LLM planning with a deterministic mock provider for CI.
- Opt-in Docker execution with offline networking, read-only workspace, non-root user,
  dropped capabilities, resource limits (including swap cap), a no-implicit-pull policy, pinned image references, bounded logs, and
  JSON run reports.
- Read-only local metadata adapters for CyberGym and CyberGym-E2E.
- Human-governed lifecycle state machine, persistent hash-chained audit events, evidence
  bundles, patch artifact capture, and validation of sandbox test reports.
- Provider-neutral execution backend contract with explicit VM capability requirements,
  per-run CPU/memory/disk/process/input/output limits, digest-pinned guest-relative input
  manifests, bounded output-artifact manifests (64 artifacts maximum), canonical
  versioned JSON execution manifests and digests echoed by results, absolute 10 MiB
  per-stream result caps, crash-durable atomic benchmark reports, evidence bundles, and
  lifecycle audit-store creation; persisted execution manifests and hashed bounded logs;
  strict manifest revalidation at lifecycle ingestion; lifecycle reproduction and patch-test
  evidence binding; reported-usage checks; cleanup
  verification, explicit terminal-status/exit-code consistency, and deterministic tests.
- A dedicated benchmark execution entry point that requires an explicitly injected
  backend and blocks before execution when no backend is configured or disposable-VM
  capabilities are missing. Its execute-and-report wrapper persists audit output and
  preserves the validated result if report storage fails. It has no Docker/container fallback.
- Harmless-fixture lifecycle integration tests.

Not implemented:

- Official CyberGym or CyberGym-E2E scoring/evaluator compatibility.
- Benchmark dataset download or redistribution.
- Automatic patch application or project regression-suite execution.
- A concrete VM provider, VM provisioning, or VM-level isolation in this deployment.

## Safety boundaries

- The current CLI execution policy permits explicitly approved local fixtures only.
- A human must opt in to local-fixture execution with `--allow-execution`.
- The model produces advisory plans; it cannot authorize or start execution.
- Docker networking is disabled and the workspace is mounted read-only.
- Docker shares the host kernel and is not a complete boundary for hostile code. Use a
  dedicated disposable VM before considering real benchmark workloads.
- The benchmark API requires a caller-supplied backend and fails closed without one;
  container capabilities cannot satisfy its disposable-VM requirement.
- Backend capability fields are declarations, not proof of isolation. The policy gate
  checks those declarations only; an operator and independent reviewer must verify them
  against the actual deployment before any benchmark workload is considered.
- Human approvals and lifecycle actor roles are application-level records, not
  cryptographic identities or proof of legal authorization.
- Benchmark adapters read local metadata only; they do not download, generate, submit,
  or execute benchmark artifacts.

Read [the security model](docs/SECURITY.md) before running code and the
[independent review checklist](docs/SECURITY_REVIEW_CHECKLIST.md) before considering any
real benchmark workload. Review the [benchmark adapter policy](docs/BENCHMARK_ADAPTERS.md)
before acquiring task data.

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

The `vulnresearch.execution.execute_benchmark` API is the recommended benchmark
execution entry point. It accepts an explicitly injected backend, checks its declared
capabilities against the mandatory disposable-VM requirements before invoking it, and
rejects unconfirmed cleanup or oversized output. These declarations do not prove the
underlying deployment is isolated; they require independent verification. No provider is
configured, so benchmark execution currently raises `BenchmarkBackendUnavailable` rather
than using the local Docker fixture runner.

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

GitHub Actions also pulls and pins the sandbox image, executes the harmless offline fixture, and runs the complete two-stage patch workflow demo with scripted human-review inputs.

## Roadmap

- [x] M0–M3: project foundation, task core, structured planning, isolated local-fixture
  execution, bounded reports, and offline Docker CI fixture.
- [x] M5 workflow foundation: human-governed lifecycle, persistent audit store, evidence
  bundles, patch proposal capture, test-report validation, and harmless-fixture workflow.
- [x] M4/M5 metadata adapters: local read-only CyberGym and CyberGym-E2E task mapping.
- [x] Record immutable upstream code references for both adapters; dataset acquisition, dataset licensing, and evaluator compatibility remain out of scope.
- [ ] M4/M5 remaining: controlled benchmark conformance and real project regression runs
  inside a separately reviewed VM-level isolation boundary.
- [x] M6 demo: repeatable two-run harmless baseline/candidate workflow with interactive human review gates.
- [ ] M6 remaining: independent security review and release-readiness assessment.

## License

To be decided before public redistribution.
