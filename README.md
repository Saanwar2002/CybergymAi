# VulnResearch AI

A defensive vulnerability-research prototype combining ideas from CyberGym and CyberGym-E2E.

## Status

The local-fixture task core and structured LLM planning service are implemented. This is not an official CyberGym or CyberGym-E2E implementation and does not yet include benchmark adapters.

## Safety boundaries

- Run experiments only against explicitly authorized, local benchmark targets.
- Execute untrusted build and test commands inside isolated containers.
- Disable container networking by default.
- Do not expose benchmark services or the sandbox daemon publicly.
- Require human review before accepting patches or changing production systems.
- Treat model output, repository content, and vulnerability reports as untrusted input.
- A generated research plan is advisory only; it cannot authorize or initiate execution.

## Prototype goals

1. Validate a task manifest describing an authorized target and objective.
2. Produce a schema-validated research plan using an OpenAI-compatible API.
3. Run an explicitly supplied command in a constrained Docker container.
4. Capture logs and return a machine-readable result.
5. Add CyberGym and CyberGym-E2E adapters in a later milestone.

## Quick start

Requires Python 3.11+ and Docker.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Set `OPENAI_API_KEY` and, optionally, `OPENAI_BASE_URL` and `OPENAI_MODEL` in the environment (or your local `.env` loader). For Docker execution, set `VULNRESEARCH_SANDBOX_IMAGE` to an approved `python:3.11-slim@sha256:<64-hex-digest>` image reference. Mutable image tags are rejected.

Validate the harmless example task:

```bash
vulnresearch validate examples/task.json
```

Generate a structured plan (JSON):

```bash
vulnresearch plan examples/task.json
```

The plan contains an objective, assumptions, reproduction strategy, evidence requirements, remediation ideas, and human-review gates. Provider output is validated before it is displayed. CI uses a deterministic mock provider and does not require API credentials.

Sandbox execution is intentionally opt-in and requires Docker. Configure `VULNRESEARCH_SANDBOX_IMAGE` with an approved `python:3.11-slim@sha256:<64-hex-digest>` reference. Each run retains at most 1 MiB of stdout and stderr, records whether either stream was truncated, and writes a JSON run record plus hashed log artifacts under `artifacts/runs/` by default. Override the destination with `--output-dir`:

```bash
vulnresearch run examples/task.json --allow-execution --output-dir artifacts/runs
```

## Development

```bash
pytest
ruff check .
```

## Roadmap

- [x] Initial project structure and safety contract
- [x] Task manifest validation and tests
- [x] API-backed structured planning client and mock provider
- [x] Hardened isolated Docker runner, bounded logs, and run reporting (verified by an offline Docker fixture in CI)
- [ ] CyberGym local metadata adapter (read-only; no PoC generation or benchmark execution)
- [ ] CyberGym-E2E lifecycle workflow (in-memory state machine and human review gates implemented)
- [ ] Persisted evidence bundles and end-to-end tests with a harmless fixture

See [benchmark adapter scope and licensing notes](docs/BENCHMARK_ADAPTERS.md) before importing upstream task data, and [the E2E lifecycle workflow](docs/E2E_LIFECYCLE.md) for the current human-governed state machine.

## License

To be decided before public redistribution.
