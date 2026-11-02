# VulnResearch AI — Project Blueprint

**Document status:** Implementation blueprint  
**Version:** 1.0  
**Repository:** `Saanwar2002/CybergymAi`  
**Default branch:** `main`  
**Project approach:** Combined CyberGym + CyberGym-E2E concepts; API-based model integration; prototype-first delivery.

This document is the project’s source of truth for architecture, milestones, engineering standards, safety requirements, and acceptance criteria. Update it whenever a material design decision changes.

---

## 1. Executive summary

VulnResearch AI is a defensive vulnerability-research orchestration platform. It is intended to help an authorized researcher organise vulnerability-reproduction work, collect evidence, reason about remediation, and verify outcomes through a controlled workflow.

The project combines two complementary evaluation ideas:

- **CyberGym-style tasks:** reproduce and investigate a known vulnerability in a defined software target.
- **CyberGym-E2E-style lifecycle:** coordinate the broader process from understanding a report through reproduction, patch proposal, and verification.

The initial product is a research assistant and workflow orchestrator, not an autonomous offensive agent. It must operate only on explicitly authorized targets and isolated benchmark environments. A model may propose plans and explain evidence; deterministic tools and human reviewers remain responsible for execution decisions and acceptance.

### Product principles

1. **Safety first:** explicit scope, isolation, least privilege, and human approval.
2. **Reproducibility:** every run has a manifest, versioned inputs, logs, and structured results.
3. **Evidence over assertion:** conclusions must link to observable test output or source evidence.
4. **Human control:** no autonomous production changes, disclosure, or external target testing.
5. **Modular integration:** benchmark adapters, model providers, and execution backends are replaceable.
6. **Incremental delivery:** establish a reliable local prototype before adding benchmark complexity.

---

## 2. Goals, non-goals, and success measures

### 2.1 Goals

- Parse and validate a machine-readable research task.
- Check that the target and requested activity are within an approved scope.
- Generate a structured, defensive research plan through a configurable LLM API.
- Execute approved, bounded test commands in a disposable isolated environment.
- Capture stdout, stderr, exit status, timing, and relevant artifact references.
- Support reproducible task runs and machine-readable reports.
- Add adapters for supported CyberGym and CyberGym-E2E task formats after the core runner is stable.
- Guide researchers through reproduction, patch review, and regression verification.
- Provide an auditable record of human approvals and tool actions.

### 2.2 Non-goals for the prototype

- Scanning arbitrary public IP addresses, domains, or third-party systems.
- Autonomous exploitation, persistence, lateral movement, credential theft, or data exfiltration.
- Running untrusted code on the host or with unrestricted network access.
- Automatically merging patches, publishing advisories, or deploying to production.
- Claiming official benchmark compatibility before adapter conformance tests pass.
- Training or fine-tuning a foundation model.
- Building a multi-tenant hosted service before local security controls are proven.

### 2.3 Prototype success criteria

The prototype is successful when:

- A valid task manifest can be loaded and invalid manifests fail closed.
- The CLI can validate a task without invoking a model or running code.
- The API client can produce a schema-constrained plan and handle missing credentials, timeouts, and provider errors safely.
- An explicitly approved harmless fixture can run in a container with network disabled and resource limits.
- Run metadata and logs can be saved in a predictable output format.
- Automated tests cover validation, policy decisions, API error handling, sandbox command construction, and report generation.
- CI runs formatting/linting and tests on every pull request.
- A reviewer can reproduce a fixture run from documented instructions.

---

## 3. Users and primary workflows

### Primary user

A security researcher, vulnerability analyst, or software maintainer working on a target they own or are explicitly authorized to assess.

### Workflow A — Prepare a task

1. Researcher creates or imports a task manifest.
2. System validates its schema and required fields.
3. Scope policy checks target identity, authorization metadata, permitted operations, and execution profile.
4. Researcher reviews the task summary and explicitly approves execution where required.

### Workflow B — Plan research

1. System builds a bounded prompt from validated task data.
2. LLM returns a structured plan: objective, assumptions, safe reproduction outline, evidence requirements, remediation considerations, and verification criteria.
3. System validates the model response against a schema.
4. Researcher edits or approves the plan.
5. The plan is stored with provider/model metadata and a prompt/template version.

### Workflow C — Execute a fixture or benchmark task

1. Runner resolves the approved workspace and execution profile.
2. Runner prepares an isolated disposable environment.
3. Network is disabled by default; resource, process, filesystem, and time limits are applied.
4. Only the approved command and read-only input workspace are mounted.
5. Execution result and logs are collected.
6. Environment is destroyed, and the run is marked completed, failed, timed out, or blocked.

### Workflow D — Review a patch

1. Researcher supplies a candidate patch or branch.
2. System runs the task's permitted regression checks in an isolated environment.
3. Results are compared with the baseline.
4. System prepares a review report with test evidence, unresolved risks, and limitations.
5. A human reviewer decides whether the patch is acceptable.

---

## 4. System architecture

### 4.1 Logical components

| Component | Responsibility | Initial implementation |
|---|---|---|
| CLI / API boundary | User commands and input validation | Python CLI |
| Task registry | Load, validate, identify task definitions | JSON manifests |
| Scope and policy engine | Authorization and action gating | Local policy module |
| Workflow orchestrator | Coordinate plan, approval, run, report states | Python service layer |
| LLM provider interface | Plan generation and evidence explanation | OpenAI-compatible HTTP API |
| Benchmark adapters | Translate benchmark formats into internal tasks | CyberGym first, E2E next |
| Execution backend | Run approved commands in isolation | Docker runner |
| Artifact store | Store logs and reports | Local filesystem initially |
| Reporting | Produce JSON and Markdown summaries | Python serializers |
| Observability | Structured events, timings, error records | Python logging initially |

### 4.2 High-level flow

```text
Researcher
    |
    v
CLI / API
    |
    v
Task Loader + Schema Validation
    |
    v
Scope & Policy Gate <---- Authorization metadata / approval
    |
    v
Workflow Orchestrator
    |                         |
    v                         v
LLM Provider Interface     Benchmark Adapter
    |                         |
    +------------+------------+
                 |
                 v
        Approved Run Specification
                 |
                 v
         Isolated Execution Backend
                 |
                 v
      Logs + Artifacts + Run Metadata
                 |
                 v
       Evidence / Report Generator
                 |
                 v
          Human Review Decision
```

### 4.3 Architectural boundaries

- The LLM must never receive host secrets, API keys, or unrestricted filesystem contents.
- The LLM does not execute commands directly. It can propose structured plans; the policy engine and runner decide what is allowed.
- Benchmark-specific formats must be translated by adapters into a stable internal task model.
- The execution backend must accept only a validated run specification, never raw model-generated shell text.
- Artifacts are treated as untrusted input when reloaded or passed to a model.
- External network access remains disabled unless a future, separately reviewed benchmark requirement explicitly justifies a narrowly scoped exception.

---

## 5. Repository layout target

The existing repository is an initial scaffold. Grow it toward this structure as features are implemented; do not create empty placeholder modules without a working purpose.

```text
.
├── README.md
├── PROJECT_BLUEPRINT.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── BENCHMARK_ADAPTERS.md
│   ├── OPERATIONS.md
│   └── decisions/
│       └── 0001-initial-architecture.md
├── examples/
│   ├── task.json
│   └── fixtures/
├── vulnresearch/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── task.py
│   ├── policy/
│   │   ├── __init__.py
│   │   └── scope.py
│   ├── workflow/
│   │   ├── __init__.py
│   │   └── orchestrator.py
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   └── openai_compatible.py
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── cybergym.py
│   │   └── cybergym_e2e.py
│   ├── execution/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   └── docker.py
│   ├── artifacts/
│   │   ├── __init__.py
│   │   └── store.py
│   └── reporting/
│       ├── __init__.py
│       └── report.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── fixtures/
└── .github/
    └── workflows/
        └── ci.yml
```

---

## 6. Core data contracts

Use versioned JSON-compatible schemas. Reject unknown or malformed security-critical fields rather than silently guessing.

### 6.1 Task manifest (target schema)

Example shape (illustrative; implementation should formalize this with JSON Schema or Pydantic):

```json
{
  "schema_version": "1.0",
  "task_id": "local-fixture-001",
  "name": "Harmless local fixture",
  "description": "A local test task with no external target.",
  "source": {
    "kind": "local_fixture",
    "reference": "examples/fixtures/hello"
  },
  "authorization": {
    "status": "approved",
    "scope": "local_fixture_only",
    "approved_by": "researcher",
    "approval_reference": "local-development"
  },
  "workspace": "examples/fixtures/hello",
  "execution_profile": "offline_readonly",
  "commands": [
    {
      "id": "smoke-test",
      "argv": ["python", "-c", "print('fixture ready')"],
      "timeout_seconds": 30
    }
  ],
  "acceptance_criteria": [
    "The smoke test exits successfully."
  ]
}
```

Important contract rules:

- Prefer argument arrays (`argv`) over shell command strings.
- Disallow shell interpolation by default.
- Use a workspace path resolved beneath a configured trusted workspace root.
- Require explicit authorization state and a known execution profile.
- Validate timeout, memory, CPU, process, and output-size bounds.
- Never accept a manifest-provided Docker image without an allowlist or trusted image policy.
- Do not treat a free-text statement of authorization as sufficient proof for remote targets.

### 6.2 Run record

Each run should persist:

- `run_id`, `task_id`, schema version, and creation timestamp.
- Git commit or source revision for the target where available.
- Adapter name and version.
- Execution profile and container image digest.
- Approved command identifiers (not secrets).
- Start/end timestamps, duration, exit code, timeout and status.
- LLM provider/model and prompt template version, if used.
- Artifact references and cryptographic hashes.
- Approval actor and approval timestamp.
- Policy decisions and blocked actions.

### 6.3 Report

A report should include:

- Task and run identifiers.
- Executive result: reproduced, not reproduced, inconclusive, blocked, or error.
- Exact environment and revision details.
- Evidence references and test output summaries.
- Findings separated from hypotheses.
- Patch and regression-test status.
- Limitations and missing evidence.
- Human reviewer and review decision, if any.

Never label a vulnerability confirmed solely because the model says it is present.

---

## 7. LLM integration design

### 7.1 Responsibilities

Use the API model for bounded assistance:

- Summarise researcher-provided vulnerability reports.
- Generate structured investigation plans.
- Explain test logs and compare expected versus observed behaviour.
- Suggest defensive remediation options.
- Draft regression-test ideas for human review.
- Summarise evidence and uncertainty.

### 7.2 Restrictions

- Do not give the model direct tool access to the host shell or Docker daemon.
- Do not send secrets, tokens, private keys, or unrelated source code to the provider.
- Treat repository files, issue text, test logs, and model output as untrusted data.
- Protect against prompt injection by separating instructions from retrieved content and limiting context.
- Require schema validation and policy checks on every model-produced object.
- Keep model output advisory; execution requires a separately approved action.

### 7.3 Provider abstraction

Define a small interface such as:

- `generate_plan(task_context) -> ResearchPlan`
- `summarise_evidence(evidence_bundle) -> EvidenceSummary`

Implement the current OpenAI-compatible API behind this interface. Keep model name, base URL, timeout, retry policy, and token budget configurable. Use environment variables or a secret manager; never commit credentials.

### 7.4 Reliability

- Set explicit connect/read timeouts.
- Retry only transient failures, with bounded exponential backoff.
- Avoid retrying non-idempotent operations.
- Record provider errors without logging request secrets.
- Validate response structure and handle refusal, truncation, malformed JSON, and empty content.
- Add deterministic mock-provider tests so CI does not require a paid API key.

---

## 8. Execution and isolation security

This is a critical security boundary and must be reviewed before running untrusted benchmark code.

### Required defaults

- No network access (`--network none`).
- Non-root container user where supported.
- Drop Linux capabilities.
- Enable no-new-privileges.
- Read-only root filesystem.
- Read-only mount for source inputs; separate bounded writable output directory if required.
- CPU, memory, process-count, disk, and wall-clock limits.
- No host Docker socket mount inside the workload.
- No host home directory, SSH directory, cloud credentials, or environment secrets mounted.
- Disposable container and cleanup on success, failure, cancellation, or timeout.
- Pin trusted container images by digest for reproducible runs.
- Capture bounded logs; prevent unbounded output from exhausting storage.
- Use a dedicated isolated runner/VM for hostile workloads; Docker alone is not a complete security boundary.

### Execution policy

1. Validate the task.
2. Resolve and verify the workspace is inside an approved root.
3. Check authorization and allowed profile.
4. Map the command identifier to an approved command definition.
5. Require explicit user approval for execution.
6. Start the sandbox with enforced limits.
7. Collect bounded output and exit metadata.
8. Destroy the sandbox and record cleanup status.
9. Mark the run blocked if any required control cannot be applied.

Do not silently downgrade isolation if Docker or a security option is unavailable. Fail closed.

---

## 9. Benchmark integration strategy

### 9.1 Adapter interface

Each adapter should translate upstream benchmark inputs into the internal task/run contracts. It should not bypass policy or call the execution backend directly.

Expected adapter capabilities:

- Identify supported upstream format/version.
- Parse a benchmark instance.
- Resolve local benchmark assets.
- Produce a normalized task definition.
- Map benchmark-specific outputs to the common report format.
- Declare required resources and whether network access is needed.
- Reject unsupported or ambiguous instances clearly.

### 9.2 CyberGym adapter

Planned work:

1. Review official CyberGym documentation, repository structure, task format, and license.
2. Pin a supported upstream revision and record it in adapter metadata.
3. Build a read-only parser for a small representative task subset.
4. Map task identifiers, target metadata, expected outputs, and allowed commands into the internal schema.
5. Add parser fixtures and compatibility tests.
6. Run only supported benchmark tasks inside the isolated runner.
7. Compare results with the benchmark's documented expected behaviour.
8. Document unsupported task categories and environment assumptions.

Do not copy benchmark assets or redistribute upstream material unless the applicable license permits it.

### 9.3 CyberGym-E2E adapter

Add only after the common workflow and CyberGym adapter are stable.

Map lifecycle stages into explicit states, for example:

```text
IMPORTED
  -> TRIAGED
  -> PLAN_APPROVED
  -> REPRODUCTION_ATTEMPTED
  -> EVIDENCE_REVIEWED
  -> PATCH_PROPOSED
  -> PATCH_TESTED
  -> HUMAN_ACCEPTED | HUMAN_REJECTED | INCONCLUSIVE
```

Every transition should record the actor, timestamp, input evidence, and decision. The agent may recommend a transition but cannot self-approve sensitive gates.

### 9.4 Compatibility policy

- Keep upstream references, revisions, and license notices documented.
- Do not claim benchmark scores or compatibility without running the official evaluation protocol.
- Preserve benchmark task identifiers and expected result semantics.
- Add regression fixtures whenever an adapter bug is fixed.

---

## 10. Testing and quality strategy

### Unit tests

- Manifest parsing and schema validation.
- Workspace path traversal and symlink rejection.
- Authorization and execution-profile decisions.
- Command allowlisting and argument handling.
- LLM response parsing, refusal, timeout, and provider error paths.
- Report serialization and artifact hashing.
- State-machine transition rules.

### Integration tests

- CLI validate/plan flow with a mock LLM.
- Docker runner with harmless local fixtures.
- Timeout and cleanup behaviour.
- Output truncation and artifact persistence.
- Adapter parsing against checked-in minimal fixtures.

### Security tests

- Reject unapproved tasks.
- Reject path traversal and workspace escape.
- Reject shell-string execution where argv is required.
- Reject privileged container settings.
- Confirm network is disabled by default.
- Confirm secrets and host credential paths are not mounted.
- Confirm malformed model output cannot trigger execution.
- Confirm prompt-injected task content cannot change system policy.
- Confirm cleanup occurs after failure and timeout.

### Quality gates

Every pull request must pass:

- Ruff linting and formatting checks.
- Pytest unit suite.
- Integration tests that do not require external credentials.
- Dependency vulnerability review.
- Secret scanning.
- CI workflow and basic packaging/install check.

A security-sensitive change requires review by a human maintainer before merge.

---

## 11. Delivery roadmap and milestones

Milestones are ordered by dependency. Estimate effort only after each milestone is broken into GitHub issues.

### M0 — Project foundation

**Deliverables**
- Blueprint and architecture decision record.
- Documented scope, non-goals, and safety rules.
- Stable Python package layout and developer instructions.
- CI workflow for linting and tests.

**Acceptance**
- A new developer can install the project and run tests using README instructions.
- CI runs on pull requests and main-branch pushes.

### M1 — Reliable task core

**Deliverables**
- Versioned task schema.
- Task loader and validator.
- Workspace-root enforcement.
- Scope and execution-profile policy module.
- Unit and security tests.

**Acceptance**
- Valid fixture manifests load.
- Missing, malformed, out-of-scope, and unsafe manifests fail closed.
- No execution occurs during validation.

### M2 — LLM planning service

**Deliverables**
- Provider interface and OpenAI-compatible implementation.
- Structured plan schema and validation.
- Configuration and secret handling.
- Mock provider for CI.
- Error handling, timeouts, and bounded retries.

**Acceptance**
- Plan generation works with a configured API key.
- CI tests do not need a real API key.
- Malformed model output is rejected and cannot initiate a run.

### M3 — Isolated execution and reporting

**Deliverables**
- Execution backend interface.
- Hardened Docker runner.
- Explicit approval gate.
- Bounded log and artifact store.
- Run records and JSON/Markdown reports.

**Acceptance**
- Harmless fixture runs in a network-disabled container.
- Timeout, failure, and cleanup are tested.
- Missing isolation controls cause a blocked run, not an unsafe fallback.

### M4 — CyberGym adapter

**Deliverables**
- [x] Review upstream task formats and separate code/data licensing considerations.
- [x] Document the supported metadata subset and adapter limitations.
- [x] Normalize local task metadata and validate task identifiers, difficulty, and root confinement.
- [x] Add parser fixtures and compatibility/security tests.
- [ ] Pin a benchmark revision and execute a controlled benchmark task in a dedicated VM.

**Acceptance**
- [x] The documented supported subset imports correctly from an existing local data directory.
- [ ] Benchmark execution is isolated and reproducible in the required VM boundary.
- [x] Unsupported task types, difficulty labels, and path escapes are rejected explicitly.

Implementation note: the CyberGym adapter is deliberately metadata-only. It does not download data, unpack archives, invoke upstream scripts, generate PoCs, or run benchmark code. See `docs/BENCHMARK_ADAPTERS.md`; do not interpret adapter completion as official benchmark compatibility.

### M5 — CyberGym-E2E workflow

**Deliverables**
- [x] Initial lifecycle state machine with role-gated transitions and immutable event records.
- [x] Persistent hash-chained lifecycle event storage and bounded evidence-bundle format.
- [x] Patch proposal capture and evidence-backed validation of sandbox regression reports.
- [x] Human review gates preventing agent self-approval.
- [x] Read-only E2E task metadata adapter for local project/task directories.
- [ ] Official E2E evaluator and real project regression workflow in a dedicated VM.

**Acceptance**
- [x] A complete harmless-fixture workflow can move from import to reviewed result with persisted audit history and evidence references.
- [x] No sensitive transition can be self-approved by the agent.
- [x] Every successful transition is auditable in the returned record and can be persisted in a verified hash chain.

Implementation note: the state machine, persisted `WorkflowSession`, patch-evidence flow, and single-writer hash-chained JSONL audit store are documented in `docs/E2E_LIFECYCLE.md`; local artifact manifests are documented in `docs/EVIDENCE_BUNDLES.md`; the metadata-only adapter is documented in `docs/BENCHMARK_ADAPTERS.md`. The patch workflow records a proposed diff and verifies a separately prepared harmless candidate fixture; it does not apply patches or run real project regression suites. The current report verifier binds report status/exit code and stdout/stderr metadata to the hashed evidence bundle. 

### M6 — Prototype hardening and demonstration

**Deliverables**
- [x] Repeatable two-run harmless baseline/candidate demo in `examples/demo_workflow.py` and `docs/DEMO.md`.
- [x] Threat model, security boundaries, and residual risks documented in `docs/SECURITY.md`.
- [x] Operational guide and troubleshooting documented in `docs/OPERATIONS.md`.
- [x] Architecture overview and known limitations documented in `docs/ARCHITECTURE.md` and README.
- [ ] Independent security review using `docs/SECURITY_REVIEW_CHECKLIST.md` before any real benchmark workload.

**Acceptance**
- [x] Demo is repeatable from a clean checkout after configuring Docker and the pinned image.
- [x] Security controls and failure modes are documented; CI exercises both the offline fixture and the complete harmless baseline/candidate workflow.
- [x] No unsupported claims about benchmark performance or production readiness.

---

## 12. Initial GitHub issue backlog

Create issues from these work packages and link each issue to its milestone.

| Priority | Work item | Depends on |
|---|---|---|
| P0 | Add CI workflow for lint, tests, and package install | M0 |
| P0 | Formalize versioned task manifest schema | M1 |
| P0 | Add trusted workspace-root and path traversal checks | M1 |
| P0 | Implement scope and execution-profile policy gate | M1 |
| P1 | Add mock LLM provider and structured plan model | M2 |
| P1 | Harden API configuration, timeout, and error handling | M2 |
| P1 | Add execution backend interface | M3 |
| P1 | Harden Docker runner and explicit approval flow | M3 |
| P1 | Persist run metadata, bounded logs, and artifacts | M3 |
| P2 | Review CyberGym upstream format and licensing | M4 |
| P2 | Implement CyberGym parser and fixture tests | M4 |
| P2 | Add lifecycle state machine and review events | M5 |
| P2 | Review CyberGym-E2E format and implement adapter | M5 |
| P3 | Add demo workflow, threat model, and operational docs | M6 |

---

## 13. Configuration and operations

### Configuration

Keep configuration explicit and validated at startup:

- LLM provider and base URL.
- Model identifier.
- API key from environment or secret manager.
- Request timeout and token/output budget.
- Trusted workspace root.
- Artifact output directory.
- Allowed execution profiles.
- Approved container images and digests.
- Resource and log limits.

Provide safe defaults. Never include real secrets in `.env.example`, fixtures, logs, or documentation.

### Local developer workflow

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
vulnresearch validate examples/task.json
```

Only run the execution command after reviewing the task manifest and confirming the local sandbox is available.

### Release discipline

- Use pull requests for feature work.
- Keep `main` releasable.
- Pin dependencies and benchmark revisions.
- Tag prototype milestones.
- Record breaking schema changes and provide migration notes.
- Publish a release only after tests and human review pass.

---

## 14. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Untrusted code escapes isolation | Host compromise | Dedicated disposable VM/runner, least privilege, no secrets, fail-closed policy |
| Prompt injection in reports or source files | Unsafe or misleading plan | Treat retrieved content as data, strict schemas, no direct model execution |
| Incorrect model conclusions | False positive/negative | Evidence-linked reports, deterministic tests, human review |
| Benchmark drift | Broken adapter or invalid results | Pin upstream revisions, compatibility fixtures, documented version support |
| API outage or cost spike | Interrupted workflow | Timeouts, bounded retries, budgets, mock provider, graceful failure |
| Secret leakage | Account or infrastructure compromise | Environment/secret manager, redaction, secret scanning |
| Excessive output or resource use | Runner/host exhaustion | CPU, memory, PID, disk, duration, and log limits |
| Unclear authorization | Unauthorized testing | Explicit scope metadata and approval gate; no arbitrary remote targets |
| Premature feature expansion | Unreliable prototype | Milestone gates and non-goals |

---

## 15. Governance and definition of done

A feature is done only when:

- Its purpose and scope are documented.
- Inputs are validated and errors are actionable.
- Security-sensitive decisions fail closed.
- Unit tests and relevant integration/security tests pass.
- Logs do not expose secrets.
- The README or relevant documentation is updated.
- A human reviewer approves the change.
- The feature's limitations are recorded.

A benchmark adapter is not complete until its supported upstream version, license considerations, task mapping, fixtures, and reproducibility instructions are documented.

A vulnerability finding is not confirmed until supported by reproducible evidence and reviewed by a human.

---

## 16. Immediate next actions

Work in this order; do not skip ahead to benchmark execution:

1. Inspect the existing scaffold and reconcile it with this blueprint.
2. Add CI (Ruff, pytest, package installation) and make the current test suite pass.
3. Formalize the task manifest schema and add path/scope validation.
4. Separate LLM, policy, workflow, and execution code into the target module boundaries.
5. Replace direct execution assumptions with an explicit approved run specification.
6. Harden the Docker runner and test its isolation configuration.
7. Add run records and report serialization.
8. Only then begin CyberGym upstream format and licensing review.

### First release target

The first demonstrable release should accept a harmless local fixture, validate its scope, generate a plan using a mock or configured API provider, require explicit approval, execute in an offline sandbox, and produce a reproducible evidence report.

**Do not describe the project as production-ready or benchmark-compatible until the corresponding acceptance criteria have been met.**
