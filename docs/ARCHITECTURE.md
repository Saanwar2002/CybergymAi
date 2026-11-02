# Architecture overview

## Execution and research flow

```text
Task manifest
    |
    v
Task loader + workspace validation
    |
    v
Scope policy (local fixture only)
    |
    +----> Structured LLM planning (advisory only)
    |
    v
Explicit CLI execution opt-in
    |
    v
Docker sandbox (offline, read-only workspace, bounded resources)
    |
    v
Bounded stdout/stderr + JSON run report
    |
    v
Evidence bundle (relative paths + SHA-256 digests)
    |
    v
Human-governed lifecycle session + hash-chained audit log
    |
    v
Human review decision
```

## Modules

| Module | Responsibility |
|---|---|
| `task.py` | Parse task manifests and constrain workspace paths |
| `policy/scope.py` | Fail-closed local-fixture authorization policy |
| `llm.py` | Structured advisory planning via a configurable provider |
| `sandbox.py` | Construct and run the restricted Docker command |
| `reporting.py` | Persist bounded run output and JSON metadata |
| `adapters/cybergym.py` | Read-only local CyberGym metadata mapping |
| `adapters/cybergym_e2e.py` | Read-only local CyberGym-E2E project/task metadata mapping |
| `workflow/lifecycle.py` | State machine and actor-role transition rules |
| `workflow/store.py` | Single-writer JSONL audit log with hash-chain verification |
| `workflow/evidence.py` | Bounded local evidence manifests and content verification |
| `workflow/session.py` | Session facade for transitions, patch artifact capture, and test-report evidence |

## Trust boundaries

- LLM responses are untrusted suggestions; they cannot invoke the runner.
- Task manifests are untrusted until parsed, workspace-checked, and policy-approved.
- The Docker daemon and host kernel remain trusted components in the current prototype.
- Run reports, patch artifacts, and evidence references are untrusted until verified.
- Lifecycle actor roles are logical controls, not authentication or digital signatures.
- Benchmark adapters never bypass the task policy or execution backend.

## Deliberate omissions

No remote target scanner, PoC generator, benchmark submission client, autonomous patch
application, or public service is included. Full official benchmark compatibility requires
separate adapter conformance work, licensing review, and isolated-runner security review.
