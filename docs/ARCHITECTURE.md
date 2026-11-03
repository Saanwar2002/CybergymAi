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
Execution backend policy gate
    |
    +---- harmless local fixture ----> Host Docker sandbox (offline, read-only)
    |
    +---- future benchmark workload -> Disposable VM -> guest-local Docker if required
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
| `sandbox.py` | Construct and run restricted Docker commands for harmless local fixtures; verify container removal and bound output-reader shutdown after timeouts or unexpected interruption |
| `execution/base.py` | Provider-neutral run specification with a versioned canonical JSON manifest and SHA-256 identity, digest-pinned input manifest, explicit resource/transfer limits, absolute 10 MiB per-stream and configurable aggregate output caps, bounded output-artifact manifest, backend-reported usage checks, and cleanup gate |
| `execution/reporting.py` | Crash-durably publish benchmark execution manifests, bounded hashed stdout/stderr evidence, backend usage/cleanup metadata, and output artifact descriptors (fsync staged files/directories and the publication parent) |
| `workflow/evidence.py` | Publish no-overwrite evidence bundle manifests only after file and staging-directory fsync; fsync the parent after staging cleanup |
| `workflow/store.py` | Create no-overwrite lifecycle audit stores with file/staging-directory fsync and parent-directory fsync after cleanup |
| `execution/runner.py` | Explicit benchmark entry point and execute-and-report orchestration; requires an injected backend, has no container fallback, and retains the validated result if report publication raises any ordinary exception |
| `reporting.py` | Crash-durably publish bounded local-fixture run output and JSON metadata (fsync each file, staging directory, and publication parent) |
| `adapters/cybergym.py` | Read-only local CyberGym metadata mapping |
| `adapters/cybergym_e2e.py` | Read-only local CyberGym-E2E project/task metadata mapping |
| `workflow/lifecycle.py` | State machine and actor-role transition rules |
| `workflow/store.py` | Hash-chained JSONL audit log with exclusive advisory locking for cooperating concurrent appenders |
| `workflow/evidence.py` | Bounded local evidence manifests and content verification |
| `workflow/session.py` | Session facade for transitions, benchmark reproduction and patch-test evidence binding, patch artifact capture, and test-report evidence |

## Trust boundaries

- LLM responses are untrusted suggestions; they cannot invoke the runner.
- Task manifests are untrusted until parsed, workspace-checked, and policy-approved.
- The Docker daemon and host kernel remain trusted components in the current harmless-fixture prototype.
- Real benchmark workloads require a separate disposable-VM backend; the host Docker socket must never enter the guest or workload.
- The future VM backend must stage only digest-verified manifest inputs read-only beneath a fixed guest input root, collect only bounded artifacts beneath a fixed guest output root, and fail closed when image, resource, network, staging, or destruction guarantees cannot be verified.
- `execution/runner.py` applies the benchmark policy to declared backend capabilities; the CLI still uses the separate Docker fixture runner, and no VM provider is available.
- Capability booleans are declarations only. This code cannot inspect or authenticate a VM deployment; operators must retain deployment evidence and obtain independent review before use.
- Run reports, patch artifacts, and evidence references are untrusted until verified.
- Lifecycle actor roles are logical controls, not authentication or digital signatures.
- Benchmark adapters never bypass the task policy or execution backend.

## Deliberate omissions

No remote target scanner, PoC generator, benchmark submission client, autonomous patch
application, VM provider integration, or public service is included. The VM boundary is
specified in [ADR 0002](decisions/0002-disposable-vm-boundary.md), but is not implemented. Full official benchmark compatibility requires
separate adapter conformance work, licensing review, and isolated-runner security review.
