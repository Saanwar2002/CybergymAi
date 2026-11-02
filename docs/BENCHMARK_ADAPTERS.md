# Benchmark adapter policy

## CyberGym

The first adapter is deliberately metadata-only. It recognizes the upstream task families
`arvo`, `oss-fuzz`, and `oss-fuzz-latest`, plus the four published difficulty labels
(`level0` through `level3`). It resolves an existing task directory under a caller-supplied
local data root and returns a normalized descriptor.

The adapter does **not**:

- download benchmark data or extract archives;
- create `submit.sh` files or contact a submission server;
- generate proof-of-concept inputs;
- run, fuzz, debug, or otherwise execute benchmark code;
- copy or redistribute upstream task assets.

The upstream CyberGym code repository is Apache-2.0 licensed. That does not automatically
license the separately hosted benchmark dataset, the underlying OSS-Fuzz/ARVO projects,
or their binaries and source archives. Review the applicable license for each dataset
component before downloading, copying, or redistributing it. Keep benchmark data local and
do not expose any CyberGym server or task infrastructure to the public internet.

References:

- https://github.com/sunblaze-ucb/cybergym
- https://huggingface.co/datasets/sunblaze-ucb/cybergym

## CyberGym-E2E

The initial CyberGym-E2E adapter is also metadata-only. It accepts local task references in
`<project>/<task-type>_<task-id>` form and the upstream modes `e2e` and `patch-only`.
It reads the project's `project.toml` and the task's `config.toml`, then returns only
project name, language, mode, target program, vulnerable commit, and resolved local path.
Ground-truth patch fields are ignored and are not exposed in the descriptor.

The adapter does **not**:

- download the dataset or pull benchmark Docker images;
- read or copy PoCs, ground-truth patches, build scripts, or test scripts;
- generate PoCs or patches;
- execute benchmark scripts or invoke the upstream evaluator;
- claim compatibility with the official four-stage scoring protocol.

CyberGym-E2E distinguishes end-to-end and patch-only modes and validates outputs through
four stages. This repository currently maps task metadata only; it does not implement
those evaluation stages. Review upstream licensing for the code, dataset, and each
underlying project before using or redistributing task assets.

References:

- https://github.com/sunblaze-ucb/cybergym-e2e
- https://www.cybergym.io/cybergym-e2e/

## Compatibility status

Both adapters are local metadata resolvers, not claims of full official benchmark
compatibility. They do not implement PoC submission protocols, scoring, server
interactions, dataset download workflows, or execution. Those capabilities require
separate security and licensing review.
