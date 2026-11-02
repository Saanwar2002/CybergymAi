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

## Compatibility status

This is a local metadata resolver, not a claim of full official benchmark compatibility.
It does not implement the upstream PoC submission protocol, scorer, server, or dataset
download workflow. Those capabilities require separate security and licensing review.
