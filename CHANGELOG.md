# Changelog

## Unreleased

- Make the Docker build independent of private images and add a localhost-only Compose deployment.
- Replace legacy code, documentation, workflows, and tests with the current inline implementation and generated-fixture integration checks.

## 0.4.3

- Reuse program-local decompilers across read executions, retaining concurrent instances until 60 seconds idle.
- Invalidate pooled instances around writes and discard failed or cancelled instances.

## 0.4.2

- Add `gh.decompile(..., with_addresses=True)` with source-aligned line records and Ghidra-linked instruction origins.

## 0.4.1

- Reject writes outside program memory and roll back failed batches.
- Require function entry addresses, with explicit containing-function resolution through `gh.function()`.
- Report output-pipe cancellation on stderr and exit with code 1.
- Test every documented function selector and clarify defined-string search scope.

## 0.4.0

- Standardize target-taking helpers on eager array inputs and ordered `(input, result)` outputs.
- Add memory, string, byte-search, disassembly, call-relationship, symbol, comment, and type helpers.
- Support common-value and per-target batch mutations.

## 0.3.0

- Replace the upstream command collection with Python inline execution over a resident PyGhidra service.
- Add immutable targets, concurrent reads, serialized writes, transactions, streamed output, jobs, cancellation, and error-only temporary diagnostics.

Earlier history belongs to [akiselev/ghidra-cli](https://github.com/akiselev/ghidra-cli) and remains available in Git.
