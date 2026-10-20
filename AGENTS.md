# Development

- CLI: `src/inline_main.rs`; resident backend: `python/ghidra_inline/`.
- Agent API contract: `docs/AI_REFERENCE.md`. Keep it consistent with the implementation.
- Prefer Python inline, explicit immutable targets, eager array APIs, and ordinary shell output.
- Successful executions create no automatic source/output history. Errors use caller-local temporary reports.
- Keep changes simple and run `cargo test --locked --bin ghidra` plus `tests/run_smoke.sh` for runtime changes.
- Integration tests use generated sample programs and must restore temporary mutations.
