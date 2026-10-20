# ghidra-agent-cli-py

A small shell interface to resident Ghidra for AI agents. Send Python on stdin, batch related analysis in one execution, and pipe selected output into ordinary tools such as `rg`.

Originally derived from [akiselev/ghidra-cli](https://github.com/akiselev/ghidra-cli), this project was substantially rewritten on 2026-10-20. It replaces the original command collection and Java bridge with a Rust frontend and a resident PyGhidra backend. The original command-line interface is not compatible with this fork.

**Agent contract:** [docs/AI_REFERENCE.md](docs/AI_REFERENCE.md). It contains every CLI argument, helper signature, return shape, and execution rule.

## What it does

- Immutable project/program targets: another agent selecting a program never retargets your commands.
- Eager array-based helpers for decompilation, memory, strings, references, call relationships, symbols, comments, and types. The full Ghidra Java API is also available through `program`.
- Optional decompiler line-to-instruction mappings with `with_addresses=True`.
- Concurrent reads, exclusive writes per program, independent programs in parallel. Decompilers are reused per program and retired after 60 idle seconds.
- One transaction per `exec --write`, automatic save on success, rollback on execution failure.
- Script stdout/stderr stream directly to the shell. Successful runs create no source/output history files. Failures produce a caller-local temporary diagnostic report.

## Run

The supplied container is tested on Linux x86-64, using Ghidra 12.1.2, Java 21, and PyGhidra 3.1.0. Docker Desktop can run it from Windows or macOS with an x86-64 Linux engine. Building the host CLI requires Rust 1.92 or newer.

From a checkout:

```bash
cargo install --path . --locked
mkdir -p projects
```

Place an existing Ghidra project (`analysis.gpr` and its matching `analysis.rep/`) in `projects/`. Alternatively, place your binary there and create a project before starting the service:

```bash
docker compose build
docker compose run --rm --entrypoint /opt/ghidra/support/analyzeHeadless ghidra \
  /projects analysis -import /projects/program.bin
```

Start the backend and select the project-internal program name:

```bash
docker compose up -d --build
target=$(ghidra use --project /projects/analysis.gpr --program program.bin)
ghidra --target "$target" exec <<'PY'
for f in gh.functions(name='parse', limit=10):
    print(f.getEntryPoint(), f.getName(), sep='\t')
PY
```

Use an actual function entry address or name for decompilation:

```bash
ghidra --target "$target" exec <<'PY' | rg -n -C 3 return
f = gh.functions(limit=1)[0]
print(gh.decompile([f])[0][1])
PY
```

Changes require `exec --write`. Keep the returned target ID for subsequent commands; acquire it again after backend restart. Project files must be writable by the service and closed in other Ghidra processes.

Compose defaults to UID/GID 1000. On Linux with another user ID, set `GHIDRA_UID` and `GHIDRA_GID` to your numeric IDs. `GHIDRA_PROJECTS_DIR` overrides the host project directory. The project directory is the only persistent mount; generated analysis data is excluded from Git.

The service executes supplied Python with its OS permissions and has no authentication. The Compose port is bound to localhost; use it only with trusted local clients.

## Use an existing Ghidra installation

Docker is optional. With Ghidra 12.1.2, Java 21 and Python 3.12 installed:

```bash
python3 -m venv .venv
.venv/bin/pip install --no-index \
  --find-links "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra==3.1.0
PYTHONPATH="$PWD/python" .venv/bin/python -m ghidra_inline.server
```

Set `GHIDRA_INSTALL_DIR` and `JAVA_HOME` to your installations. Native startup binds to `127.0.0.1:8089`; `--host` and `--port` override the listener. Set `GHIDRA_CLI_SERVER=host:port` or pass `ghidra --server host:port` to connect elsewhere. Project paths are resolved on the backend machine. `GHIDRA_PROJECT_DIRS` is a colon-separated search path for relative project selectors (default `/projects:/data`); `GHIDRA_PROJECT_ALIASES` optionally maps aliases to `.gpr` paths as a JSON object.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --bin ghidra
PYTHONPATH=python python3 -m unittest discover -s tests -p "test_*.py"
bash tests/run_smoke.sh
```

The smoke test requires Bash, Docker, Rust, Python 3.10+, ripgrep (`rg`), and a C compiler. It builds the public image, compiles a small fixture, imports two sample programs into a temporary Ghidra project, runs the integration suite, then removes the container and temporary project. It does not require your own binaries or projects. GitHub Actions runs the same checks.

The Rust frontend is `src/inline_main.rs`; the Python service, project workers, and helpers are under `python/ghidra_inline/`. One worker process owns each open project and its JVM. Run the backend locally or in a container and connect from your agent environment.

## Acknowledgments and license

This project began as a fork of [akiselev/ghidra-cli](https://github.com/akiselev/ghidra-cli), created by Alexander Kiselev. It has since evolved into an independent tool centered on Python inline execution, a resident PyGhidra backend, and concurrent use by AI agents.

We thank Alexander Kiselev and the upstream contributors for providing the starting point for this project. The original Git history is preserved, and this project continues under the GPL-3.0 license.

See [LICENSE](LICENSE). Ghidra and the container base images retain their respective licenses; the Docker build downloads the official Ghidra archive and verifies its SHA256.
