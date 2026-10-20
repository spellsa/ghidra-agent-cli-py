# Ghidra CLI — agent reference

Execution context: Bash with `ghidra` available. Public interface: `use`, `exec`, `jobs`, `cancel`, `help`. Perform analysis through Python inline in `exec`.

## CLI contract

```text
ghidra [--server HOST:PORT] use --project PROJECT --program PROGRAM
ghidra [--server HOST:PORT] --target TID exec [--write] [-- ARG...]
ghidra [--server HOST:PORT] --target TID jobs [JID]
ghidra [--server HOST:PORT] --target TID cancel JID
ghidra [COMMAND] --help
ghidra --version
```

- `PROJECT`/`PROGRAM` are task-supplied selectors; `TID`/`JID` are exact returned IDs. Replace placeholders with actual values. `exec`, `jobs`, `cancel` require explicit `--target` on every call.
- `use`: both selectors required; stdout is one target ID. `--project`: configured alias or existing `.gpr` path. `--program`: project-internal name/path, not the binary's filesystem path. IDs are fixed to a project/program and become invalid after service restart; reacquire with `use`.
- `exec`: source comes from stdin; quote the heredoc delimiter. Default read; `--write` for mutations. Arguments after `--` become `args: list[str]`; place CLI flags before `--`.
- `jobs`: optional positional JID restricts output to one job; otherwise lists this target's active/queued/recent jobs. Empty matches produce no rows, exit 0.
- `cancel`: positional JID required; returns current state in the same format as `jobs`.
- `--server`: explicit flag > `GHIDRA_CLI_SERVER` > `127.0.0.1:8089`. Use the same endpoint for target acquisition and execution.
- `-h`/`--help`: command help. `-V`/`--version`: top-level version.

## Acquire a target

Use the project/program specified by the task. Prefer an existing `.gpr` absolute path when deployment-specific aliases are unknown. Program selectors are project-internal paths such as `/folder/program.bin`.

```bash
target=$(ghidra use --project "$project" --program "$program_path")
ghidra --target "$target" exec <<'PY'
print(program.getName())
print(program.getFunctionManager().getFunctionCount())
PY
```

Here `project` and `program_path` must be populated from the task or available project information. Use function discovery to select valid addresses; numeric examples below are illustrative, not target defaults.

Retain the returned ID in your agent context. Shell variables may not survive separate tool calls: substitute the literal ID in later commands, or reacquire with `use`. A target is not an agent-private session; agents selecting the same program may receive the same ID. Another agent's `use` never retargets your execution.

## Python contract and array API (0.4.3)

Fresh Python globals per execution; program analysis state persists. Available: `program` (selected Ghidra Program), `gh` (helpers), `args: list[str]`, `monitor`, `check_cancelled()`.

**Targets are always arrays**, including one item. Python lists/tuples accepted. Target-taking reads eagerly return `[(input, result), ...]`, preserving input order, duplicates, and original selectors. Lists inside each result remain grouped by target. Empty targets return `[]`. Listing methods return plain lists of objects. Calls complete all selected work before returning; printing is explicit.

```python
[(address, source)] = gh.decompile([0x401000])
for address, source in gh.decompile([0x401000, 0x402000]):
    print(hex(address), source)
for address, refs in gh.xrefs_to([0x401000, 0x402000], limit=20):
    for ref in refs:
        print(hex(address), ref.getFromAddress(), sep='\t')
```

Selectors: A = int hex, address-space string such as `'ram:00401000'`, or Address. F = function address/name or Function from this program. Function addresses must be entry points except in `function()`, which explicitly resolves interior addresses. T = type name/path or DataType. Numeric examples are illustrative; select valid addresses from the task/program. Ambiguous function/type names require an address/full type path.

### Target-taking reads

All return pairs; the last column is each pair's result.

| Signature | Result |
| --- | --- |
| `address(targets)` | Address / `None` |
| `function(targets)` | Function; interior addresses resolve to containing function |
| `decompile(targets, *, timeout=0, with_addresses=False)` | C source `str` by default; with_addresses=True returns line records described below; F selectors; interior address raises with the containing function entry point; timeout seconds, 0 unlimited |
| `read_bytes(targets, *, size)` | Exactly `size` bytes; A selectors |
| `read_string(targets, *, max_length=4096, encoding='utf-8', errors='strict')` | NUL-terminated `str`; max_length bytes; missing terminator raises |
| `disassemble(targets, *, count=20)` | List of existing contiguous Instructions; first address must contain a defined instruction; reading only |
| `callers(targets, *, limit=None, offset=0)` | Direct caller Functions, address ordered; F selectors |
| `callees(targets, *, limit=None, offset=0)` | Direct callee Functions, address ordered; F selectors |
| `xrefs_to(targets, *, limit=None, offset=0)` | References pointing to each A |
| `xrefs_from(targets, *, limit=None, offset=0)` | References originating at each A |
| `get_comment(targets, *, kind='EOL')` | Comment text / `None`; A selectors |
| `get_type(names)` | DataType; T selectors; primitive, pointer, array expressions supported |
| `find_strings(patterns, *, regex=False, case_sensitive=False, start=None, end=None, limit=None, offset=0)` | Matching defined-string Data per string pattern; substring search unless regex=True |
| `find_bytes(patterns, *, start=None, end=None, limit=None, offset=0)` | Matching Addresses per pattern; bytes or hex strings with `?` nibble wildcards, e.g. `'48 8? ??'`; overlapping matches included |

**String search scope:** `strings()` and `find_strings()` search only Ghidra-defined strings. Zero matches does not establish absence from the binary. Search undefined/raw memory with `find_bytes([text.encode(encoding)], ...)`, using the expected encoding.

Each name above is a method on `gh`. Paging on grouped results applies per target/pattern. `find_bytes` defaults to program min/max addresses. `read_string` supports byte, UTF-16 and UTF-32 NUL units according to encoding; use explicit endianness such as `utf-16-le` for BOM-free strings.

### Decompile line addresses

`gh.decompile(targets, with_addresses=True)` returns `[(input, rows), ...]`. Each row is `{'line': int, 'text': str, 'addresses': list[Address]}`. `line` is 1-based, includes blank lines, and matches the default source's `splitlines()`; `text` retains indentation and omits the newline. `addresses` contains deduplicated instruction-origin addresses linked by Ghidra to the line's tokens/statements, sorted by address space and offset. They are instruction origins, rather than referenced global-data addresses or callee entry points. One line may have several addresses; `[]` means Ghidra has no linked operation for that line. This mapping is not an exhaustive instruction listing: decompiler transformations can omit or share instruction origins. Print only the fields/lines needed; address mapping produces no automatic output or saved files.

### Listings

| Signature | Objects |
| --- | --- |
| `functions(*, name=None, start=None, end=None, min_size=None, max_size=None, unnamed=None, limit=None, offset=0)` | Address-ordered Functions; unnamed=True selects default-generated names, False selects other names |
| `strings(*, text=None, start=None, end=None, limit=None, offset=0)` | Defined-string Data |
| `symbols(*, name=None, kind=None, start=None, end=None, limit=None, offset=0)` | Symbols; kind matches native type, e.g. `'Function'`, `'Label'` |
| `memory_blocks(*, name=None, limit=None, offset=0)` | MemoryBlocks |
| `types(*, name=None, limit=None, offset=0)` | Program DataTypes; name searches full type path |

Name/text filters are case-insensitive substrings. Address bounds and min/max size are inclusive. Address filtering uses record entry/start address. `offset` skips matched objects before `limit`; `limit=None` means all, `limit=0` returns empty. Use filtered/paged queries to control result size.

### Writes

All require `exec --write`; address-based writes require an address inside program memory. Function writes require a function whose entry point is inside program memory. They execute eagerly, and return `[(target, None), ...]`. Each supports either common value or per-target pairs:

```python
gh.set_comment([0x401000, 0x402000], 'reviewed')
gh.rename_function([(0x401000, 'parse_header'), (0x402000, 'load_body')])
gh.apply_type([(0x403000, 'Header'), (0x404000, 'byte[16]')])
```

| Signature | Behavior |
| --- | --- |
| `rename_function(targets, name)` or `rename_function(edits)` | Rename F selectors |
| `rename_label(targets, name)` or `rename_label(edits)` | Rename primary label or create label at A; preserves function identity |
| `set_comment(targets, text, *, kind='EOL')` or `set_comment(edits, *, kind='EOL')` | Set comment at A; text=None removes it |
| `set_signature(targets, signature)` or `set_signature(edits)` | Apply complete C function declaration to F, including its function name |
| `apply_type(targets, type_name, *, clear=False, length=None)` or `apply_type(edits, *, clear=False, length=None)` | Apply T at A; default permits undefined-data conflicts, clear=True permits replacing defined data; instructions remain protected; length in bytes for variable-size types; fixed-size types use their declared length |

`edits` is an array of `(target, value)` pairs. Comment kinds: `EOL`, `PRE`, `POST`, `PLATE`, `REPEATABLE`. For signature type changes without renaming, keep the current function name in the declaration.

Operate on supplied `program`. Select another program through `use` + `--target`. One `exec --write` is one transaction/save unit: all selected mutations succeed and save, or uncommitted mutations roll back before other accesses resume. Exceptions fail the entire call; traceback notes identify batch item/selector. External file writes are separate. Exit 0 establishes save completion. For `SAVE_ERROR`, inspect `committed`/`phase` before retrying.

Useful object fields:
- Function: `getEntryPoint()`, `getName()`, `getBody().getNumAddresses()`.
- String Data: `getAddress()`, `getValue()`; Instruction: `getAddress()`, `getMnemonicString()`, `str(instruction)`.
- Reference: `getFromAddress()`, `getToAddress()`, `getReferenceType()`.
- Symbol: `getAddress()`, `getName()`, `getSymbolType()`.
- MemoryBlock: `getStart()`, `getEnd()`, `getName()`, `getSize()`.
- DataType: `getPathName()`, `getLength()`.
- Program: `getName()`, `getFunctionManager()`, `getMemory()`.

Convert Java-returned text with `str(...)` for Python string operations. For one result use `[(key, value)] = gh.method([target], ...)`; 0.4.0 requires arrays; migrate scalar calls from 0.3.x.

## Keep tool output small

Batch related work within one `exec`; emit selected fields rather than printing whole result arrays. Use one-record-per-line TSV and `repr(str(value))` for embedded newlines. Listings return arrays; obtain counts with `len(...)`, narrow using filters/limit first.

```bash
ghidra --target TID exec -- "$name_fragment" <<'PY'
for f in gh.functions(name=args[0], min_size=100, limit=20):
    print(f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses(), sep='\t')
PY
```

For repeated searches, explicitly save selected decompilations once; retain the resulting path across calls. `function_addresses` below is a task-selected list of integer addresses supplied as shell arguments. `pattern` is the current search expression.

```bash
out=$(mktemp "${TMPDIR:-/tmp}/ghidra-decompile.XXXXXX")
ghidra --target TID exec -- "${function_addresses[@]}" <<'PY' > "$out"
for address, source in gh.decompile([int(value, 0) for value in args]):
    print(f'=== {address:#x} ===')
    print(source)
PY
rg -n -C 3 -- "$pattern" "$out"
printf 'source=%s\n' "$out"
```

Remove temporary files when finished. Normal calls create no source/output history files automatically. Shell redirection writes on the caller side. Python `open()` accesses the execution-side filesystem; use task/deployment-provided shared absolute paths when exchanging files.

## Parallel execution and jobs

`exec` waits for completion; query/cancel from another tool call or shell. Decompilation borrows one program-local decompiler per call and processes the target array sequentially. Concurrent calls borrow separate instances; returned instances expire after 60 idle seconds. Write executions use fresh instances and invalidate idle instances before/after the transaction. Failed decompilation instances are discarded. Same-program reads overlap; same-program writes run exclusively and wait for other accesses; different-program operations may overlap. Committed writes are visible to subsequent reads. Python variables and output are execution-local.

`jobs` and `cancel` return headerless TSV:

```text
JID<TAB>STATE<TAB>TID<TAB>read|write<TAB>BLOCKING_JIDS
```

`BLOCKING_JIDS` is comma-separated or empty. States: `queued`, `running`, `success`, `error`, `cancel_requested`, `cancelled`. Jobs can include other agents using this target; identify the intended JID before cancellation. Recently completed jobs are transient history, not stored results.

```bash
ghidra --target TID jobs
ghidra --target TID jobs JID
ghidra --target TID cancel JID
ghidra --target TID jobs JID
```

A successful `cancel` means the request was accepted; observe `cancelled` for completion (or the final state if already finished). Cancellation is cooperative; use `monitor`/`check_cancelled()` in long custom operations. Closing the receiving pipe, e.g. via `head`, requests cancellation of unfinished execution. The CLI prints `CANCEL_REQUESTED` on stderr and exits 1; observe the final job state with `jobs JID`. A shell pipeline normally returns the last command's status; use `set -o pipefail` or inspect `PIPESTATUS` to retain the CLI failure. Limit inside Python when normal completion matters.

## Success, errors, recovery

- stdout = script output; stderr = explicit script stderr plus an error-detail path on failure. No success marker or JSON envelope. A silent execution can succeed. A broken output pipe reports `CANCEL_REQUESTED` for unfinished execution, or `BROKEN_PIPE` for non-execution output, directly on stderr.
- Exit codes: 0 = completed successfully; 1 = execution/connection/save failure or cancellation; 2 = argument syntax error with CLI help.
- Printed output alone does not establish success. With pipelines, use `set -o pipefail`; inspect `${PIPESTATUS[0]}` immediately for the Ghidra exit code. `rg` also returns 1 for no matches.
- On failure, read the absolute error-file path printed on stderr. It is local to the calling process's OS temporary directory (`TMPDIR` applies). Prior script output may precede failure; explicit script stderr may precede the path.
- Detail contains the available target/project/program context, code/message/next_action, source/hash, traceback, output tails. Inspect only needed fields, then source/traceback if necessary. Error-only reports are temporary; preserve deliberately if needed.

| Error code | Action |
| --- | --- |
| `TARGET_REQUIRED`, `TARGET_UNAVAILABLE` | Acquire/reacquire target, specify `--target` |
| `NO_PROJECT_OPEN`, `PROGRAM_NOT_FOUND` | Correct project `.gpr` / project-internal program selector |
| `PROJECT_OPEN_ERROR`, `PROJECT_OPEN_TIMEOUT` | Read open/startup failure detail |
| `SYNTAX_ERROR`, `RUNTIME_ERROR` | Read current source/line/traceback; fix code |
| `SAVE_ERROR` | Inspect `committed`, `phase`, current program contents before repeating mutations |
| `CONNECTION_ERROR`, `EXECUTION_INTERRUPTED` | Check endpoint and job/current program state before repeating mutations |
| `CANCELLED` | Confirm final job state |
| `JOB_NOT_FOUND` | Select an available JID from the same target's jobs |
| `SOURCE_MISMATCH` | Resend original code |
| `CLI_ERROR` | Read local failure detail |
