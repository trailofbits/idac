# idac Quick Reference

The command grammar for the `idac` CLI.

## Conventions

- list commands use one optional positional filter such as `NAME_FILTER` or `TYPE_FILTER`
- `--regex` enables regular-expression matching
- matching is case-sensitive by default; `-i` makes it case-insensitive
- `function list` text output includes the containing section, such as `.plt` or `.text`
- `function list --demangle` matches and renders demangled display names
- `function metadata` and JSON `function list` rows include `display_name` when available; JSON `function list` rows also include `section`
- function-taking commands can resolve a unique demangled C++ name such as `ExampleClass::method_1`; if multiple functions match, use a mangled name, full signature, or address
- `segment list` lists database segments
- setup, maintenance, and utility commands live under `misc`

## Common reads

```bash
idac docs
idac docs guide
idac docs workflows
idac function list
idac function list --demangle
idac function list "init|open|close" --demangle --regex -i
idac function list "sub_08041337"
idac function list "sub_.*" --regex
idac function list "sub_08041337" -i
idac segment list
idac segment list "__TEXT|__cstring" --regex
idac function metadata "sub_08041337"
idac function frame "sub_08041337"
idac function stackvars "sub_08041337"
idac function callees "sub_08041337"
idac function callers "sub_08041337"
idac function prototype show "sub_08042010"
idac function locals list "sub_08041337"
idac decompile "sub_08041337"
idac decompile "ExampleClass::method_1"
idac decompile "sub_08041337" -o "/tmp/sub_08041337.txt"
idac decompilemany "sub_08041337" --out-file "/tmp/sub_08041337.c"
idac decompilemany --functions-file "funcs.txt" --out-dir "/tmp/decomp"
idac decompilemany --functions-file "funcs.txt" --out-dir "/tmp/decomp" --disasm --ctree
idac disasm "sub_08041337"
idac disasm --start "0x100000460" --end "0x1000004a0"
idac ctree "sub_08041337"
idac xrefs "sub_08041337"
idac imports
idac search bytes "74 69 6e 79" --segment "__cstring" --timeout 30
idac search strings "tiny" --segment "__cstring" --timeout 30
idac type deps "ExampleStruct"
idac type check --decl-file "recovered_types.h" --json
idac function prototype check "sub_08041337" --decl-file "sub_08041337_proto.h" --json
```

`xrefs` is a top-level command; there is no `function xrefs` command.
For broad function discovery, prefer `function list "name1|name2" --regex -i` so IDA filters before rendering. Add `--demangle` when the filter should match demangled display names. Avoid producing a full function list just to pipe it into `rg`; add `--out <path>` if the filtered result is still too large for inline output.
`search strings` and `search bytes` require both `--timeout` and `--segment`. On dyld shared caches, `search strings` only allows `--scan` with explicit `--start` / `--end` bounds up to 16 MiB.

## Preview

`idac` preview is always a wrapper and always writes JSON or JSONL.
The payload includes `command`, `status`, `before`, `after`, `result`, `readback`, `undo`, `artifacts`, and `stderr`.

```bash
idac preview -o "/tmp/preview.json" \
  function prototype set "sub_08042010" --decl "long long __cdecl sub_08042010(long long lhs, long long rhs)"
```

Read-only commands under `preview` are treated as no-op previews with identical `before` and `after` payloads.

## Batch

Batch accepts one command per line and writes structured JSON or JSONL.
It allows `preview ...` lines, but commands that are not batch-safe are rejected.
If a batch contains persistent mutating commands, `batch --out` is required so the ordered result log is preserved before any changes run.

```bash
idac batch "recovery.idac" --out "/tmp/recovery.json"
idac batch "recovery.idac" --lint --out "/tmp/recovery.lint.json"
```

Batch files may include blank lines and `#` comments. Example:

```text
# recovery.idac
type check --decl-file "recovered_types.h"
type declare --replace --decl-file "recovered_types.h"
function prototype set "sub_08041337" --decl-file "sub_08041337_proto.h"
misc reanalyze "sub_08041337"
function locals rename "sub_08041337" --index 6 --new-name "entry_count"
```

For a full recovery-pass example and the batch authoring rules, read [workflows.md](workflows.md#batch).

## Misc commands

These setup, maintenance, and utility commands live under `misc`:

- `misc rename` — rename a function or global symbol. Not available in `batch` or `preview`; commit symbol renames one-off.
- `misc reanalyze` — re-run IDA analysis on a function or range. Batch-safe; place it between type/prototype mutations and local cleanup.
- `misc plugin install` — install the GUI bridge plugin; `--force` replaces an existing install. Setup-only; rejected from `batch`.
- `misc skill install` — install the bundled skill. Setup-only; rejected from `batch`.

## Bundled docs

`idac docs` prints an agent-oriented index of bundled reference material without needing a live IDA target.
Use `idac docs TOPIC` for focused guidance, such as `guide`, `cli`, `workflows`, `targets`, `troubleshooting`, `class-recovery`, `ida-cpp-type-details`, `ida-set-types`, `ida-advanced-type-annotations`, `templates`, or `workspace`.
Use `idac docs --list` to list every topic and `idac docs --all --out docs.md` to write all bundled docs to a file.

## Output notes

- terminal output still enforces the inline size limit
- large inline results print a short summary first, then error
- `type declare --clang` uses IDA's clang parser for more complex C/C++ declarations
- `type check` validates declarations without importing them; use it before large or parser-risky `type declare` runs
- `function prototype check` validates a function declaration without applying it
- `type deps NAME` prints an existing type with IDA dependency expansion when available
- `type list`, `type struct list`, and `type enum list` require `--out` when no pattern is given
- for `function locals retype`, `--type` is shorthand for simple type text; use `--decl` or `--decl-file` for a full declaration, such as arrays or function pointers
- `decompile` uses `-o/--out` for a single rendered result; `decompilemany` uses `--out-file` or `--out-dir` for bulk artifacts
- `decompilemany FUNCTION_FILTER` selects functions by name substring; it is not a list of exact functions
- for multiple explicit functions, write one function name or address per line and pass `decompilemany --functions-file <path>`
- `decompilemany --out-file` writes combined text
- `decompilemany --out-dir` writes one file per function plus `manifest.json`
- `decompilemany --disasm` and `--ctree` require `--out-dir` and add per-function `.asm` and `.ctree` artifacts to the manifest
- long `decompilemany --out-dir` artifact names are shortened with a stable digest; use `manifest.json` `.functions[].address` as the stable exact lookup key, and `.functions[].artifact_path` / `.functions[].artifacts` for file paths
