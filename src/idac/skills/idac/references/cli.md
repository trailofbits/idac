# idac Quick Reference

The command grammar for the `idac` CLI.

## Conventions

- list commands use one optional positional filter such as `NAME_FILTER` or `TYPE_FILTER`
- `--regex` enables regular-expression matching
- matching is case-sensitive by default; `-i` makes it case-insensitive
- `function list` text output includes the containing section, such as `.plt` or `.text`
- `function list --demangle` matches and renders demangled display names
- `function metadata` and JSON `function list` rows include `display_name` when available; JSON `function list` rows also include `section`
- `segment list` lists database segments
- setup, maintenance, and utility commands live under `misc`

## Common reads

```bash
idac docs
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
idac function prototype show "sub_08042010"
idac function locals list "sub_08041337"
idac decompile "sub_08041337"
idac decompile "sub_08041337" -o "/tmp/sub_08041337.txt"
idac decompilemany "sub_08041337" --out-file "/tmp/sub_08041337.c"
idac decompilemany --functions-file "funcs.txt" --out-dir "/tmp/decomp"
idac disasm "sub_08041337"
idac ctree "sub_08041337"
idac xrefs "sub_08041337"
idac imports
idac search bytes "74 69 6e 79" --segment "__cstring" --timeout 30
idac search strings "tiny" --segment "__cstring" --timeout 30
```

`xrefs` is a top-level command; there is no `function xrefs` command.
For broad function discovery, prefer `function list "name1|name2" --regex -i` so IDA filters before rendering. Add `--demangle` when the filter should match demangled display names. Avoid producing a full function list just to pipe it into `rg`; add `--out <path>` if the filtered result is still too large for inline output.

## Preview

`idac` preview is always a wrapper and always writes JSON or JSONL.
The payload includes `command`, `status`, `before`, `after`, `result`, `readback`, `undo`, `artifacts`, and `stderr`.

```bash
idac preview -o "/tmp/preview.json" \
  function prototype set "sub_08042010" --decl "long long __cdecl sub_08042010(long long lhs, long long rhs)"
```

Use `--propagate-callers` when you also want to apply the new callee type at matching caller call sites.

Read-only commands under `preview` are treated as no-op previews with identical `before` and `after` payloads.

## Batch

Batch accepts one command per line and writes structured JSON or JSONL.
It allows `preview ...` lines, but commands that are not batch-safe are rejected.

```bash
idac batch "recovery.idac" -o "/tmp/recovery.json"
```

Batch files may include blank lines and `#` comments.

Example batch file:

```text
# recovery.idac
type declare --replace --decl-file "recovered_types.h"
type declare --clang --decl-file "recovered_templates.hpp"
function prototype set "sub_08041337" --decl-file "sub_08041337_proto.h"
function locals update "sub_08041337" "v12" --rename "value_maybe" --decl-file "local_v4.h"
function locals rename "sub_08041337" "v12" --new-name "value_maybe"
function locals retype "sub_08041337" "value_maybe" --type "unsigned int"
function locals retype "sub_08041337" "value_maybe" --decl-file "local_v4.h"
preview function prototype set "sub_08041337" --decl-file "sub_08041337_proto.h"
```

Keep setup-only `misc` commands such as `misc plugin install` and `misc skill install` outside saved batch files.
`search strings` and `search bytes` require both `--timeout` and `--segment`.
On dyld shared caches, `search strings` only allows `--scan` with explicit `--start` / `--end` bounds up to 16 MiB.
For `function locals retype`, `--type` is shorthand for simple type text. Use `--decl` or `--decl-file` when you need a full declaration, such as arrays or function pointers.

## Misc commands

These setup, maintenance, and utility commands live under `misc`:

- `misc rename`
- `misc reanalyze`
- `misc plugin install`
- `misc skill install`

Some `misc` commands are intentionally unavailable in `preview` or `batch`.

## Bundled docs

`idac docs` prints an agent-oriented index of bundled reference material without needing a live IDA target.
Use `idac docs TOPIC` for focused guidance, such as `cli`, `workflows`, `targets`, `troubleshooting`, `class-recovery`, `ida-cpp-type-details`, `ida-set-types`, `templates`, or `workspace`.
Use `idac docs --list` to list every topic and `idac docs --all --out docs.md` to write all bundled docs to a file.

## Output notes

- terminal output still enforces the inline size limit
- large inline results print a short summary first, then error
- `type declare --clang` uses IDA's clang parser for more complex C/C++ declarations
- `type list`, `type struct list`, and `type enum list` require `--out` when no pattern is given
- `decompile` uses `-o/--out` for a single rendered result; `decompilemany` uses `--out-file` or `--out-dir` for bulk artifacts
- `decompilemany FUNCTION_FILTER` selects functions by name substring; it is not a list of exact functions
- for multiple explicit functions, write one function name or address per line and pass `decompilemany --functions-file <path>`
- `decompilemany --out-file` writes combined text
- `decompilemany --out-dir` writes one file per function plus `manifest.json`
