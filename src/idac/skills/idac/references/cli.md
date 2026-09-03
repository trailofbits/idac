# idac Quick Reference

The command grammar for the `idac` CLI.

## Conventions

- list commands use one optional positional filter such as `NAME_FILTER` or `TYPE_FILTER`
- `--regex` enables regular-expression matching
- matching is case-sensitive by default; `-i` makes it case-insensitive
- `function list` text output includes the containing section, such as `.plt` or `.text`
- `function list --demangle` matches and renders demangled display names
- `function metadata` and JSON `function list` rows include `display_name` when available; JSON `function list` rows also include `section`
- `function list` also accepts `--segment` to scope by segment and `--limit` to cap returned rows; `search bytes` accepts `--limit` too
- function-taking commands can resolve a unique demangled C++ name such as `ExampleClass::method_1`; if multiple functions match, use a mangled name, full signature, or address
- `segment list` lists database segments
- maintenance operations live under `misc`; installation commands live under `setup`; workspace scaffolding lives under `workspace`

## Context selection

- `-c/--context PATH` opens or attaches to an `.i64` or input binary through Nexus.
- `--instance RECORD_ID` attaches to one exact READY discovery record from
  `targets list`.
- The selectors are mutually exclusive. With neither, exactly one READY Nexus instance
  must exist.
- Context options may be placed before the command or on a context-aware subcommand.
- Headless opens wait for analysis and use a five-minute idle keepalive. Successful
  headless mutations save on release; live GUI saves are explicit.
- Discovery, timeout, connection, and version failures have no fallback or automatic
  retry.

## Common reads

```bash
idac docs
idac docs guide
idac docs workflows
idac database show --json
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
idac type show "ExampleStruct"
idac type deps "ExampleStruct"
idac type check --decl-file "recovered_types.h" --json
idac function prototype check "sub_08041337" --decl-file "sub_08041337_proto.h" --json
idac comment show "sub_08041337" --scope function
idac bookmark list
```

`xrefs` is a top-level command; there is no `function xrefs` command.
For broad function discovery, prefer `function list "name1|name2" --regex -i` so IDA filters before rendering. Add `--demangle` when the filter should match demangled display names. Avoid producing a full function list just to pipe it into `rg`; add `--out <path>` if the filtered result is still too large for inline output.
`search strings` and `search bytes` require both `--timeout` and `--segment`. On dyld shared caches, `search strings` only allows `--scan` with explicit `--start` / `--end` bounds up to 16 MiB.

## Comments and bookmarks

```bash
idac comment set "sub_08041337" "parses the record header" --scope function
idac comment set "0x100000460" "length check before the copy" --scope line
idac comment delete "sub_08041337" --scope function
idac bookmark add "sub_08041337" --comment "entry parser"
idac bookmark set 3 "0x100000460" --comment "length check"
idac bookmark show 3
idac bookmark delete 3
```

Comment scopes are `line`, `function`, `anterior`, and `posterior`. `--anterior` and
`--posterior` are shorthands for the matching scope, and `--repeatable` selects the
repeatable slot for `line` and `function` comments. `bookmark add` takes the first free
slot; `bookmark set` writes an explicit slot number.

`comment set`, `comment delete`, and the mutating `bookmark` commands are
preview-capable and batch-safe. Prefer them over local-only notes when a finding belongs
with the address it describes.

## Struct field and enum member edits

Edit one member of an existing local type without re-declaring the whole type:

```bash
idac type struct field set "ExampleStruct" "entry_count" --offset 0x18 --decl "unsigned int"
idac type struct field rename "ExampleStruct" "field_20" "flags"
idac type struct field delete "ExampleStruct" "field_28"
idac type enum member set "ExampleEnum" "EXAMPLE_FLAG_RETRY" --value 0x4
idac type enum member rename "ExampleEnum" "member_2" "EXAMPLE_FLAG_ASYNC"
idac type enum member delete "ExampleEnum" "member_3"
```

- `--offset` is a byte offset. A field already at that exact offset is retyped and, if
  needed, renamed; otherwise a new field is added there.
- `type struct field set --decl` accepts bare type text such as `unsigned int` or a full
  member declaration such as `unsigned int entry_count;`. Use `--decl-file` for array or
  function-pointer members.
- `type enum member set --value` is required and adds the member when it does not exist;
  `--mask` applies to bitfield enums.
- All six commands are mutating, preview-capable, and batch-safe, and they default to
  JSON output. They return the refreshed struct or enum, so the command output is the
  readback.
- Prefer these for small corrections to a type that is already close. Re-import through
  `type declare --replace` when the layout changes broadly.

## Preview

`idac` preview is always a wrapper and always writes JSON or JSONL.
The payload includes `command`, `status`, `before`, `after`, `result`, `readback`, `undo`, `artifacts`, and `stderr`.

```bash
idac function prototype show "sub_08042010"
idac function prototype check "sub_08042010" --decl "long long __cdecl sub_08042010(long long lhs, long long rhs)"
idac preview -o "/tmp/preview.json" \
  function prototype set "sub_08042010" --decl "long long __cdecl sub_08042010(long long lhs, long long rhs)"
```

The wrapper owns the preview artifact. Wrapped commands cannot set `--out`,
`--out-file`, or `--out-dir`; put `--out` on `preview`. Output paths cannot
alias the selected binary/database or a command input file. Insert `--` before the
wrapped command when its first token starts with a dash.

Preview-capable read-only commands are treated as no-op previews with identical `before` and `after` payloads. Commands not marked preview-capable remain rejected by the wrapper.

## Batch

Batch accepts one command per line and writes structured JSON or JSONL.
It allows `preview ...` lines, but commands that are not batch-safe are rejected.
If a batch contains persistent mutating commands, `batch --out` is required so the ordered result log is preserved before any changes run.
The wrapper writes an initial `pending` journal before dispatch, checkpoints after every line, and writes the terminal result only after the shared Nexus session closes. An interrupted batch records `interrupted` and exits 130. Mutating child commands cannot set `--out`; reserve child artifacts for read-only commands.

```bash
idac batch "recovery-preview.idac" --lint --out "/tmp/recovery-preview.lint.json"
idac batch "recovery-preview.idac" --fail-fast --out "/tmp/recovery-preview.json"
jq . "/tmp/recovery-preview.json"
idac batch "recovery-commit.idac" --lint --out "/tmp/recovery-commit.lint.json"
idac batch "recovery-commit.idac" --fail-fast --out "/tmp/recovery-commit.json"
```

Inspect every preview's `before` and `after` data before launching the commit batch. Batch files may include blank lines and `#` comments. Keep preview and commit in separate files:

```text
# recovery-preview.idac
type check --decl-file "recovered_types.h"
preview type declare --replace --decl-file "recovered_types.h"
function prototype show "sub_08041337"
function prototype check "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
preview function prototype set "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
```

```text
# recovery-commit.idac -- run only after inspecting recovery-preview.json
type declare --replace --decl-file "recovered_types.h"
function prototype set "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
misc reanalyze "sub_08041337"
function locals list "sub_08041337" --json --out "sub_08041337.locals.json"
```

For a full recovery-pass example and the batch authoring rules, read [workflows.md](workflows.md#batch).

## Setup and misc commands

Installation commands live under `setup` and are rejected from `batch`:

- `setup gui` — install ida-nexus v0.7.0 through pinned ida-hcli with
  ida-domain 0.5.1.
- `setup skill` — install the bundled skill for Claude Code, Codex, both, or a custom
  destination. `--host {claude,codex,both}`, `--dest PATH`, and `--mode {copy,symlink}`
  control where and how it lands.

IDA maintenance commands live under `misc`:

- `misc rename` — rename a function or global symbol. Preview-capable but not available in `batch`; commit symbol renames one-off.
- `misc reanalyze` — re-run IDA analysis on a function or range. Batch-safe, not preview-capable; place it between type/prototype mutations and local cleanup. Add `--end` for a range instead of a single function.

Workspace scaffolding lives under `workspace`:

- `workspace init [DEST]` — create a recovery workspace with `audit/`, `headers/`,
  `references/`, `scripts/`, `prompts/`, and `.idac/tmp/`. Add `--force` to overwrite
  user-tunable config in an existing workspace. Read `idac docs workspace` for the
  conventions it installs.

## Bundled docs

`idac docs` prints an agent-oriented index of bundled reference material without needing a live IDA target.
Use `idac docs TOPIC` for focused guidance, such as `guide`, `cli`, `workflows`, `targets`, `troubleshooting`, `class-recovery`, `ida-cpp-type-details`, `ida-set-types`, `ida-advanced-type-annotations`, `templates`, or `workspace`.
Use `idac docs --list` to list every topic and `idac docs --all --out docs.md` to write all bundled docs to a file.

## Output notes

- terminal output still enforces the inline size limit
- large inline results print a truncated prefix first, then error
- `type declare --clang` uses IDA's clang parser for more complex C/C++ declarations
- `type declare --bisect` isolates the first declaration IDA rejects when a multi-declaration import fails; it reports the failing line range, whether that declaration imports on its own, and any by-value members whose types are still opaque. It needs IDA undo support and is rejected by `type check`.
- `type declare --alias OLD=NEW` rewrites identifiers before import; use it to flatten namespace-qualified names
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
