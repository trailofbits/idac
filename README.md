# idac

idac is the IDA Pro CLI for the agents (and humans). One Unix socket, no JSON-RPC framing, no sidecar daemon, no babysitting — just `idac decompile sub_08041337` from any shell, any sandbox, any agent loop.

## Why idac

- **Agent-native by default** — every command emits structured JSON, every mutation supports `preview` for dry-run, and the bundled skill teaches Claude Code and Codex to drive it.
- **Not an MCP server** — composes with shell, pipes, `xargs`, `jq`, and your agent's existing tool-use loop.
- **Built for batches** — recover an entire class hierarchy, retype a hundred locals, or decompile every `Handler_*` in one `idac batch` invocation against a shared context.
- **Live or headless** — the same commands work against any of your seven open IDA databases or saved database. Switch with one flag, no separate tooling.

## Demo

```bash
idac decompilemany "Handler_" --out-dir decomp/ -c "db:sample.i64"
```

Every `Handler_*` function decompiled into its own `.c` file with a `manifest.json`. Works identically against a live GUI session — drop the `-c` flag and idac auto-targets the only open instance.

## Quick start

Install, then wire up the GUI plugin and agent skill:

```bash
uv tool install -e .
idac misc plugin install
idac misc skill install
```

Talk to a live GUI session:

```bash
idac targets list --json
idac decompile "sub_08041337"
idac decompile "sub_08041337" --f5
idac decompile "sub_08041337" -c "pid:1234"
```

Work headless against an existing database:

```bash
idac doctor
idac database show -c "db:sample.i64"
idac decompile "ExampleClass::method_1" -c "db:sample.i64"
idac decompile "sub_08041337" --no-cache -c "db:sample.i64"
```

If running from the repo without a global install:

```bash
uv run idac --help
```

## Requirements

For `idalib`, `idapro` must already be installed. This repo assumes the standard IDA 9.3 macOS layout at `/Applications/IDA Professional 9.3.app/Contents/MacOS`.

## How it works

Most commands can run with no context at all when exactly one live IDA GUI session is open. For explicit selection, use `-c/--context` with either a GUI selector or a database locator such as `db:sample.i64`.

**Drive your live IDA session** — idac connects to a running IDA desktop over a Unix socket bridge. Use `idac targets list --json` to discover instances. If only one is open, most commands can omit `-c` entirely. Use `-c pid:<pid>` or `-c <module>` when multiple GUI sessions are open.

**Spin up headless databases on demand** — passing `-c "db:<database.i64|idb>"` starts or reuses a headless per-database `idalib` process automatically. No daemon to manage, no port to allocate. Use `idac database save -c "db:<database>"` to checkpoint and `idac database close -c "db:<database>"` to tear down.

## Agent sandbox setup

Both backends use Unix sockets. The recommended setup is to scaffold a project-local reversing workspace:

```bash
idac workspace init reversing-workspace
```

That creates workspace-local `.claude/` and `.codex/` config files, agent guidance files, prompt templates, a `reference/` copy of the bundled skill docs, and a git-backed directory layout for reverse-engineering work. The generated sandbox settings are intentionally broad so sandboxed agents can reach the `idac` Unix socket bridge.

Unix socket access is required for all live GUI operations (read-only and mutating). If read-only commands succeed but a mutation fails, troubleshoot the underlying IDA/database error rather than assuming a socket permission split.

If you prefer manual setup or want to customize the generated files, see the workspace templates under [src/idac/workspace_template/default](src/idac/workspace_template/default).

## Usage

Use `idac --help` for a specific subcommand or `idac --full-help` for the complete CLI surface.

### Command families

| Family | Commands |
|--------|----------|
| Discovery | `doctor`, `docs`, `targets list`, `database show`, `segment list`, `bookmark list/show`, `comment show` |
| Functions | `function list`, `metadata`, `frame`, `stackvars`, `callees`, `callers`, `prototype`, `locals` |
| Decompilation | `decompile`, `decompilemany`, `disasm`, `ctree` |
| Search | `search bytes`, `search strings`, `xrefs`, `imports` |
| Types | `type list`, `show`, `declare`, `type struct list/show/field`, `type enum list/show/member`, `type class vtable` |
| Classes | `type class list`, `show`, `hierarchy`, `fields`, `candidates` |
| Mutations | `misc rename`, `comment set/delete`, `bookmark add/set/delete`, `function prototype set`, `function locals update/rename/retype`, `type struct field set/rename/delete`, `type enum member set/rename/delete` |
| Batch | `batch`, `preview` |
| IDAPython | `py exec` |
| Workspace | `workspace init` |
| Maintenance | `misc reanalyze`, `database open/save/close`, `targets cleanup`, `misc plugin`, `misc skill` |

Many models want to fill up their context quickly by running strings so currently `search bytes` and `search strings` require both `--timeout` and `--segment`.

### Preview

Preview uses a wrapper command:

```bash
idac preview -o "/tmp/preview.json" function prototype set "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
```

### Local Selectors

`function locals update`, `function locals rename`, and `function locals retype` use the same selector model. `rename` takes the replacement name via `--new-name`:

```bash
idac function locals update "sub_08041337" "v12" --rename "value_maybe" --decl "unsigned int value_maybe;"
idac function locals rename "sub_08041337" "v12" --new-name "value_maybe"
idac function locals rename "sub_08041337" "3" --new-name "value_maybe"
idac function locals rename "sub_08041337" "stack(16)@0x100000460" --new-name "value_maybe"
idac function locals retype "sub_08041337" "v12" --type "unsigned int"
idac function locals retype "sub_08041337" "v12" --decl "unsigned int v12;"
```

Selector forms:

- local name such as `v12`
- numeric index such as `3`
- canonical local id such as `stack(16)@0x100000460`

Use `function locals list --json` to read the canonical `local_id` string.
Prefer `--index` or `--local-id` for longer mutation passes or after prototype/reanalysis changes:

```bash
idac function locals update "sub_08041337" "value_maybe" --index 3 --decl "unsigned int value_maybe;"
idac function locals update "sub_08041337" --local-id "stack(16)@0x100000460" --rename "value_maybe"
idac function locals rename "sub_08041337" --index 3 --new-name "value_maybe"
idac function locals retype "sub_08041337" --local-id "stack(16)@0x100000460" --decl-file "local_v4.h"
```

Use `--type` when you only need to spell a simple type such as `unsigned int` or `MyStruct *`.
Use `--decl` or `--decl-file` when the retype needs a full declaration, for example arrays, function pointers, or a declaration whose exact local spelling matters.
Prefer `function locals update` when a recovered local needs both a better name and a better type in one pass. Keep `rename` and `retype` for simple one-off edits.

### Output

Most read commands default to `--format text`. Use `--format json` (or the `-j` shortcut) or `--format jsonl` when parsing output, and `-o/--out <path>` for large results. When `--out` is set, `stdout` stays empty and the CLI prints a short `stderr` summary with the artifact path; broad discovery commands also include result counts there. Matching is case-sensitive by default, broad list commands use one positional name filter, `--regex` treats that filter as a regular expression, `function list --demangle` renders demangled display names in text output, and `type list` / `type struct list` / `type enum list` require `--out` when no filter is given.

### Fresh Decompile

If pseudocode looks stale after reanalysis or nearby mutations, rerun decompile with a fresh Hex-Rays pass:

```bash
idac decompile "sub_08041337" --no-cache
idac decompile "sub_08041337" --f5
```

`--f5` is an alias for `--no-cache`, named after the usual Hex-Rays refresh shortcut in the UI.

### Decompile Many

`decompilemany` decompiles a set of functions in one pass against a shared context. Select either by name filter or by reading exact identifiers from a file, and choose between one combined output file (`--out-file`) or one `.c` file per function plus a `manifest.json` (`--out-dir`):

```bash
idac decompilemany "Handler_" --out-dir ".idac/tmp/decomp" -c "db:sample.i64"
idac decompilemany "Handler_.*" --regex --out-dir ".idac/tmp/decomp" -c "db:sample.i64"

printf '%s\n' main sub_401000 0x401234 > funcs.txt
idac decompilemany --functions-file "funcs.txt" --out-file ".idac/tmp/decompile.c" -c "db:sample.i64"
```

Pass `--f5` (alias for `--no-cache`) when running readback after type or prototype changes so each function reflects the latest state.

Function-targeting commands (`decompile`, `disasm`, `ctree`, and the `function` family) accept demangled C++ names when they resolve uniquely, for example `idac decompile "ExampleClass::method_1"`. On non-unique matches, use a mangled name, full signature, or address. Other identifier-taking commands (`name`, `comment`, `bookmark`, `search`, `xref`, vtable lookups) take only addresses or mangled names.

`function metadata` and `function list --json` include a `display_name` field with the demangled symbol name when available. `function list --demangle` changes text output to use that display name while keeping JSON `name` stable.

### Batch

Run many subcommands against one shared context:

```bash
idac batch "recovery.idac" --out "/tmp/recovery_batch.json"
idac batch "rename-pass.idac" -c "db:sample.i64" --out "/tmp/rename-pass.jsonl"
```

Batch files use one shell-like subcommand per line, omit the leading `idac` (a leading `idac` is also accepted), and inherit `-c/--context` and `--timeout` from `batch`. Relative child paths such as `--decl-file`, `--functions-file`, and per-line `--out` resolve from the batch file directory. Blank lines and `#` comments are ignored.

A prototype-cleanup batch file (`prototype-pass.idac`) might look like:

```
# Run after support types already exist locally.
function prototype set "0x100000000" --decl "int __fastcall ExampleClass__parseHeader(ExampleClass *__hidden this, const unsigned __int8 *buf, unsigned int len)"
function prototype set "0x100000100" --decl "void *__fastcall ExampleClass__buildResult(ExampleClass *__hidden this, InputContext *ctx, const ExampleOptions *options)"
function prototype set "0x100000200" --decl "unsigned int __fastcall ExampleClass__getCount(const ExampleClass *__hidden this)"
```

A local-rename pass (`rename-pass.idac`) is just a sequence of `function locals rename` lines:

```
function locals rename "0x100000000" 5 --new-name header_size
function locals rename "0x100000000" 6 --new-name record_type
function locals rename "0x100000100" 4 --new-name result_ptr
function locals rename "0x100000100" 11 --new-name error_code
```

Batch reuses the same handler surface as normal execution, accepts `preview ...` lines, and writes JSON or JSONL based on the output filename. Maintenance and setup `misc` commands are intentionally rejected from `batch`.

## Skill

A bundled skill in [src/idac/skills/idac](src/idac/skills/idac) teaches Claude Code and Codex to prefer `idac` commands over ad hoc shell or raw IDAPython for RE work.

```bash
idac misc skill install
```

This installs into both `~/.claude/skills/idac` and `~/.codex/skills/idac`. Both agents auto-discover skills from their `skills/` directories.

Once installed, the skill is loaded automatically when relevant. For starter task prompts (general analysis, class-recovery passes, full reverse-engineering passes), run `idac workspace init <dir>` to scaffold a workspace whose `prompts/` directory contains ready-to-edit templates. Use `idac docs` for an index of bundled command, workflow, and IDA reference material.


## Development

```bash
uv sync
make test        # run tests
make check       # format + lint + test + audit
```

See [docs/development.md](docs/development.md) for fixture regeneration, live GUI tests, and local tooling details.

## Credits

Inspired by [@banteg's `bn` Binary Ninja CLI tool](https://github.com/banteg/bn).
Written by [Codex](https://openai.com/codex)/gpt-5.3-codex and gpt-5.4.
