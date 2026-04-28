# idac

An agent-friendly CLI for IDA Pro. Not an MCP server — a proper CLI that composes with shell pipelines, runs in agent sandboxes without a sidecar process, and doesn't need you to debug JSON-RPC framing when things go wrong.

Most commands can run with no context at all when exactly one live IDA GUI session is open. For explicit selection, use `-c/--context` with either a GUI selector or an explicit database locator such as `db:sample.i64`.

## Quick start

Install, then wire up the GUI plugin and agent skill:

```bash
uv tool install -e .
idac misc plugin install
idac misc skill install
```

Talk to a live GUI session:

```bash
idac doctor
idac targets list --json
idac decompile "sub_08041337"
idac decompile "sub_08041337" --f5
idac decompile "sub_08041337" -c "pid:1234"
```

Work headless against an existing database:

```bash
idac doctor
idac database show -c "db:sample.i64"
idac decompile "sub_08041337" -c "db:sample.i64"
idac decompile "ExampleClass::method_1" -c "db:sample.i64"
idac decompile "sub_08041337" --no-cache -c "db:sample.i64"
```

For `idalib`, `idapro` must already be installed. This repo assumes the standard IDA 9.3 macOS layout at `/Applications/IDA Professional 9.3.app/Contents/MacOS`.

If running from the repo without a global install:

```bash
uv run idac --help
```

## Backends

**Live GUI** — connects to a running IDA desktop session over a Unix socket bridge. Use `idac targets list --json` to discover instances. If only one is open, most commands can omit `-c` entirely. Use `-c pid:<pid>` or `-c <module>` when multiple GUI sessions are open.

**Database context** — passing `-c "db:<database.i64>"` or `-c "db:<database.idb>"` starts or reuses a headless per-database `idalib` process automatically. Use `idac database save -c "db:<database>"` to checkpoint and `idac database close -c "db:<database>"` to tear down.

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
| Discovery | `doctor`, `targets list`, `database show`, `segment list` |
| Functions | `function list`, `metadata`, `frame`, `stackvars`, `callees`, `prototype`, `locals` |
| Decompilation | `decompile`, `disasm`, `ctree` |
| Search | `search bytes`, `search strings`, `xrefs`, `imports` |
| Types | `type list`, `show`, `declare`, `struct`, `enum`, `type class vtable` |
| Classes | `type class list`, `show`, `hierarchy`, `fields`, `candidates` |
| Mutations | `misc rename`, `comment set`, `bookmark add/set`, `function prototype set`, `function locals update/rename/retype` |
| Batch | `batch`, `preview` |
| IDAPython | `py exec` |
| Maintenance | `misc reanalyze`, `database save`, `database close`, `targets cleanup`, `misc plugin`, `misc skill` |

`search bytes` and `search strings` require both `--timeout` and `--segment`. On dyld shared caches, `search strings` only allows `--scan` with explicit `--start` / `--end` bounds up to 16 MiB.

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

Most read commands default to `text`. Use `--json` when parsing output. Use `--out <path>` for large results. When `--out` is set, `stdout` stays empty and the CLI prints a short `stderr` summary with the artifact path; broad discovery commands also include result counts there. Matching is case-sensitive by default, broad list commands use one positional name filter, `--regex` treats that filter as a regular expression, `function list --demangle` renders demangled display names in text output, and `type list` / `type struct list` / `type enum list` require `--out` when no filter is given.

### Fresh Decompile

If pseudocode looks stale after reanalysis or nearby mutations, rerun decompile with a fresh Hex-Rays pass:

```bash
idac decompile "sub_08041337" --no-cache
idac decompile "sub_08041337" --f5
```

`--f5` is an alias for `--no-cache`, named after the usual Hex-Rays refresh shortcut in the UI.

Identifier-taking commands such as `decompile` also accept demangled C++ names when they resolve uniquely, for example `idac decompile "ExampleClass::method_1"`. If multiple overloads share the same short demangled name, use a mangled name, full signature, or address instead.

`function metadata` and `function list --json` include a `display_name` field with the demangled symbol name when available. `function list --demangle` changes text output to use that display name while keeping JSON `name` stable.

### Batch

Run many subcommands against one shared context:

```bash
idac batch "recovery.idac" --out "/tmp/recovery_batch.json"
```

Batch files use one shell-like subcommand per line, omit the leading `idac` (a leading `idac` is also accepted), and inherit `-c/--context` and `--timeout` from `batch`. Relative child paths such as `--decl-file`, `--functions-file`, and per-line `--out` resolve from the batch file directory.

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
Written by [Codex](https://openai.com/codex).
