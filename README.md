# idac

![version](https://img.shields.io/badge/version-0.18.0-blue)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![status](https://img.shields.io/badge/status-alpha-orange)

The IDA Pro CLI built for agents and humans. One Unix socket — no JSON-RPC framing, no sidecar daemon, no MCP server. Just `idac decompile "sub_08041337"` from any shell or agent.

> `idac` is in early alpha and actively developed. It is already useful day to day, but the CLI surface may still change between releases.

## Contents

- [Why idac](#why-idac)
- [Demo](#demo)
- [Quick start](#quick-start)
- [Requirements](#requirements)
- [How it works](#how-it-works)
- [Agent sandbox setup](#agent-sandbox-setup)
- [Usage](#usage)
- [Highlights](#highlights)
- [Skill](#skill)
- [Development](#development)
- [Credits](#credits)

## Why idac

- **Not an MCP server** — compose with the shell you already have: pipes, `xargs`, `jq`, and your agent's existing tool-use loop. No server to run, no protocol to babysit.
- **Agent-native by default** — every command can emit structured JSON (`-j`), and a bundled skill teaches Claude Code and Codex to drive `idac` instead of guessing at raw IDAPython.
- **Safe mutations** — every mutation supports `preview`, which applies the change under IDA's undo, captures the before/after, and rolls it back. Dry-run any rename, retype, or prototype change before committing it.
- **Built for batches** — recover an entire class hierarchy, retype a hundred locals, or decompile every `Handler_*` in one invocation against a shared context.
- **Live or headless** — the same commands work against a running IDA GUI session or a saved `.i64`/`.idb`. Switch targets with `-c`; with one GUI open, omit it entirely.

## Demo

Run this against the fixture committed in this repo:

```bash
idac decompilemany "CreateHandler_" --out-dir decomp/ -c "db:fixtures/idb/handler_hierarchy.i64"
```

Every matching function is decompiled into its own `.c` file (named `<symbol>_0x<address>`) alongside a `manifest.json` index:

```
decomp/
├── CreateHandler_Text_0x100000588.c
├── CreateHandler_Stream_0x100000608.c
├── CreateHandler_Pack_0x100000688.c
└── manifest.json
```

The `.c` files hold the real Hex-Rays pseudocode:

```c
Handler *__cdecl CreateHandler_Text()
{
  Handler_Text *v1; // [xsp+8h] [xbp-18h]

  v1 = (Handler_Text *)operator new(0x38u);
  Handler_Text::Handler_Text(v1);
  return v1;
}
```

`manifest.json` records the exact address, symbol, and artifact paths for each function (abridged to one of three entries):

```json
{
  "ok": true,
  "pattern": "CreateHandler_",
  "out_dir": "decomp",
  "functions_total": 3,
  "functions_succeeded": 3,
  "functions_failed": 0,
  "functions": [
    {
      "identifier": "CreateHandler_Text",
      "name": "CreateHandler_Text",
      "address": "0x100000588",
      "ok": true,
      "chars": 175,
      "artifact_path": "decomp/CreateHandler_Text_0x100000588.c",
      "artifact_stem": "CreateHandler_Text_0x100000588",
      "artifacts": { "decompile": "decomp/CreateHandler_Text_0x100000588.c" }
    }
  ]
}
```

The same command works against a live GUI session — drop `-c` and `idac` auto-targets the only open instance.

## Quick start

Clone and install the CLI, then wire up the GUI plugin and agent skill:

```bash
git clone https://github.com/trailofbits/idac.git
cd idac
uv tool install .            # installs the `idac` command on your PATH
idac doctor                  # verify IDA install, license, and bridge
idac misc plugin install     # GUI bridge plugin
idac misc skill install      # Claude Code + Codex skill
```

Talk to a live GUI session:

```bash
idac targets list --json
idac decompile "sub_08041337"
idac decompile "sub_08041337" --f5        # force a fresh Hex-Rays pass
idac decompile "sub_08041337" -c "pid:1234"
```

Work headless against an existing database:

```bash
idac database show -c "db:sample.i64"
idac decompile "ExampleClass::method_1" -c "db:sample.i64"
```

To run from a checkout without installing globally, use `uv run idac --help`.

## Requirements

- **Python 3.10+** and [`uv`](https://docs.astral.sh/uv/).
- **IDA Pro** with the **Hex-Rays decompiler** (required for `decompile`, `ctree`, and class recovery).
- A valid IDA license. Headless work uses `idalib`, which requires `idapro` to be installed and importable.

`idac` discovers your IDA install from the user config automatically. On macOS it also falls back to the standard IDA 9.3 layout at `/Applications/IDA Professional 9.3.app/Contents/MacOS`. Run `idac doctor` to confirm what was detected.

## How it works

`idac` has two execution paths, and the same command surface drives both:

- **`gui`** connects to a running IDA desktop over a Unix-socket bridge plugin. With exactly one GUI open, most commands need no `-c` at all. Use `-c pid:<pid>` or `-c <module>` to pick one of several open sessions.
- **`idalib`** opens a `.i64`/`.idb`/binary in a short-lived headless worker. Passing `-c "db:<path>"` starts or reuses a per-database `idalib` process automatically; those rows show `backend: "idalib"` in `targets list --json`.

Discover everything that's reachable with `idac targets list --json`. Checkpoint headless state with `idac database save -c "db:<path>"`; `idac database close -c "db:<path>"` saves before closing by default, and `--discard` abandons pending changes.

For bridge socket and sandbox diagnostics, run `idac docs troubleshooting`.

## Agent sandbox setup

Scaffold a project-local reversing workspace for sandboxed agents:

```bash
idac workspace init reversing-workspace
```

That creates workspace-local `.claude/` and `.codex/` config, agent guidance files, prompt templates, a `references/` copy of the bundled skill docs, and a git-backed directory layout for RE work. The generated sandbox settings are intentionally broad so sandboxed agents can reach the `idac` Unix socket bridge.

To customize the generated files, see the templates under [src/idac/workspace_template/default](src/idac/workspace_template/default).

## Usage

Use `idac <command> --help` for one subcommand, `idac --full-help` for the complete CLI surface, and `idac docs` for an index of bundled command, workflow, and IDA reference material (`idac docs guide`, `idac docs cli`, `idac docs workflows`, `idac docs class-recovery`, ...).

### Command families

| Family | Commands |
|--------|----------|
| Discovery | `doctor`, `docs`, `targets list`, `database show`, `segment list`, `bookmark list/show`, `comment show` |
| Functions | `function list`, `metadata`, `frame`, `stackvars`, `callees`, `callers`, `prototype`, `locals` |
| Decompilation | `decompile`, `decompilemany`, `disasm`, `disasm --start/--end`, `ctree` |
| Search | `search bytes`, `search strings`, `xrefs`, `imports` |
| Types | `type list`, `show`, `deps`, `check`, `declare`, `type struct list/show/field`, `type enum list/show/member`, `type class vtable` |
| Classes | `type class list`, `show`, `hierarchy`, `fields`, `candidates` |
| Mutations | `misc rename`, `comment set/delete`, `bookmark add/set/delete`, `function prototype set`, `function locals update/rename/retype/apply`, `type struct field set/rename/delete`, `type enum member set/rename/delete` |
| Batch | `batch`, `batch --lint`, `preview` |
| IDAPython | `py exec` |
| Workspace | `workspace init` |
| Maintenance | `misc reanalyze`, `database open/save/close`, `targets cleanup`, `misc plugin`, `misc skill` |

### Output

Most read commands default to `--format text`. Use `--format json` (or `-j`) or `--format jsonl` when parsing, and `-o/--out <path>` for large results. With `--out`, `stdout` stays empty and a short `stderr` summary reports the artifact path and result counts. Matching is case-sensitive by default; `--regex` treats the filter as a regular expression and `-i` makes it case-insensitive. `search bytes` and `search strings` require both `--timeout` and `--segment`.

## Highlights

A few of the commands that make `idac` worth reaching for. See `idac docs cli` and `idac docs workflows` for the full reference.

### Preview a mutation before committing

`preview` is a wrapper that runs the real mutation under IDA undo and rolls it back, returning the before/after so you (or an agent) can verify the change first:

```bash
idac preview -o "/tmp/preview.json" \
  function prototype set "sub_08041337" \
  --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
```

### Recover C++ class hierarchies

Walk vtables, flattened layouts, and inheritance straight from the database:

```bash
idac type class list
idac type class hierarchy "ExampleClass"
idac type class show "ExampleDerived"          # flattened object layout
idac type class vtable "ExampleDerived" --runtime
```

### Decompile a whole family in one pass

Select by name filter or by reading exact identifiers from a file; emit one combined file or one `.c` per function plus a `manifest.json`:

```bash
idac decompilemany "Handler_" --out-dir "decomp/" -c "db:sample.i64"
idac decompilemany "Handler_.*" --regex --out-dir "decomp/" --disasm --ctree

printf '%s\n' main sub_401000 0x401234 > funcs.txt
idac decompilemany --functions-file "funcs.txt" --out-dir "decomp-exact/"
# Or use --out-file for one combined text file without a manifest.
```

Pass `--f5` after type or prototype changes so each function reflects the latest state. With `--out-dir`, the manifest records each function's `name`, exact `address`, and artifact paths.

### Run an ordered mutation pass with batch

Run many subcommands against one shared context, leaving behind a stable ordered log. Batch files use one subcommand per line (drop the leading `idac`) and inherit `-c` and `--timeout` from the `batch` call:

```bash
idac batch "recovery.idac" --out "/tmp/recovery_batch.json"
idac batch "recovery.idac" --lint --out "/tmp/recovery_batch_lint.json"
```

```text
# recovery.idac — run after support types exist locally
type check --decl-file "recovered_classes.h"
type declare --replace --decl-file "recovered_classes.h"
function prototype check "0x100000000" --decl "int __fastcall ExampleClass__parseHeader(ExampleClass *__hidden this, const unsigned __int8 *buf, unsigned int len)"
function prototype set "0x100000000" --decl "int __fastcall ExampleClass__parseHeader(ExampleClass *__hidden this, const unsigned __int8 *buf, unsigned int len)"
misc reanalyze "0x100000000"
function locals rename "0x100000000" 5 --new-name header_size
function locals rename "0x100000000" 6 --new-name record_type
```

Mutating batches require `--out` so the result log is preserved before any change runs. `batch --lint` parses child commands, resolves relative input paths, rejects unsupported batch commands, and warns on risky local selectors before execution. Setup `misc` commands are intentionally rejected from `batch`; `misc reanalyze` is batch-safe and belongs between type/prototype changes and local cleanup.

### Address locals three ways

`function locals update/rename/retype` share one selector model — local name, numeric index, or canonical `local_id`. Prefer `--index` or `--local-id` for longer passes and after reanalysis, since names drift:

```bash
idac function locals rename "sub_08041337" "v12" --new-name "value_maybe"
idac function locals rename "sub_08041337" --index 3 --new-name "value_maybe"
idac function locals retype "sub_08041337" --local-id "stack(16)@0x100000460" --type "unsigned int"
idac function locals apply "sub_08041337" --json-file "locals-plan.json"
```

Read the canonical `local_id` with `idac function locals list --json`. Use `update` when one local needs both a better name and type in one pass, and `apply` when several locals in one function should be applied from one fresh locals snapshot.

### Escape hatch: raw IDAPython

When no first-class command fits, drop to IDAPython against the same target:

```bash
idac py exec --code "result = {'entry': hex(idc.get_inf_attr(idc.INF_START_EA))}"
```

## Skill

A bundled skill in [src/idac/skills/idac](src/idac/skills/idac) teaches Claude Code and Codex to prefer `idac` commands over ad hoc shell or raw IDAPython for RE work.

```bash
idac misc skill install
```

This installs into both `~/.claude/skills/idac` and `~/.codex/skills/idac`; both agents auto-discover skills from their `skills/` directories. Once installed, the skill loads automatically when relevant. For starter prompts (general analysis, class-recovery passes, full reverse-engineering passes), run `idac workspace init <dir>` to scaffold a workspace whose `prompts/` directory contains ready-to-edit templates.

## Development

```bash
uv sync
make test        # run tests
make check       # format + lint + test + audit
```

See [docs/development.md](docs/development.md) for fixture regeneration, live GUI tests, and local tooling details.

## Credits

Inspired by [@banteg's `bn` Binary Ninja CLI tool](https://github.com/banteg/bn).
Written by [Codex](https://openai.com/codex)/gpt-5.3-codex/gpt-5.4/gpt-5.5.
