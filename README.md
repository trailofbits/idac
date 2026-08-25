# idac

[![version](https://img.shields.io/pypi/v/idac?color=blue)](https://pypi.org/project/idac/)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![status](https://img.shields.io/badge/status-alpha-orange)

The IDA Pro CLI built for agents and humans, powered by
[`ida-nexus`](https://github.com/HexRaysSA/ida-nexus). Run
`idac decompile "sub_08041337"` from any shell or agent against either a live IDA
session or a headless database.

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
- **Safe mutations** — supported mutations offer `preview`, which applies the change,
  captures the before/after, and restores it with IDA undo or an operation-specific rollback. Dry-run retypes,
  prototype changes, and other preview-capable edits before committing them.
- **Built for batches** — recover an entire class hierarchy, retype a hundred locals, or decompile every `Handler_*` in one invocation against a shared context.
- **Live or headless** — the same commands work against a running IDA GUI session,
  a saved `.i64`, or a binary that IDA can open. Select a path with `-c`, an exact
  running instance with `--instance`, or omit both when exactly one instance is ready.

## Demo

Run this against the fixture committed in this repo:

```bash
idac decompilemany "CreateHandler_" --out-dir decomp/ \
  -c fixtures/idb/handler_hierarchy.i64
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

The same command works against a live GUI session — drop `-c` when it is the only
READY Nexus instance.

## Quick start

Install the CLI from [PyPI](https://pypi.org/project/idac/), then install the pinned
GUI integration and agent skill:

```bash
uv tool install idac         # installs the `idac` command on your PATH
idac setup gui               # ida-nexus 0.7.0 via ida-hcli
idac setup skill             # Claude Code + Codex skill
idac doctor                  # verify the exact local and in-IDA stack
```

`ida-hcli==0.19.2` is an exact `idac` runtime dependency. Setup and diagnostics
run it through `idac`'s Python environment; they do not require `uvx` or a
separately installed HCLI executable.

To install the latest development version straight from git instead:

```bash
uv tool install git+https://github.com/trailofbits/idac.git
```

Talk to a live GUI session:

```bash
idac targets list --json
idac decompile "sub_08041337"
idac decompile "sub_08041337" --f5        # force a fresh Hex-Rays pass
idac decompile "sub_08041337" --instance "<record-id>"
```

Work headless against an existing database:

```bash
idac database show -c sample.i64
idac decompile "ExampleClass::method_1" -c sample.i64
```

To run from a checkout without installing globally, use `uv run idac --help`.

## Requirements

- **Python 3.11+** and [`uv`](https://docs.astral.sh/uv/).
- **IDA Pro 9.4+** with the **Hex-Rays decompiler** for `decompile`, `ctree`,
  and class recovery.
- A valid IDA license and an IDA Python environment on Python 3.11 or newer.
- The exact supported runtime: `ida-nexus==0.7.0` (protocol 6) and
  `ida-domain==0.5.1`.
  They are pinned by the `idac` package; install the matching GUI component with
  `idac setup gui`.

Run `idac doctor` to validate the CLI packages, installed GUI component, Nexus
discovery, and the runtime versions inside every ready IDA instance. Version or
protocol mismatches are hard errors; `idac` does not fall back to another backend.

## How it works

Every IDA operation goes through the public ida-nexus Python API. `-c/--context PATH`
opens or attaches to an `.i64` or input binary. Nexus prefers a matching live GUI
database, reuses a matching managed worker, or starts a headless worker. Use
`--instance RECORD_ID` to attach to one exact record from `idac targets list`.

With neither selector, `idac` proceeds only when discovery finds exactly one READY
instance. Ambiguous, missing, blocked, disconnected, timed-out, or version-mismatched
targets fail explicitly. An operation is never retried on a different instance.

Headless opens enable auto-analysis and wait for it to finish. A released worker stays
warm for five idle minutes, and successful headless mutations are checkpointed before
another remote request or lease release. A failed preview or locally interrupted
request retires that exact headless worker with `save=False`; the operation is never
retried. Live GUI commands do not force analysis or save; checkpoint GUI changes
explicitly with `idac database save`.

For selection and Nexus diagnostics, run `idac docs targets` and
`idac docs troubleshooting`.

## Agent sandbox setup

Scaffold a project-local reversing workspace for sandboxed agents:

```bash
idac workspace init reversing-workspace
```

That creates workspace-local `.claude/` and `.codex/` config, agent guidance files,
prompt templates, a `references/` copy of the bundled skill docs, and a git-backed
directory layout for RE work. Nexus discovery and execution are local to the host;
the generated workspace allows the local access needed by `idac`.

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
| Maintenance | `misc reanalyze`, `database save`, `setup gui`, `setup skill` |

### Output

Most read commands default to `--format text`. Use `--format json` (or `-j`) or `--format jsonl` when parsing, and `-o/--out <path>` for large results. With `--out`, `stdout` stays empty and a short `stderr` summary reports the artifact path and result counts. Matching is case-sensitive by default; `--regex` treats the filter as a regular expression and `-i` makes it case-insensitive. `search bytes` and `search strings` require both `--timeout` and `--segment`.

## Highlights

A few of the commands that make `idac` worth reaching for. See `idac docs cli` and `idac docs workflows` for the full reference.

### Preview a mutation before committing

`preview` is a wrapper that runs the real mutation and restores it with IDA undo or an operation-specific rollback, returning the before/after so you (or an agent) can verify the change first:

```bash
idac preview -o "/tmp/preview.json" \
  function prototype set "sub_08041337" \
  --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
```

The wrapper owns the preview artifact. A wrapped command cannot set `--out`,
`--out-file`, or `--out-dir`; put `--out` on `preview` itself. Output paths are
also rejected when they alias the selected binary/database or any command input.

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
idac decompilemany "Handler_" --out-dir "decomp/" -c sample.i64
idac decompilemany "Handler_.*" --regex --out-dir "decomp/" --disasm --ctree

printf '%s\n' main sub_401000 0x401234 > funcs.txt
idac decompilemany --functions-file "funcs.txt" --out-dir "decomp-exact/"
# Or use --out-file for one combined text file without a manifest.
```

Pass `--f5` after type or prototype changes so each function reflects the latest state. With `--out-dir`, the manifest records each function's `name`, exact `address`, and artifact paths.

### Run an ordered mutation pass with batch

Run many subcommands against one shared context, leaving behind a stable ordered log. Batch files use one subcommand per line (drop the leading `idac`) and inherit `-c` and `--timeout` from the `batch` call. Child commands cannot set their own target or timeout because the wrapper owns one Nexus session for the entire run:

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

Mutating batches require `--out` so the result log is preserved before any change runs. `batch --lint` parses child commands, resolves relative input paths, rejects unsupported batch commands, and warns on risky local selectors before execution. Setup commands are intentionally rejected from `batch`; `misc reanalyze` is batch-safe and belongs between type/prototype changes and local cleanup.
Before dispatching the first command, `batch` writes a `pending` journal and checkpoints it after every line. It closes the shared Nexus session before replacing that journal with a terminal `ok`, `failed`, or `interrupted` record; Ctrl-C returns 130 without discarding the lifecycle record. Mutating child commands cannot set their own `--out`—the wrapper artifact is the mutation log—while read-only children may still write separate artifacts.

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
idac setup skill
```

This installs into both `~/.claude/skills/idac` and `~/.codex/skills/idac`; both agents auto-discover skills from their `skills/` directories. Once installed, the skill loads automatically when relevant. For a ready-to-fill task prompt covering anything from a light analysis pass to class-family recovery, run `idac workspace init <dir>` to scaffold a workspace containing `prompts/recovery-pass.md`.

Claude Code users can alternatively install the skill as a namespaced plugin from
this repository:

```text
/plugin marketplace add trailofbits/idac
/plugin install idac@idac
```

## Development

```bash
git clone https://github.com/trailofbits/idac.git
cd idac
uv sync          # project venv with an editable install; run via `uv run idac ...`
make test        # run tests
make check       # format + lint + test + audit
```

To put an `idac` on your PATH that tracks your checkout, install it as editable:

```bash
uv tool install -e .
```

See [docs/development.md](docs/development.md) for fixture regeneration, Nexus
integration tests, and local tooling details.

## Credits

Inspired by [@banteg's `bn` Binary Ninja CLI tool](https://github.com/banteg/bn).
Backend integration is provided by
[`ida-nexus`](https://github.com/HexRaysSA/ida-nexus).
Written by [Codex](https://openai.com/codex)/gpt-5.3-codex/gpt-5.4/gpt-5.5.
