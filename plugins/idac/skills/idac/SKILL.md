---
name: idac
description: Analyze binaries and inspect or edit IDA Pro databases with the local idac CLI. Use for IDA decompilation, xrefs, type or class recovery, and database edits, rather than general RE explanations or source-only work.
---

# idac

Use `idac` against a live IDA GUI, an existing `.i64`, or a binary IDA can open.
Every operation uses ida-nexus. Prefer first-class commands; use `idac py exec`
when they cannot express the required IDA operation.

Follow the user's target, scope, and deliverables. Explicit user instructions take
precedence over this skill's defaults. Inspection requests stay read-only; recovery,
annotations, and workspace creation belong only where the task calls for them.

## Operating defaults

- Work from the binary and database evidence. Consult the web or external source
  trees only when requested or when external correlation is part of the task.
- Keep the selected target on subsequent commands: `-c/--context PATH` for a
  database or binary, or `--instance RECORD_ID` for an exact READY row from
  `targets list --json`. Omit both only when exactly one READY instance exists.
  Put target and timeout options on the wrapper for `batch` and `preview`.
- Run one `idac` command at a time per target. Write function/type lists and
  family reads to `--out` even with filters; a filtered list can exceed the inline
  limit. Use `decompilemany` for several functions and ordered `batch` files for
  related edits and readbacks in one session.
- During type or prototype recovery, use `decompile --f5` or `decompilemany --f5`
  (`--no-cache`) so readback reflects current types.
- For edits, read [mutation workflows](references/workflows.md). Inspect the
  current prototype before setting it, declare support types before dependent
  prototypes, and reanalyze after meaningful type or prototype changes before
  calibrating local selectors from fresh JSON. Preview parser-risky type changes
  or uncertain selectors and inspect the artifact before committing. Confirmed
  symbol renames, comments, and parameter-name edits with `--preserve-cc` can be
  committed directly with readback. Continue authorized edits through verification.
- Run `idac doctor` when the runtime stack is uncertain. For a Nexus failure,
  diagnose the reported cause using [troubleshooting](references/troubleshooting.md).
  Read affected state before retrying a mutation with an uncertain outcome.

## Read what the task needs

Common command paths:

```text
function list FILTER --demangle --json --out functions.json
function prototype show FUNC
function prototype set FUNC --preserve-cc --decl 'RETURN CONVENTION FUNC(ARGS);'
misc rename FUNC NAME
misc reanalyze FUNC
misc reanalyze START --end END
comment show FUNC --scope function
comment set FUNC TEXT --scope function
type show NAME
type check --decl-file types.h
type declare --replace --decl-file types.h
```

For parameter names or a return type, edit the declaration from `function
prototype show` and use `set`, preserving the other types, parameters, and calling
convention. Add `--preserve-cc` to keep IDA's existing calling convention even when
its parser normalizes the declaration to another convention. This does not require
an IDAPython script. Use the known paths directly;
consult targeted `--help` for unfamiliar flags or subcommands. Use `--full-help`
when the command family is unclear. Read only the relevant reference sections.

Reanalysis requires a function name or address. Use `misc reanalyze START --end END`
for a bounded address range.

| Task | Reference |
|------|-----------|
| Command grammar, reads, filters, output formats | [CLI quick reference](references/cli.md) |
| Select a GUI or headless target; understand saves and runtime requirements | [Targets and backends](references/targets-and-backends.md) |
| Prototypes, locals, type edits, annotations, preview, batch, IDAPython | [Mutation workflows](references/workflows.md) |
| Recover C++ layouts, inheritance, or virtual targets | [Class recovery](references/class-recovery.md) |
| Write IDA-compatible C++ class or vtable declarations | [C++ type details](references/ida-cpp-type-details.md) |
| Custom calling conventions or IDA declaration keywords | [IDA type syntax](references/ida-set-types.md) |
| Shifted pointers, scattered arguments, or display annotations | [Advanced type annotations](references/ida-advanced-type-annotations.md) |
| Discovery, import, preview, or stale-readback failures | [Troubleshooting](references/troubleshooting.md) |

## Artifacts and completion

Use the user's existing artifact locations and workspace conventions. When a
recovery workspace is requested or useful for sustained work, `idac workspace init`
provides headers, audit notes, and temporary artifact directories; follow its
installed conventions. Keep existing audit logs append-only. Optional
[templates](references/templates/README.md) cover prototype and local-edit passes.

For analysis, ground findings in function names or addresses and state unresolved
uncertainty. For edits, verify the affected database state and fresh pseudocode
where relevant. Report artifact paths and whether changes were saved: successful
headless mutations are checkpointed automatically; live GUI saves are explicit.
Stop when the requested result is supported by evidence; cosmetic pseudocode
cleanup is useful only when it helps that result.
