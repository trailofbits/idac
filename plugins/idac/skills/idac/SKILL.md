---
name: idac
description: Use for reverse-engineering work through the local `idac` CLI against a live IDA GUI session, an existing `.i64` database, or a binary that IDA can open. Trigger this skill when the task involves decompilation, disassembly, ctree or microcode inspection, functions, locals, types, xrefs, strings, imports, C++ class or vtable recovery, Nexus target selection, prototype or local/type mutations, struct fields, enum members, comments, bookmarks, reanalysis, or IDAPython execution through IDA.
---

# idac

Use `idac` for IDA-backed reverse engineering through a live IDA GUI, an existing
`.i64`, or a binary that IDA can open. Every operation uses ida-nexus; there is no
alternate execution path.
Prefer first-class `idac` commands, then `idac py exec`, then external or ad hoc tooling only when `idac` cannot cover the task.

## Critical defaults

- Work from the binary first. Do not search the web or external source trees unless the user explicitly asks for that or the task is specifically about external correlation.
- Require Python 3.11+, IDA 9.4+, ida-nexus 0.7.0/protocol 6, and ida-domain
  0.5.1. Run `idac doctor` when the stack is uncertain; do not substitute another
  execution path after a Nexus failure.
- Run one `idac` command at a time for each target. Use `batch`, `decompilemany`, and `--out` artifacts for broad work instead of background parallel commands.
- Use `decompile --f5` or `decompilemany --f5` during type or prototype recovery. `--f5` is an alias for `--no-cache`.
- Preview supported persistent mutations first, then commit only after the preview confirms the intended change. Outside batch mode, `preview` requires `-o/--out`.
- Before `function prototype set`, run `function prototype show`. Run `function prototype check` first when the declaration uses a custom calling convention (`__usercall`, `__userpurge`, `__spoils`) or references newly imported types; declare missing support types before dependent prototypes.
- Before importing large headers, validate with `type check --decl-file ...`.
- After type or prototype mutations, run `misc reanalyze`, then reread pseudocode or locals before rename-heavy cleanup. Calibrate local renames from fresh `function locals list --json` output using `--local-id` or `--index`; see [the mutation workflows](references/workflows.md#selector-calibration) for selector calibration.
- Before executing a mutation batch, run `batch <batch.idac> --lint --out <lint.json>` and fix reported issues.
- Run dependency-ordered mutation batches with `--fail-fast`, especially when a check or preview guards a later commit and for local rename/retype passes.
- Context selection: use `-c/--context PATH` for an `.i64` or binary, use
  `--instance RECORD_ID` for one exact READY row from `targets list`, and omit both
  only when exactly one READY Nexus instance exists.
- When a `type declare` import fails and the error does not name the culprit, rerun it once with `--bisect` before hand-editing the header.
- When working in an idac workspace, keep audit notes append-only and factual. Distinguish proven facts from inferred names, types, and semantics. Create one with `idac workspace init` for multi-pass work and follow the conventions installed in the workspace.

Read the bundled reference files linked below when their guidance applies. For CLI syntax, prefer targeted help such as `idac type class --help`; use `idac --full-help` only when the command surface itself is unclear.

## When not to use

- The task is not IDA-backed and the user wants standalone RE tooling.
- The task is source-level debugging or runtime inspection; use a debugger directly.
- The task is static analysis, linting, or vulnerability scanning outside IDA-driven reverse-engineering work.

## Choose the path

- For read-only inspection such as decompilation, listings, xrefs, strings, ctree, or microcode, read the [CLI quick reference](references/cli.md).
- For mutations such as renames, retypes, prototypes, type edits, comments, or bookmarks, read the [mutation workflows](references/workflows.md).
- For C++ class or vtable recovery, read the [class recovery workflow](references/class-recovery.md) and [IDA C++ type details](references/ida-cpp-type-details.md).
- For multi-pass recovery that needs durable notes and headers, run `idac workspace init` and follow the conventions installed in the workspace.
- For context or target selection, read [targets and backends](references/targets-and-backends.md); for Nexus state trouble, read [troubleshooting](references/troubleshooting.md).
- When no first-class command covers the task, use `idac py exec` with a small explicit script.

## First commands

Use only the commands that match the current target state:

```bash
# discover live GUI and headless Nexus instances
idac targets list --json
# open or reuse a headless binary context; analysis completes before the read
idac database show -c "/path/to/binary" --json
# exactly one READY Nexus instance: omit the selector
idac function list "init|open|close" --demangle --regex -i --json --out /tmp/functions.json
# one of several live instances: select the record ID from targets list
idac decompile "sub_08041337" --instance "<record-id>" -o /tmp/sub_08041337.c
# exactly one READY Nexus instance: omit the selector
idac decompile "sub_08041337" -o /tmp/sub_08041337.c
# current context
idac xrefs "sub_08041337" --json
idac disasm --start "0x100000460" --end "0x1000004a0"
```

## Mutation outline

Read [the mutation workflows](references/workflows.md) for exact syntax.

1. Discovery and read-only audit.
2. Preview each preview-capable persistent mutation.
3. Lint mutation batches before running them.
4. For preview-capable commands, commit only the mutation confirmed by an inspected preview artifact.
5. Run `misc reanalyze` after type or prototype changes.
6. Reread pseudocode or locals; calibrate local selectors from fresh JSON.
7. Verify final readback and, when working in a workspace, record the pass in the workspace audit log (`audit/<target>-recovery.md`) if one exists.

Successful headless mutations are checkpointed automatically when the command releases
its Nexus lease. A released worker remains warm for five idle minutes. Live GUI edits
remain unsaved until `database save` is requested explicitly. Headless opens wait for
auto-analysis; live GUI commands do not force it.

## Class recovery outline

Read [the class recovery workflow](references/class-recovery.md) for the full process and [IDA C++ type details](references/ida-cpp-type-details.md) before importing C++ class or vtable declarations.

## Python escape hatch

Use `py exec` only when no first-class command covers the task cleanly:

```bash
idac py exec --code "print(hex(idaapi.get_imagebase())); result = {'entry': hex(idc.get_inf_attr(idc.INF_START_EA))}"
```

Supported modes are `--code`, `--stdin`, and `--script`. Each execution uses a fresh
namespace. `--script` sets `__file__` to the local script path; code and result values
cross the Nexus boundary, not the local `idac` package.
The execution scope includes the core `ida*` modules that `idac` imports itself, plus `idautils`, `idc`, and `result`.

## Reference index

| File | When to read |
|------|--------------|
| [CLI quick reference](references/cli.md) | Command grammar, common reads, preview, batch, output notes |
| [Targets and backends](references/targets-and-backends.md) | Nexus context selection, opening binaries, target discovery |
| [Mutation workflows](references/workflows.md) | Safe mutation loop, batch, selector calibration, post-mutation readback |
| [Class recovery](references/class-recovery.md) | C++ class recovery workflow, naming rules, vtable guidance, verification |
| [IDA C++ type details](references/ida-cpp-type-details.md) | IDA C++ parser expectations, `__vftable`, `*_vtbl`, multiple inheritance |
| [IDA type syntax](references/ida-set-types.md) | IDA C declaration syntax: calling conventions, usercall locations, attribute and type keywords |
| [Advanced type annotations](references/ida-advanced-type-annotations.md) | Scattered argument locations and other advanced IDA declaration annotations |
| [Troubleshooting](references/troubleshooting.md) | Nexus selection, runtime, mutation, or stale-result problems |
| [Reusable templates](references/templates/README.md) | Prototype and rename preview/commit passes, locals-plan, checkpoint-note, and locals-jq templates |
