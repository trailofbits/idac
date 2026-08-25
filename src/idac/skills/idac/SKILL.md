---
name: idac
description: Use for reverse-engineering work through the local `idac` CLI against a live IDA GUI session, an existing `.i64` database, or a binary that IDA can open. Trigger this skill when the task involves decompilation, disassembly, ctree or microcode inspection, functions, locals, types, xrefs, strings, imports, C++ class or vtable recovery, Nexus target selection, prototype or local/type mutations, reanalysis, or IDAPython execution through IDA.
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
- After type or prototype mutations, run `misc reanalyze`, then reread pseudocode or locals before rename-heavy cleanup. Calibrate local renames from fresh `function locals list --json` output using `--local-id` or `--index`; see `idac docs workflows` for selector calibration.
- Before executing a mutation batch, run `batch <batch.idac> --lint --out <lint.json>` and fix reported issues.
- Context selection: use `-c/--context PATH` for an `.i64` or binary, use
  `--instance RECORD_ID` for one exact READY row from `targets list`, and omit both
  only when exactly one READY Nexus instance exists.
- When working in an idac workspace, keep audit notes append-only and factual. Distinguish proven facts from inferred names, types, and semantics.

When this guide is installed as a skill, the reference files sit alongside it; otherwise use `idac docs TOPIC` for the same material. For CLI syntax, prefer targeted help such as `idac type class --help`; use `idac --full-help` only when the command surface itself is unclear.

## When not to use

- The task is not IDA-backed and the user wants standalone RE tooling.
- The task is source-level debugging or runtime inspection; use a debugger directly.
- A first-class `idac` command already covers the task; do not start with raw IDAPython.
- The task is static analysis, linting, or vulnerability scanning outside IDA-driven reverse-engineering work.

## Choose the path

```
What is the task?
│
├─ Read-only inspection (decompile, list, xrefs, strings, ctree, microcode)
│   └─ Run `idac docs cli`
│
├─ Mutation (rename, retype, prototype, type declare)
│   └─ Run `idac docs workflows`
│
├─ C++ class or vtable recovery
│   └─ Run `idac docs class-recovery` and `idac docs ida-cpp-type-details`
│
├─ Context/target selection or Nexus state trouble
│   └─ Run `idac docs targets` or `idac docs troubleshooting`
│
└─ No first-class command covers the task
    └─ Use `idac py exec` with a small explicit script
```

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

Use `idac docs workflows` (`workflows.md`) for exact syntax.

1. Discovery and read-only audit.
2. Preview each persistent mutation.
3. Lint mutation batches before running them.
4. Commit the mutation.
5. Run `misc reanalyze` after type or prototype changes.
6. Reread pseudocode or locals; calibrate local selectors from fresh JSON.
7. Verify final readback and, when working in a workspace, record the pass in the workspace audit log (`audit/<target>-recovery.md`) if one exists.

Successful headless mutations are checkpointed automatically when the command releases
its Nexus lease. A released worker remains warm for five idle minutes. Live GUI edits
remain unsaved until `database save` is requested explicitly. Headless opens wait for
auto-analysis; live GUI commands do not force it.

## Class recovery outline

Use `idac docs class-recovery` (`class-recovery.md`) for the full workflow and `idac docs ida-cpp-type-details` (`ida-cpp-type-details.md`) before importing C++ class or vtable declarations.

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

| File | `idac docs` topic | When to read |
|------|-------------------|--------------|
| `references/cli.md` | `cli` | Command grammar, common reads, preview, batch, output notes |
| `references/targets-and-backends.md` | `targets` | Nexus context selection, opening binaries, target discovery |
| `references/workflows.md` | `workflows` | Safe mutation loop, batch, selector calibration, post-mutation readback |
| `references/class-recovery.md` | `class-recovery` | C++ class recovery workflow, naming rules, vtable guidance, verification |
| `references/ida-cpp-type-details.md` | `ida-cpp-type-details` | IDA C++ parser expectations, `__vftable`, `*_vtbl`, multiple inheritance |
| `references/ida-set-types.md` | `ida-set-types` | IDA C declaration syntax: calling conventions, usercall locations, attribute and type keywords |
| `references/ida-advanced-type-annotations.md` | `ida-advanced-type-annotations` | Scattered argument locations and other advanced IDA declaration annotations |
| `references/troubleshooting.md` | `troubleshooting` | Nexus selection, runtime, mutation, or stale-result problems |
| `references/templates/README.md` | `templates` | Reusable prototype-pass, rename-pass, checkpoint-note, and locals-jq templates (printed in full) |
