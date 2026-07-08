---
name: idac
description: Use for reverse-engineering work through the local `idac` CLI against a live IDA GUI session, an existing `.i64` / `.idb` database, or a binary that IDA can open. Trigger this skill when the task involves decompilation, disassembly, ctree or microcode inspection, functions, locals, types, xrefs, strings, imports, C++ class or vtable recovery, target or backend selection, prototype or local/type mutations, reanalysis, or IDAPython execution through IDA.
---

# idac

Use `idac` for IDA-backed reverse engineering through a live IDA GUI, an existing `.i64` / `.idb`, or a binary that IDA can open.
Prefer first-class `idac` commands, then `idac py exec`, then external or ad hoc tooling only when `idac` cannot cover the task.

## Critical defaults

- Work from the binary first. Do not search the web or external source trees unless the user explicitly asks for that or the task is specifically about external correlation.
- Run one `idac` command at a time for each target. Use `batch`, `decompilemany`, and `--out` artifacts for broad work instead of background parallel commands.
- Use `decompile --f5` or `decompilemany --f5` during type or prototype recovery. `--f5` is an alias for `--no-cache`.
- Preview supported persistent mutations first, then commit only after the preview confirms the intended change. Outside batch mode, `preview` requires `-o/--out`.
- Before `function prototype set`, run `function prototype show`. Run `function prototype check` first when the declaration uses a custom calling convention (`__usercall`, `__userpurge`, `__spoils`) or references newly imported types; declare missing support types before dependent prototypes.
- Before importing large headers, validate with `type check --decl-file ...`.
- After type or prototype mutations, run `misc reanalyze`, then reread pseudocode or locals before rename-heavy cleanup. Calibrate local renames from fresh `function locals list --json` output using `--local-id` or `--index`; see `idac docs workflows` for selector calibration.
- Before executing a mutation batch, run `batch <batch.idac> --lint --out <lint.json>` and fix reported issues.
- Context selection: omit `-c` for one live GUI session, use `-c pid:<pid>` for multiple GUI sessions, and use `-c "db:/path"` for headless work.
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
├─ Context/target selection, backend state, or bridge trouble
│   └─ Run `idac docs targets` or `idac docs troubleshooting`
│
└─ No first-class command covers the task
    └─ Use `idac py exec` with a small explicit script
```

## First commands

Use only the commands that match the current target state:

```bash
# always: discover live GUI and headless targets
idac targets list --json
# headless binary import
idac database open "/path/to/binary" --json
# headless database or imported binary context
idac database show -c "db:/path/to/binary" --json
# single live GUI session: omit -c
idac function list "init|open|close" --demangle --regex -i --json --out /tmp/functions.json
# one of several live GUI sessions: select the pid from targets list
idac decompile "sub_08041337" -c "pid:1234" -o /tmp/sub_08041337.c
# single live GUI session: omit -c
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

For headless `db:` work, checkpoint with `database save`; `database close` saves by default, and `database close --discard` abandons pending changes. Live GUI edits remain in the IDA session.

## Class recovery outline

Use `idac docs class-recovery` (`class-recovery.md`) for the full workflow and `idac docs ida-cpp-type-details` (`ida-cpp-type-details.md`) before importing C++ class or vtable declarations.

## Python escape hatch

Use `py exec` only when no first-class command covers the task cleanly:

```bash
idac py exec --code "print(hex(idaapi.get_imagebase())); result = {'entry': hex(idc.get_inf_attr(idc.INF_START_EA))}"
```

Supported modes: `--code`, `--stdin`, `--script`. `--script` preserves IDAPython script semantics such as `__file__`, script-directory imports, and `sys.argv` when IDA exposes that helper. Add `--persist` only when later `py exec` calls in the same session must reuse Python globals.
The execution scope includes the core `ida*` modules that `idac` imports itself, plus `idautils`, `idc`, and `result`.

## Reference index

| File | `idac docs` topic | When to read |
|------|-------------------|--------------|
| `references/cli.md` | `cli` | Command grammar, common reads, preview, batch, output notes |
| `references/targets-and-backends.md` | `targets` | Context selection, GUI vs `idalib`, opening binaries, target discovery |
| `references/workflows.md` | `workflows` | Safe mutation loop, batch, selector calibration, post-mutation readback |
| `references/class-recovery.md` | `class-recovery` | C++ class recovery workflow, naming rules, vtable guidance, verification |
| `references/ida-cpp-type-details.md` | `ida-cpp-type-details` | IDA C++ parser expectations, `__vftable`, `*_vtbl`, multiple inheritance |
| `references/ida-set-types.md` | `ida-set-types` | IDA C declaration syntax: calling conventions, usercall locations, attribute and type keywords |
| `references/ida-advanced-type-annotations.md` | `ida-advanced-type-annotations` | Scattered argument locations and other advanced IDA declaration annotations |
| `references/troubleshooting.md` | `troubleshooting` | Bridge, backend, mutation, stale-result, or sandbox problems |
| `references/templates/README.md` | `templates` | Reusable prototype-pass, rename-pass, checkpoint-note, and locals-jq templates (printed in full) |
