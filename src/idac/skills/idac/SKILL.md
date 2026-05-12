---
name: idac
description: Use for reverse-engineering work through the local `idac` CLI against a live IDA GUI session, an existing `.i64` / `.idb` database, or a binary that IDA can open. Trigger this skill when the task involves decompilation, disassembly, ctree or microcode inspection, functions, locals, types, xrefs, strings, imports, C++ class or vtable recovery, target or backend selection, prototype or local/type mutations, reanalysis, or IDAPython execution through IDA.
---

# idac

Prefer built-in `idac` commands over `idac py exec`, and prefer both over ad hoc shell guesses.
Use `py exec` as the escape hatch for one-off analysis, not the default path for recurring class-recovery tasks.

## Critical defaults

- Work from the binary first. Do not search the web or external source trees unless the user explicitly asks for that or the task is specifically about external correlation.
- During type or prototype recovery, always use `decompile --f5` or `decompilemany --f5`. `--f5` is an alias for `--no-cache`.
- Before `function prototype set`, run `function prototype show` so the current signature is part of the audit trail and the intended delta is explicit.
- After type or prototype mutations, run `misc reanalyze` before rename-heavy cleanup, then reread pseudocode or locals instead of assuming propagation.
- Clean up shared helper prototypes before broad local-rename passes. When a helper signature is still generic, fix that first, reanalyze, and then decide whether local renames are still necessary.
- Before batch local renames, run `function locals list --json` and prefer `--local-id` or `--index` once prototypes or reanalysis may have shifted the local set.
- Stop a rename batch on the first miss. Reread locals, recalibrate selectors, and only then continue.
- Declare support types before dependent prototypes.
- Prefer minimal `struct` declarations first, then grow them from observed offsets and access patterns. Use blob padding for unknown regions instead of guessed scalar fields.
- If observed field offsets prove a compiler-packed layout, declare the struct or union with `__attribute__((packed))`; do not use packed as a shortcut for unknown gaps.

For bundled agent guidance, workflows, and IDA-specific reference material, run `idac docs`.
Use `idac docs TOPIC` for focused readback, for example `idac docs cli`, `idac docs workflows`, `idac docs class-recovery`, or `idac docs ida-cpp-type-details`.
For CLI help, prefer targeted help for the commands most likely needed, for example `idac type class --help` or `idac type declare --help`.
Use `idac --full-help` only when the command surface itself is unclear and the full help tree is needed.

## When to use

- Inspecting, mutating, or navigating an IDA Pro database through `idac`
- Decompiling, disassembling, or reading function, type, string, import, or xref data
- Recovering C++ classes, vtables, RTTI-adjacent type information, or struct layouts
- Setting prototypes, renaming locals, declaring types, importing recovered headers, or reanalyzing affected code
- Running IDAPython against a live GUI target or headless `idalib` database
- Choosing a context, selecting a target, or troubleshooting bridge/backend state

## When not to use

- General binary analysis without an IDA database or active IDA session — use standalone RE tools
- Source-level debugging or runtime inspection — use a debugger directly
- Ad hoc Python scripting when a first-class `idac` command already exists
- Static analysis, linting, or vulnerability scanning outside IDA-driven reverse-engineering work

## Choosing the right path

```
What is the task?
│
├─ Read-only inspection (decompile, list, xrefs, strings)
│   └─ Use commands from "Preferred read commands" below
│
├─ Mutation (rename, retype, prototype, type declare)
│   └─ Follow "Mutation workflow" below
│   └─ For batch or selector details → references/workflows.md
│
├─ C++ class or vtable recovery
│   └─ Read references/class-recovery.md and references/ida-cpp-type-details.md
│
├─ Backend, target, or bridge trouble
│   └─ Read references/troubleshooting.md
│
└─ No first-class command covers the task
    └─ Use "Python escape hatch" below
```

## Context workflow

1. Choose the context:

- Omit `-c/--context` when exactly one live IDA GUI session is open.
- You can place `-c/--context` and `--timeout` either before the subcommand or on the command itself. If both are present, the command-local value wins. Omit `--timeout` to wait indefinitely.
- Use `-c pid:<pid>` or `-c <module>` to select one live GUI session explicitly.
- Use `-c "db:/path/to/file.i64"` or `-c "db:/path/to/file.idb"` for headless access to an existing database file.
- For a new binary, first run `idac database open /path/to/binary --json`; then use `-c "db:/path/to/binary"` for read commands. For massive binaries or first-time autoanalysis, prefer the indefinite default unless the user asked for a deadline. Do not wrap this import in a shell-level timeout or a tool-call timeout; let the command keep running and poll the session if your tool supports incremental output.
- After opening a binary or database headlessly, `idac targets list --json` should show a row with `backend: "idalib"`. Use the `db:/path` context for commands; do not treat a missing GUI row as a missing headless target.

2. Choose the target:

- If exactly one GUI instance is open, many commands can omit `-c`.
- If multiple GUI instances are open, pass `-c pid:<pid>` from `idac targets list`.
- If backend state is unclear or target discovery fails, read [references/targets-and-backends.md](references/targets-and-backends.md) first, then [references/troubleshooting.md](references/troubleshooting.md).

## Preferred read commands

```bash
idac function list --json
idac function list --demangle
idac function list "init|open|close" --demangle --regex -i
idac segment list
idac decompile "sub_08041337"
idac decompile "ExampleClass::method_1"
idac decompile "sub_08041337" --f5
idac ctree "sub_08041337"
idac xrefs "sub_08041337"
idac function locals list "sub_08041337"
```

Command spellings:

```bash
idac function metadata "sub_08041337"
idac search strings "token" --segment "__cstring" --timeout 30
idac type list "example"
idac type class candidates "ExampleClass" --json --out "/tmp/class_candidates.json"
idac function prototype show "sub_08041337"
idac misc reanalyze "sub_08041337"
idac database open "/path/to/binary" --json
idac targets list --json
idac misc skill install
```

Run `idac docs cli` for the current command catalog including struct/enum ops, rename selectors, batch, comments, and jq examples.
Run `idac docs targets` when backend or target selection is the main question.
Run `idac docs class-recovery` when the task is C++ class recovery or vtable cleanup.
Run `idac docs ida-cpp-type-details` before writing or importing C++ class declarations, vtable types, or multiple-inheritance layouts that must match IDA's parser expectations.
Run `idac docs templates` when you need a reusable starting point for a prototype batch, local-rename batch, checkpoint note, or locals-JSON `jq` filter.

For strings, always pass both `--timeout` and `--segment`; unlike `database open`, string/byte searches require a finite timeout. Default to a two-step flow: run `search strings --scan --segment ...` on the relevant segment first, then use `search strings --segment ...` to read back defined-string results after the interesting region or token is known.
For dyld shared caches, do not use defined-string listing. Use `search strings --scan --segment ... --start ... --end ... --timeout 30` with a range no larger than 16 MiB.
In binary-only analysis mode, bias toward strings, RTTI, vtables, demangled symbols, local types, and call behavior rather than any external lookup.
For freshly imported binaries, symbol names can be thinner than in a prepared `.i64`; if `main` or an expected name is missing, use `database show --json` for `start_ea` / `entry_ea` and `function list --json` for candidate function addresses.
For broad symbol discovery, prefer IDA-side filtering with `function list "name1|name2" --regex -i` over piping an unfiltered function list through shell tools. Add `--demangle` when the filter should match demangled display names. Add `--out <path>` when the filtered result may still be large.
If decompile output looks stale after nearby mutations or reanalysis, rerun `decompile` with `--f5` or `--no-cache` to force a fresh Hex-Rays pass. `--f5` is an alias for `--no-cache`.
Function-taking commands can also resolve a unique demangled C++ function name directly. If a short demangled name is overloaded, switch to a mangled name, fuller signature, or address.
`function metadata` and JSON `function list` rows include `display_name` when a demangled symbol name is available. JSON `function list` rows also include `section`; text output shows the section column by default. Use `function list --demangle` when filtering and text output should use the display name.

## Mutation workflow

Working rules for live GUI and `idalib` work:

- Preview performs a real mutation under IDA undo. Preview applies the change, captures the result, and undoes it before returning.
  - Preview is always `preview <command...>` and writes JSON or JSONL.
- For `idalib`, the first `-c <database>` command starts or reuses one per-database idalib process. Commands that target the same `-c <database>` reuse that open database state.
- Use `database save` explicitly when you need an on-disk checkpoint.
- Use `database close` when you need a clean handoff point or want to discard pending in-memory changes with `--discard`.

Use strict phases for multi-step recovery passes:

1. discovery
2. read-only audit
3. mutations
4. explicit reanalyze
5. local renames or retypes
6. final readback

Prefer preview first when it is supported. Preview mode uses IDA undo: it applies the change, captures the result, and undoes it before returning.
Use `preview -o /tmp/preview.json function prototype set ...`; command-specific preview readbacks such as before/after decompile are still attached when supported.
For larger prototype, retype, or rename passes, prefer `batch` so the mutation order is explicit and the run leaves behind one stable ordered log.
For `function locals retype`, use `--type` for simple type spellings such as `unsigned int` or `ExampleStruct *`. Use `--decl` or `--decl-file` when the change needs a full declaration, such as arrays or function pointers.
Use `--decl` for short one-off edits. Prefer `--decl-file` when the declaration is long or when you are writing batch scripts.
For JSON parsing, stable artifacts, and broad-read defaults, read [references/cli.md](references/cli.md).

When a class-recovery pass changed local vtable or class types, include the underlying virtual function targets in the mutation plan, not just the local type import.
If `function prototype set` fails and the declaration references a type that is not in local types yet, expect an explicit unknown-type error and create the missing placeholder type before retrying.
Before `function prototype set`, use `function prototype show` to record the current signature and catch cases where the existing type is already usable or only needs a small adjustment.

Read [references/workflows.md](references/workflows.md) for the full safe mutation loop, batch syntax, selector calibration, and post-mutation readback procedures.

## Class recovery

Start with `type list` before trusting `type class list`; opaque structs can exist before they qualify as classes.
Use `type list [TYPE_FILTER]`, optionally with `--regex` or `-i`.
Use `type class show` for flattened object layout, `type class fields --derived-only` for subclass-owned state, and local vtable inspection after the local vtable type has been imported with `type class vtable`.
If `type class show` says the type exists but is not class-materialized, use `type show`, then `type class candidates`, then a recovered header import with `type declare --replace --decl-file`.
If symbols and RTTI already identify the family clearly, skip exploratory RTTI scripting and go straight to constructors, vtables, and representative family decompiles.

Read [references/class-recovery.md](references/class-recovery.md) for the full class recovery workflow, naming rules, vtable guidance, and verification checklist.
Read [references/ida-cpp-type-details.md](references/ida-cpp-type-details.md) when you need IDA-specific details for `__cppobj`, `__vftable`, `ClassName_vtbl`, or secondary-base vtable naming such as `ClassName_0008_vtbl`.
During type recovery, prefer `decompile --f5` and `decompilemany --f5` so each readback reflects the latest imported types and prototype changes. For ordinary exploration and routine readback, `--f5` is usually unnecessary.

## Reanalysis and structural inspection

Use `reanalyze` after meaningful type, prototype, or structural changes. It lives under `misc`:

```bash
idac misc reanalyze "sub_08041337"
idac misc reanalyze "0x100000460" --end "0x100000468"
```

After major type or prototype mutations, usually run an explicit `reanalyze` checkpoint before rename-heavy follow-up. Then reread pseudocode or locals instead of assuming propagation.
After `function prototype set`, inspect inbound references for the updated callee and rerun `decompile` on the most relevant callers, not just the callee itself. Use `xrefs`.
If caller pseudocode still shows stale argument types or bad `this` propagation, reanalyze those caller functions and then decompile them again.
If large-stack AArch64 functions still show suspicious prologue value flow after that, treat it as a Hex-Rays presentation limit rather than proof that the recovered structure is wrong.
Stop once the safety-relevant structure and call behavior are readable. Do not keep forcing cosmetic cleanup when the remaining problems are clearly decompiler presentation artifacts.

Prefer `ctree` over `decompile` when you care about the exact Hex-Rays tree shape rather than polished pseudocode.

## Python escape hatch

Use `py exec` only when no first-class command covers the task cleanly:

```bash
idac py exec --code "print(hex(idaapi.get_imagebase())); result = {'entry': hex(idc.get_inf_attr(idc.INF_START_EA))}"
```

Supported modes: `--code`, `--stdin`, `--script`.
The execution scope includes the core `ida*` modules that `idac` imports itself, plus `idautils`, `idc`, and `result`.

## Reference index

| File | When to read |
|------|-------------|
| [references/cli.md](references/cli.md) | Current command cheatsheet and jq examples |
| [references/targets-and-backends.md](references/targets-and-backends.md) | Backend or target selection questions |
| [references/workflows.md](references/workflows.md) | Safe mutation loop, batch, selector calibration, post-mutation readback |
| [references/class-recovery.md](references/class-recovery.md) | C++ class recovery workflow, naming rules, vtable guidance, verification checklist |
| [references/ida-cpp-type-details.md](references/ida-cpp-type-details.md) | IDA parser and decompiler expectations for C++ classes, `__vftable`, `*_vtbl`, and multiple inheritance |
| [references/troubleshooting.md](references/troubleshooting.md) | Bridge, backend, or mutation result problems |
| [references/templates/README.md](references/templates/README.md) | Generic reusable templates for prototype passes, rename passes, checkpoint notes, and locals-JSON `jq` snippets |
