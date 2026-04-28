# Reverse Engineer

Use the `idac` skill to systematically recover type information, improve decompiler output, and leave an audit trail for future agents.

The `idac` CLI grammar is documented in `reference/cli.md`.

<!-- ============================================================
     CUSTOMIZE THIS SECTION for your target, then use the prompt.
     Everything below the line is the workflow — edit if needed.
     ============================================================ -->

## Setup

Fill these in before running:

- **Target**: <!-- e.g., ExampleClass family, sub_08041337, all ExampleBase_* subclasses -->
- **Context**: <!-- e.g., no flag for one live GUI, -c pid:1234, or -c db:/path/to/file.i64 -->
- **Scope**: <!-- single function | single class | class family | module -->
- **Prior work**: <!-- link to existing audit entry, or "none" -->
- **Focus**: <!-- what specifically to improve — e.g., "recover vtable and field layout", "fix prototypes for callers", "rename locals in decode path" -->

---

## Non-Negotiable Defaults

- Work from the binary first. Do not search the web or external source trees unless the user explicitly asks for that or the task is specifically about external correlation.
- Unix socket access is required for all live GUI operations (read-only and mutating). If read-only commands succeed but a mutation fails, troubleshoot the underlying IDA/database error rather than assuming a socket permission split.
- During type or prototype recovery, always use `decompile --f5` and `decompilemany --f5` so readback reflects the latest imported types and signatures.
- Before `function prototype set`, run `function prototype show` to capture the current signature and confirm the intended delta.
- After meaningful type or prototype changes, run `misc reanalyze`, then reread pseudocode or locals before rename-heavy cleanup.
- For cross-references, use the top-level `xrefs` command; do not search for a `function xrefs` subcommand.
- Before batch local renames, run `function locals list --json --out <path>` and prefer `--local-id` or `--index` selectors after reanalysis drift.
- If a locals list is too large to read inline, add `--out` and work from the JSON artifact instead of the terminal buffer.
- Stop a rename batch on the first miss. Reread locals, recalibrate selectors, and only then continue.
- Declare support types before dependent prototypes.
- Prefer minimal `struct` declarations first. Start with the vtable pointer and directly observed fields, and use blob padding for unknown regions instead of guessed scalar fields.

## Phase 0 — Triage

Goal: decide what to work on and in what order. Skip for a single well-defined target.

When given a broad target (a class family, a module, or multiple targets):

1. Collect the full function and type surface:
   ```
   idac function list <family> -c <context> --json --out .idac/tmp/triage_functions.json
   idac type list <family> -c <context> --json --out .idac/tmp/triage_types.json
   ```
2. Identify base types and widely-referenced types first — fixing them improves decompiler output across many functions at once:
   - Types that appear in many function signatures
   - Base classes that other classes inherit from
   - Structs passed to or returned from many callees
   - Enums used in switch statements across multiple functions
3. Identify dependency order. A derived class needs its base recovered first. A prototype needs its parameter types to exist first.
4. Check `audit/` for prior work — don't redo what's already done.
5. Write a triage plan to `audit/<family>-triage.md`:

```markdown
## <family> — Triage — <date>

### Targets Identified
### Priority Order
### Already Done
### Out of Scope
```

## Phase 1 — Discovery

Goal: understand what we're looking at before changing anything.

1. Search for the target in the function list and string table:
   ```
   idac function list <target> -c <context> --json --out .idac/tmp/discovery_functions.json
   idac search strings <target> --segment <segment> -c <context> --timeout 30
   ```
2. Decompile a representative set (constructor, destructor, one accessor, one complex method). Stop once you have enough evidence to prove the layout.
   ```
   idac decompilemany "<target>" --f5 --out-dir .idac/tmp/discovery_decompile -c <context>
   ```
   The positional argument is a name filter, not a list of functions. For multiple exact functions, write one function name or address per line and use `decompilemany --functions-file ... --out-file ...` or `--out-dir ...`.
   For a single large function, use `--out` on `decompile` from the start so the useful readback is not truncated.
3. Collect xrefs, callers, and callees for the primary entry points.
4. Check existing local types:
   ```
   idac type list <target> -c <context> --json --out .idac/tmp/discovery_types.json
   ```
5. If C++ class recovery is relevant, run candidates:
   ```
   idac type class candidates <target> -c <context> --json --out .idac/tmp/discovery_candidates.json
   ```
6. Before drafting class or vtable declarations, review `reference/class-recovery.md` and `reference/ida-cpp-type-details.md` so the imported text follows IDA's parser conventions.

Read the decompiled output carefully. Note:
- Debug strings, error messages, log format strings — these reveal parameter names, enum values, and struct semantics
- Field access patterns at `this+offset` — these reveal struct layout and field sizes
- Constants, magic numbers, and switch cases — these often indicate enums
- Virtual dispatch patterns — these reveal vtable layout
- Calls to known library functions (memcpy sizes, allocation sizes) — these reveal struct sizes

## Phase 2 — Type Recovery

Goal: build .h header files that capture recovered structs, classes, and enums.

1. For each struct/class identified in Phase 1:
   - Map field offsets from decompiled `this+offset` access patterns
   - Use neighboring field offsets to estimate sizes; confirm with constructor evidence
   - Check constructor/destructor for vtable stores (proves virtual class)
   - Name fields based on debug strings and usage context
   - Mark uncertain names with `_maybe` suffix
   - Prefer minimal declarations first; add fields only when accesses prove them
   - Use `unsigned char _unk_XX[N]` for unknown regions instead of guessing scalar types

2. For enums identified from switch statements or string tables:
   - Collect all observed values and their associated strings/behavior
   - Name members based on debug strings when available

3. For virtual classes, recover the vtable:
   - Use `type class candidates <target> --kind vtable_symbol -c <context> --json --out ...` to find runtime vtable evidence before local classes exist.
   - After importing the class, use `idac type class vtable <ClassName> --runtime -c <context>` for the combined local/runtime view.
   - If you truly need raw slot inspection before a local class exists, use `idac py exec` as the escape hatch rather than guessing at a non-public command.
   - Each slot is a function pointer. Decompile the targets to understand their signatures.
   - Build the local type text using the naming and layout rules in `reference/class-recovery.md` and `reference/ida-cpp-type-details.md`.
   - Follow IDA's exact conventions for `ClassName_vtbl`, `__vftable`, and any secondary-base `ClassName_XXXX_vtbl` cases instead of inventing local variants. Treat `__cppobj` as optional refinement, not the first import requirement.
   - Slot function pointer signatures should reflect the actual parameter types visible in the decompiled target bodies. Generic `void *` slots waste the effort.
   - If a base class already has a vtable, the derived class inherits it. Only create a new `Derived_vtbl` if the derived class adds new virtual functions or you need the slot types to use the derived `this` pointer.

4. Write recovered types to `headers/recovered/<target>.h` in dependency order:
   - Forward declarations for mutual references
   - Support types and enums first
   - Vtable structs (`/*VFT*/` annotated) before the classes that reference them
   - Base classes before derived classes
   - Prefer a minimal working first pass such as:
     ```c
     struct ClassName_vtbl { void (*slot_0)(void *); };
     struct ClassName { ClassName_vtbl *__vftable; int field_8; };
     ```
   - Keep the first import free of preprocessor wrappers and comment clutter; add refinements only after the minimal form imports cleanly

5. For types that block other declarations (forward references, enums used in prototypes), create them as support types first.

## Phase 3 — Apply Types and Prototypes

Goal: import recovered types and fix function signatures.

**Import types:**

1. Preview the type import, then commit if it succeeds:
   ```
   idac preview -c <context> -o .idac/tmp/type_import_preview.json type declare --replace --decl-file headers/recovered/<target>.h
   idac type declare --replace --decl-file headers/recovered/<target>.h -c <context>
   ```
2. Verify the imported types:
   ```
   idac type class show <ClassName> -c <context>
   idac type class vtable <ClassName> --runtime -c <context>
   ```

**Vtable-driven redecompile cycle:**

Once a vtable struct is imported and attached to a class, redecompile functions that use that class. The decompiler now resolves virtual calls through the typed vtable, so `this->__vftable->process(this, data, len)` appears instead of raw pointer arithmetic. This often reveals new type information:

3. Reanalyze, then redecompile functions that use the class.
   Use `--f5` for `decompile` and `decompilemany` throughout this phase so each readback reflects the latest type and prototype changes.
4. The improved output often reveals:
   - Parameter types that were previously opaque (now visible through vtable slot signatures)
   - Field types on related structs (slot bodies access them with correct types now)
   - Additional virtual call chains (a resolved call leads to another class with its own vtable)
   - Return types from virtual methods that were previously `__int64`
5. Feed discoveries back into the header — update field types, add newly discovered types, refine vtable slot signatures. Re-import and redecompile again. Stop when redecompiling no longer reveals new type information.

**Fix function prototypes (after vtable types are stable):**

6. For each virtual function target, read the current signature, then set the concrete function's prototype to match the vtable slot signature:
   ```
   idac function prototype show <func> -c <context>
   idac preview -c <context> -o .idac/tmp/prototype_preview.json function prototype set <func> --decl-file <proto_file>
   ```
7. Clean up the shared helpers that dominate many callers before broad rename work. Reanalyze after prototype mutations. Check callers of changed prototypes — reanalyze them too if they show stale casts.

For larger passes, prefer `batch` with a `.idac` batch file so the mutation order and any failures are captured.

## Phase 4 — Rename and Retype Locals

Goal: improve readability of individual functions after types are stable.

1. Reread locals after reanalysis:
   ```
   idac function locals list <func> -c <context> --json --out .idac/tmp/<func>.locals.json
   ```
   If you need a stable artifact for later inspection, add `--out` here as well.
2. If one local needs both a better recovered name and a better recovered type, prefer a single `function locals update` pass. For batch or post-reanalysis local work, prefer `--local-id` or `--index` selectors instead of guessed local names.
3. Use `function locals rename` or `function locals retype` only for straightforward one-off edits where changing one attribute is materially clearer than using `update`.
4. Split rename work per function. Reread locals between functions and after any reanalysis.

Previewed local mutations:

```bash
idac preview -c <context> -o .idac/tmp/local_update_preview.json function locals update <func> <selector> --rename <name> --decl-file <decl_file>
idac preview -c <context> -o .idac/tmp/local_rename_preview.json function locals rename <func> <selector> --new-name <name>
idac preview -c <context> -o .idac/tmp/local_retype_type_preview.json function locals retype <func> <selector> --type "unsigned int"
idac preview -c <context> -o .idac/tmp/local_retype_preview.json function locals retype <func> <selector> --decl-file <decl_file>
```

Use `--type` for simple local retypes. Use `--decl` or `--decl-file` when the retype needs a full declaration, such as arrays or function pointers.

## Phase 5 — Verify

Goal: confirm the decompiler output improved.

1. Redecompile the representative function set from Phase 1.
   Use `--f5` here as well when this pass is still validating type-recovery changes.
2. Key checks:
   - Class sizes match recovered declarations
   - At least one constructor/destructor decompiles cleanly with correct `this` type
   - At least one caller of a changed prototype shows correct type propagation
   - Vtable slots resolve to named functions with typed parameters
   - See the `$idac` skill's verification checklist in `class-recovery.md` for the full list
3. Compare discovery vs. verification decompiles. Note improvements and remaining issues.
4. Stop when the structure, call behavior, and safety argument are readable. Do not keep forcing types just to remove obvious Hex-Rays presentation artifacts such as large-stack AArch64 prologue noise.

## Phase 6 — Audit Log

Goal: leave a record for future agents and humans.

Append findings to `audit/<target>-recovery.md`:

```markdown
## <target> — Recovery Pass <N> — <date>

### Scope
### Types Recovered
### Prototypes Fixed
### Locals Renamed
### What Worked
### What Didn't Work
### Open Questions
### TODO for Next Pass
- [ ] ...
```

The audit log is append-only per target. Each pass adds a new section. Don't rewrite prior pass notes — they're historical record. The TODO checkboxes are meant to be picked up by future agents or humans scanning the file.

## Batch Targets

When working on a family of related types (e.g., all subclasses of a base):

1. Complete Phase 0 (triage) to establish priority order.
2. Work through the priority list, running Phases 1-6 for each target.
3. Do base classes and shared support types first — these unlock better decompilation for everything downstream.
4. After each target, update the triage plan with completion status.
5. When a batch of behavior-only subclasses share the same base layout with no derived state, review them together and write one combined audit entry noting which classes were reviewed.

## Iterative Pass Protocol

When continuing work on a previously reversed target:

1. Read the existing audit log and header for the target.
2. Check the "Open Questions" and "TODO for Next Pass" from the last entry.
3. Start from Phase 1 scoped to the open items. Follow Phases 2-6 for the incremental changes.
4. Reference the prior pass number and build on it.

If no prior audit exists, start fresh from Phase 1. If a prior audit exists but you have no conversation context, read the latest entry, spot-check that it's still accurate against the database, and continue from its open items. If the audit is stale, note that and start a fresh discovery.

## Rules

- Always preview before committing mutations
- Always reanalyze after type or prototype changes, before local renames
- During type or prototype recovery, always use `--f5` with `decompile` and `decompilemany`
- Always run `function prototype show` before `function prototype set`
- Always reread locals after reanalysis before renaming; use `--local-id` or `--index` selectors after reanalysis drift
- Work from the binary first; do not search the web or external source trees unless explicitly asked
- Mark uncertain names with `_maybe`
- Use offset-based placeholder names for unknown fields (`field_8`, `_unk_14`)
- Prefer one blob field for large unknown regions over many guessed scalars
- Don't add vtable types without evidence of virtual dispatch (constructor storing a vtable pointer, or runtime vtable symbol exists)
- Treat return-type changes as higher risk than parameter changes
- When setting prototypes on virtual function targets, use the owning class from the demangled symbol as the `this` type, not the base class
- The vtable import → redecompile → refine → re-import cycle is the core loop for class recovery; repeat until redecompiling stops revealing new information
- Stop iterating when a cycle produces only cosmetic improvements; log remaining items as TODOs rather than chasing diminishing returns
- Keep per-target headers separate unless types are tightly coupled (e.g., a base class and its vtable belong in the same header)
- Keep audit notes factual — distinguish proven from inferred
- Write headers that IDA can actually parse (test with preview)
