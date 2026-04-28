# Class Recovery Pass

Use the `idac` skill to reverse and fix up types for a class family.

<!-- Fill in before running -->
**Target**: <!-- e.g., -c db:/path/to/firmware.i64 -->
**Scope**: <!-- list specific classes, e.g., "ExampleBase, ExampleDerived, ExampleHelper" -->
**Prior work**: <!-- link to audit/ entry or "none" -->
**Focus**: <!-- e.g., "recover vtable and field layout", "fix prototypes for callers", "rename locals in decode path" -->

---

## Reference Documentation

Read these before writing declarations or mutating the database:

- **@reference/class-recovery.md** — command order, vtable guidance, verification checklist
- **@reference/ida-cpp-type-details.md** — IDA parser syntax, vtable naming patterns, multiple-inheritance edge cases
- **@reference/workflows.md** — safe mutation loop, selector calibration, batch format

---

## Phase Order

Follow the safe mutation loop from `reference/workflows.md`:

1. **Discovery** — read-only, capture artifacts
2. **Audit** — document findings before mutations
3. **Mutations** — preview, commit, readback
4. **Reanalyze** — after types/prototypes change
5. **Renames** — after reanalysis, one function at a time
6. **Verify** — final readback against Phase 1 artifacts

Start narrow from confirmed family members. Widen to callers or adjacent helpers only when readback or propagation requires it.
If read-only GUI commands succeed but a mutation fails, treat it as an IDA/database failure mode (undo disabled, read-only database, unknown type, rejected declaration) rather than a socket permission split.

---

## Discovery Commands

```bash
# Find existing local types
idac type list <pattern> -c <target> --json --out .idac/tmp/discovery_types.json

# Find candidate classes, vtables, RTTI, and function symbols
idac type class candidates <pattern> -c <target> --json --out .idac/tmp/discovery_candidates.json

# List all functions in the family
idac function list <pattern>_ -c <target> --json --out .idac/tmp/discovery_functions.json

# Decompile the whole family for local inspection
idac decompilemany "<function-filter>_" --f5 --out-dir .idac/tmp/discovery_decompile -c <target>

# Find runtime vtable symbols before local classes exist
idac type class candidates <pattern> --kind vtable_symbol -c <target> --json --out .idac/tmp/discovery_vtables.json
```

Decompile enough to prove the layout. Stop once you have:
- One constructor
- One destructor
- One accessor
- One parser/serializer or complex method

For a single large function, use `decompile "<func>" -o <path>` instead of trying to force `--out-file` onto `decompile`.

---

## Type Recovery

For each struct/class:

1. Map field offsets from `this+offset` access patterns
2. Use neighboring field offsets to estimate sizes; confirm with constructor evidence
3. Check constructor/destructor for vtable stores (proves virtual class)
4. Name fields based on debug strings and usage context
5. Mark uncertain names with `_maybe` suffix
6. Use `unsigned char _unk_XX[N]` for unknown regions — don't guess scalar fields

For enums:
- Collect all observed values from switch statements and string tables
- Name members based on debug strings when available

For vtables:
- Follow naming and layout rules from `reference/ida-cpp-type-details.md`
- VFT pointer: `__vftable`
- Vtable type: `ClassName_vtbl` (declared as `struct /*VFT*/ ClassName_vtbl { ... }`)
- Secondary vtables for multiple inheritance: `ClassName_XXXX_vtbl`
- Slot signatures should reflect actual parameter types from decompiled bodies

Write recovered types to `headers/recovered/<family>.h` in dependency order:
- Forward declarations for mutual references
- Support types and enums first
- Vtable structs before classes that reference them
- Base classes before derived classes

---

## Import and Apply

```bash
# Preview before commit
idac preview -o .idac/tmp/type_import_preview.json type declare --replace --decl-file headers/recovered/<family>.h -c <target>

# Commit
idac type declare --replace --decl-file headers/recovered/<family>.h -c <target>

# Verify
idac type class show <ClassName> -c <target>
idac type class vtable <ClassName> --runtime -c <target>
idac type class hierarchy <BaseClass> -c <target>
idac type class fields <DerivedClass> --derived-only -c <target>
```

After vtable import, redecompile functions that use the class. Resolved virtual calls reveal new type information. Feed discoveries back into the header, re-import, and iterate until redecompiling stops revealing new information.

---

## Prototype Fixes

```bash
# Read current signature first
idac function prototype show <func> -c <target>

# Preview and commit
idac preview -o .idac/tmp/proto_preview.json function prototype set <func> --decl '...' -c <target>
idac function prototype set <func> --decl '...' -c <target>

# Reanalyze after changes
idac misc reanalyze <func> -c <target>
```

For virtual function targets, use the owning class from the runtime symbol as the `this` type, not the base class. Reanalyze callers if they show stale casts.
Clean up shared helper prototypes before broad local-rename passes. Once the helpers are typed and callers are reanalyzed, the remaining local work is usually smaller and more trustworthy.

---

## Local Renames

After reanalysis, reread locals before renaming:

```bash
idac function locals list <func> --json -c <target>
idac function locals list <func> --json --out .idac/tmp/<func>.locals.json -c <target>
```

If the local set is large or you need a stable artifact for later review, prefer `--json --out` over inline readback. Copy exact `local_id` or `index` values from the artifact rather than guessing from stale pseudocode.

Prefer `--local-id` or `--index` selectors after reanalysis drift. Stop on first miss — reread locals, recalibrate, then continue.
For large rename previews, write the preview to disk with `preview -o <path>` and inspect the JSON artifact with `jq` instead of relying on inline output.

```bash
# One local needing both name and type
idac preview function locals update <func> <selector> --rename <name> --decl '...' -c <target>

# Simple rename
idac preview function locals rename <func> <selector> --new-name <name> -c <target>

# Simple retype
idac preview function locals retype <func> <selector> --type "unsigned int" -c <target>

# Full-declaration retype when the declarator is complex
idac preview function locals retype <func> <selector> --decl '...' -c <target>
```

Split rename work per function. Reread locals between functions.
Use `--type` for simple local retypes. Use `--decl` when the retype needs a full declaration, such as arrays or function pointers.

---

## Verification Checklist

From `reference/class-recovery.md`:

- [ ] Class size matches recovered declaration
- [ ] Base list matches intended hierarchy
- [ ] `type class fields --derived-only` contains expected subclass fields
- [ ] `type class vtable` shows expected slot names
- [ ] Runtime virtual targets have function prototypes applied
- [ ] At least one constructor/destructor decompiles with correct `this` type
- [ ] At least one caller of a fixed prototype shows correct type propagation
- [ ] Any renamed locals confirmed by rereading `function locals list --json`

Redecompile the representative set from discovery (constructor, destructor, accessor, parser/helper) to verify improvements.
Stop when the structure and safety-relevant call flow are readable. Do not keep forcing cleanup for obvious Hex-Rays presentation artifacts such as large-stack AArch64 prologue noise or destructor-specific derived-type loss.

---

## Audit Log

Append to `audit/<family>-recovery.md`:

```markdown
## <family> — Recovery Pass <N> — <date>

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

The audit log is append-only. Each pass adds a new section.

---

## Non-Negotiable Rules

- Always `preview` before committing mutations
- Always `function prototype show` before `function prototype set`
- Always `reanalyze` after type/prototype changes, before local renames
- Use `--f5` with `decompile`/`decompilemany` during type recovery
- Reread `function locals list --json` after reanalysis before renames
- Stop rename batch on first miss; recalibrate selectors
- Work from the binary first — no web search unless explicitly asked
- Mark uncertain names with `_maybe`
- Use offset-based placeholder names (`field_8`, `_unk_14`) for unknowns
- Don't add vtable types without evidence of virtual dispatch
- Treat return-type changes as higher risk than parameter changes
