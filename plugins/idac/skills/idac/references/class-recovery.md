# Class Recovery

Read this for C++ layouts, inheritance, vtables, and virtual-target prototypes.
Match the work to the request: a hierarchy report can use symbols and RTTI without
importing types or renaming locals. For database edits, use the
[mutation workflow](workflows.md#safe-mutation-loop).

## Contents

- [Discover the family](#discover-the-family)
- [Recover a layout](#recover-a-layout)
- [Vtable guidance](#vtable-guidance)
- [Apply types to runtime functions](#apply-types-to-runtime-functions)
- [Verification and completion](#verification-and-completion)

## Discover the family

Start with the strongest available evidence: demangled symbols, RTTI, constructor
vtable stores, existing local types, and field accesses. Scope discovery to the
requested family; widen to callers or adjacent classes when evidence requires it.

```bash
idac function list "Example" --demangle --json --out "family.functions.json"
idac type list "Example" --json --out "family.types.json"
idac type class candidates "Example" --json --out "class_candidates.json"
```

Choose the reads that address a gap:

- `type list` finds local types even when they are opaque structs.
- `type class candidates` finds local types and symbol evidence before concrete
  class layouts exist. Its rows mix `local_type`, `symbol`, `vtable_symbol`,
  `typeinfo_symbol`, `typeinfo_name_symbol`, and `function_symbol`; use `--kind`
  to select a category. Skip it when symbols and RTTI already identify the family.
- `type class show` and `type class vtable` inspect materialized local layouts.
  If a type exists but is not class-materialized, inspect `type show` and runtime
  evidence; repeating class queries on the opaque type will not recover it.
- Use addresses, mangled names, or full signatures for overloaded functions.
  Candidate, type, and function JSON lists are top-level arrays.

Decompile representative constructors, destructors, accessors, or parsers with
`--f5` until the relevant offsets and relationships are justified. For a broad
family capture, use `decompilemany` and its manifest as described in
[broad discovery](workflows.md#broad-discovery-defaults). Avoid a family-wide dump
when a few representatives answer the question.

## Recover a layout

When the task requires recovered declarations, read
[C++ type details](ida-cpp-type-details.md) for IDA parser and vtable conventions.
Declare support structs and directly referenced neighbors before dependent classes.
Reuse existing, evidence-consistent layouts and inheritance instead of recovering
their fields again. Read only the declarations needed for the requested family.
For local-type imports, flatten namespace names consistently in the header (for
example `Group__Item`) and record the mapping; avoid namespace blocks in the default
parser. Keep original demangled names in the evidence report.

Start with minimal plain `struct` declarations: observed vtable pointer, directly
evidenced fields, and blob padding for unknown regions. Preserve existing opaque
types unless replacing them is needed for the requested layout; record a deliberate
size-only replacement as a loss of type detail.

- Use neutral offset-based names such as `field_8`; mark inferred semantics in
  notes or provisional names, such as `count_maybe`.
- Use one byte array for a contiguous unknown region instead of guessed scalars.
- Add `__attribute__((packed))` only when observed offsets prove packed layout.
  Keep real gaps explicit. `__cppobj` is an optional refinement whose effect on
  layout must be checked.
- A derived class may reuse base tail padding. Field accesses and constructor
  evidence take precedence over assuming derived fields start after base size.
- Keep a derived class empty unless field accesses or constructor evidence prove
  additional state. Estimate embedded opaque-member sizes from neighboring
  offsets, then corroborate them in constructors.

For a recovered header replacing existing types, preview the replacement itself:

```bash
idac preview -o "classes.preview.json" type declare --replace --decl-file "recovered_classes.h"
jq . classes.preview.json
```

After inspecting the intended layout changes, commit and read back:

```bash
idac type declare --replace --decl-file "recovered_classes.h"
idac type deps "ExampleDerived"
idac type class show "ExampleDerived"
idac type class fields "ExampleDerived" --derived-only
idac type class hierarchy "ExampleBase"
```

Keep the selected target on every invocation. Separate imports when a later header
depends on support types; an earlier preview does not retain imported types.
Use [import troubleshooting](troubleshooting.md) for `--bisect`, parser changes
with `--clang`, or namespace flattening with `--alias OLD=NEW`.
For isolated member corrections, use [narrow type edits](workflows.md#narrow-type-edits).

## Vtable guidance

Add vtable declarations only with virtual-dispatch evidence: a constructor store,
runtime vtable symbol, or confirmed `__vftable` member. For class-helper compatibility,
name the callable-slot type `ClassName_vtbl`, declare it as
`struct /*VFT*/ ClassName_vtbl`, and attach it as `ClassName_vtbl *__vftable;`.

```bash
idac type class vtable "ExampleDerived" --runtime
```

This combines local slot types and runtime targets once a class is materialized.
Before then, `type class candidates --kind vtable_symbol` can locate a symbol;
raw slot reads need `py exec` if no first-class command covers them. A missing
runtime symbol limits that lookup rather than disproving the class family.

For Itanium-style ABIs, distinguish emitted vtable data from its address point:
header words can precede the callable slots. Keep those words in a separate scratch
layout instead of treating them as functions. For multiple inheritance, use the
IDA `ClassName_XXXX_vtbl` convention for secondary-base overrides. Offset and
declaration examples are in [C++ type details](ida-cpp-type-details.md).
Confirm the target ABI from database metadata and binary evidence before relying
on its layout rules. If the compiler ID itself is needed, use the verified
[IDAPython recipe](workflows.md#idapython-escape-hatch).

## Apply types to runtime functions

Local vtable-slot types and runtime function prototypes are separate. Apply
evidence-backed signatures to the actual virtual targets when the task requires
better caller decompilation. An inherited slot can retain a base `this` type while
the implementation belongs to a derived class; use the implementation's evidence
when choosing its prototype.

Read the current signature with `function prototype show`, validate custom
conventions with `function prototype check` when needed, then preview
and commit as described in [the mutation loop](workflows.md#safe-mutation-loop).
Use `prototype set --preserve-cc` when retyping a factory return or parameter while
retaining the existing calling convention.
Reanalyze affected functions and callers before fresh `--f5` readback. Calibrate
[local cleanup](workflows.md#selector-calibration) only after that phase.

Destructor bodies often restore a vtable pointer and then lose precise derived
type propagation in Hex-Rays. A function-local retype may help after prototype
cleanup and reanalysis; avoid forcing broader type changes solely to improve
presentation.

## Verification and completion

Verify the aspects the request depends on:

- Object size, bases, and important field offsets agree with binary evidence;
  `type class fields --derived-only` distinguishes subclass fields.
- Local vtable slots and runtime targets agree where runtime evidence is available.
- Changed runtime prototypes have the expected `this` type in fresh pseudocode,
  and an affected caller reflects the intended propagation.
- Committed local plans match fresh locals readback.
- Reports or recovered headers identify supporting addresses and unresolved
  hypotheses; workspace audit notes record actual changes and failures.

Choose representative readbacks based on the changes, such as a constructor, an
override, and an affected caller. Stop when the requested layout or relationships
are supported and relevant callers are readable. Large-stack AArch64 prologue
noise, cleanup casts, and unnamed spill temporaries warrant more work only when
they obscure the requested result.
