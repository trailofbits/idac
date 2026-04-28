# Class Recovery

This file documents the current public `idac` recovery flow.

Use `type class` as the primary entry point for C++ recovery work.
If the local type system is still opaque, start with `type list`, then use `type class candidates` before importing recovered types. After a local class/vtable type exists, use `type class vtable --runtime` for the combined local/runtime view.

## Contents

- [Recommended command order](#recommended-command-order)
- [What each command is for](#what-each-command-is-for)
- [Adjacent-class workflow](#adjacent-class-workflow)
- [Vtable guidance](#vtable-guidance)
- [C++ declaration guidance](#c-declaration-guidance)
- [Verification checklist](#verification-checklist)
- [Practical caveat](#practical-caveat)

## Recommended command order

```bash
idac type list "Example"
idac function list "Example_" --json --out "/tmp/class_family_functions.json"
idac decompilemany "Example_" --out-dir "/tmp/class_family_decompile_discovery"
idac type class candidates "Example" --json --out "/tmp/class_candidates.json"
idac type declare --replace --decl-file "support_types.h"
idac type declare --replace --decl-file "recovered_classes.h"
idac type class list "Example"
idac type class show "ExampleDerived"
idac type class fields "ExampleDerived" --derived-only
idac type class hierarchy "ExampleBase"
idac type class vtable "ExampleDerived" --runtime
idac function prototype show "0x100012340"
idac preview -o "/tmp/proto_preview.json" function prototype set "0x100012340" --decl "bool __fastcall ExampleDerived__method_1(ExampleDerived *__hidden this, const unsigned char *buf, u64 len, const char *arg3, u32 flags)"
idac misc reanalyze "ExampleDerived__method_1"
idac decompilemany "Example_" --f5 --out-dir "/tmp/class_family_decompile_verify"
idac decompile "CreateExampleDerived" --f5
idac decompile "ExampleDerived__method_1" --f5
```

Use the safe mutation loop from [workflows.md](workflows.md#safe-mutation-loop). For class-recovery work on one target, keep the phases distinct:

1. discovery
2. read-only audit
3. mutations
4. explicit reanalyze
5. local renames
6. final readback

Start narrow from confirmed family members, then widen to callers or adjacent helpers only when readback or propagation requires it.

Raw runtime slot inspection is not exposed as a first-class CLI command. Use `type class vtable --runtime` once the class is materialized, or fall back to `py exec` only when no first-class command covers the task.

## What each command is for

- `type list`: find named local types even when they are still opaque structs.
  Use `type list [TYPE_FILTER]`, and remember that an unfiltered run requires `--out`.
- `type class candidates`: find likely class names, vtables, RTTI, and helpers before local classes exist.
- `type class candidates` mixes `local_type`, `symbol`, `vtable_symbol`, `typeinfo_symbol`, `typeinfo_name_symbol`, and `function_symbol` rows in one flat result set.
  Use `--kind` when you want only one subset, such as `--kind function_symbol`.
- Skip `type class candidates` when clean demangled symbols and RTTI already identify the family. It is most useful for opaque targets.
- `type declare --replace`: re-import a recovered class header without leaving stale local types behind.
- `type class list`: find the classes materialized in local types.
  Use the positional class-filter form `type class list [CLASS_FILTER]`.
- `type class show`: read the flattened object layout, including inherited fields.
  If it says a type exists but is not class-materialized yet, use `type show` or re-import a concrete class layout first.
- `type class hierarchy`: confirm direct and transitive relationships after the recovered class layout has been imported.
- `type class fields --derived-only`: isolate the fields owned by one derived class.
- `type class vtable --runtime`: inspect both the local-type vtable layout and the raw runtime targets when symbols are available.
- `decompilemany "<function-filter>" --out-dir ...`: capture pseudocode artifacts for every function matching a class-family name filter before narrowing to representative callers and overrides.
  It writes one `.c` artifact per function plus `manifest.json`.
- For multiple exact functions, write one function name or address per line and pass `decompilemany --functions-file <path>`.
- For a single large function, use `decompile "<func>" -o <path>` instead of trying to force `--out-file` onto `decompile`.
- On symbol-rich targets, one early discovery capture is worth doing before mutations so you can grep the whole family locally.
- After type import and reanalysis, rerun a narrower verification capture only if you still need broad readback artifacts.
- During type or prototype recovery, prefer `decompile --f5` and `decompilemany --f5` so each pass reflects the latest imported class and prototype changes.
- During discovery, stop decompiling once constructor, destructor, one accessor, and one serializer or parser have already proven the layout.
- `function prototype set`: apply corrected function types to the runtime virtual targets after the class layout is in place.
  Use `function prototype show` first so the current signature is recorded before the update.
  Use `preview -o /tmp/proto_preview.json function prototype set ...`; the command-specific preview readback carries richer before/after data when supported.
  Clean up the shared helpers that dominate many callers before spending time on local renames. Once helper prototypes are correct and callers are reanalyzed, the remaining rename work is usually much smaller and more trustworthy.
- Treat return-type changes as higher risk than parameter-name changes. If the body does not clearly prove the returned semantic type, keep the return generic.
- `decompile`: spot-check representative constructors, factories, and overrides after type changes.
- For larger prototype or rename passes, write a `recovery.idac` file and run `batch` so the mutation order and failures are preserved in one log artifact.
- For embedded opaque members, estimate size from neighboring field offsets first, then use constructor evidence as confirmation.

Confidence and naming conventions:

- Mark plausible-but-unconfirmed variable or parameter names with `_maybe`
- Keep placeholder field names neutral and offset-based, such as `field_8` or `field_20`
- Prefer one byte array or blob field for a long contiguous unknown region, such as `unsigned char _unk_14[136]`, instead of inventing many guessed scalar fields.
- Do not present inferred vtable slots, members, or helper names as if they were confirmed
- When semantics are inferred rather than proven, note that explicitly in the issue log
- Apply the same rule to field and member names. If a recovered member name is only probable, keep it explicitly inferred until stronger proof appears.

Adjacent-class workflow:

- recover support structs first
- recover directly referenced neighbor classes next
- fix function prototypes
- inspect the current signature with `function prototype show` before applying `function prototype set`
- if a missing enum or support type such as `ExampleEnum` blocks a prototype, create the placeholder type before retrying
- reanalyze touched callers, not just the callee whose prototype changed
- rename locals last
- recover support types before cosmetic renames; early support-type recovery usually improves output more than local-name cleanup
- For large local-variable sets, read `function locals list --json --out <path>` and calibrate selectors from the JSON artifact before renaming.
- For rename previews on large functions, write the preview to disk with `preview -o <path>` and inspect the artifact with `jq` instead of trusting inline output.

For selector calibration before rename-heavy phases, read [workflows.md](workflows.md#selector-calibration).

Vtable guidance:

- Prefer `type class vtable` once the local vtable type exists
- If you need raw slot evidence before a local type exists, use `type class candidates --kind vtable_symbol` to find the symbol first, then use `py exec` as the escape hatch for one-off raw slot inspection
- Treat raw-vtable lookup failures as evidence about symbol availability, not as proof that the class family is unrecoverable
- Before writing or importing C++ declarations, review [ida-cpp-type-details.md](ida-cpp-type-details.md) so the local type text matches IDA's naming and layout rules
- On Itanium-style ABIs, keep the distinction between the raw virtual-table symbol and the virtual-table address point clear. The address stored in objects may point past header fields such as `offset_to_top` and `typeinfo`, so the first callable slot can begin after the symbol base instead of at it. See the Itanium C++ ABI's [virtual table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable) rules.
- When you want the class helpers to recognize the layout reliably, prefer IDA-friendly naming and formatting:
  - name the vtable type `ClassName_vtbl`
  - declare it as `struct /*VFT*/ ClassName_vtbl { ... };`
  - attach it to the object as `ClassName_vtbl *__vftable;`
- If the runtime symbol looks "off" by one or two pointer-sized entries, do not rename the helper-facing vtable type to match the raw symbol base. Keep `ClassName_vtbl` as the callable-slot type and, when needed for scratch analysis, wrap it in a separate raw-layout type such as:

```c
struct /*VFT*/ ClassName_vtbl {
  void (*dtor)(ClassName *__hidden this);
  void (*method_1)(ClassName *__hidden this);
};

struct ClassName_vtbl_layout {
  ptrdiff_t offset_to_top;
  void *typeinfo;
  ClassName_vtbl vtbl;
};
```

- Use that wrapper pattern when the raw symbol resolves cleanly but the first function pointer does not start at the symbol address. On common 64-bit Itanium-style layouts, the callable slots then start at `+0x10` because the `offset_to_top` and `typeinfo` header fields come first.
- For multiple inheritance or secondary-base overrides, use the IDA-specific `ClassName_XXXX_vtbl` pattern described in [ida-cpp-type-details.md](ida-cpp-type-details.md) instead of inventing an ad hoc secondary vtable name
- Avoid alternate suffixes or ad hoc member spellings when helper compatibility matters

Helpful scratch artifacts for long passes:

- a scratch recovery header such as `recovered_classes.hpp`
- an issue log such as `recovery_issues.md`
- a machine-readable mutation artifact such as `recovery.idac` plus its `batch --out` log

For batch syntax and `.idac` file format, read [workflows.md](workflows.md#batch).

For large recovered families, use `idac py exec` with an explicit local script when first-class commands are not enough, and keep the script with the rest of your recovery artifacts so the pass stays reviewable and reproducible.

For shell inspection of JSON artifacts, prefer portable tools such as:

- `type list`, `type class candidates`, and `function list` artifacts are top-level JSON arrays, so inspect them with `.[]`.

```bash
jq '.functions_succeeded' /tmp/class_family_decompile/decompile_manifest.json
jq -r '.functions[] | select(.ok) | [.name, .artifact_path] | @tsv' /tmp/class_family_decompile/decompile_manifest.json
jq -r '.steps[] | select(.ok == false) | [.line, .command, .error] | @tsv' /tmp/recovery_batch.json
jq -r '.[].name' /tmp/class_types.json
jq -r '.[] | select(.kind == "function_symbol") | .name' /tmp/class_candidates.json
jq -r '.[] | [.kind, .name] | @tsv' /tmp/class_candidates.json
jq -r '.[].name' /tmp/class_family_functions.json
sed -n '1,80p' /tmp/recovery_batch.json
```

## C++ declaration guidance

Prefer plain `struct` declarations first when the target database is still rough or diagnostics flag parser trouble.
Before finalizing class or vtable declaration text, read [ida-cpp-type-details.md](ida-cpp-type-details.md) for IDA parser syntax, naming patterns, and multiple-inheritance edge cases.

Practical rules:

- keep the first import minimal: plain `struct`, direct field declarations, and no preprocessor wrappers or comment noise
- only add vtable-specific forms when there is direct evidence of virtual dispatch on that class, such as a constructor storing a vtable pointer, a recovered runtime vtable symbol, or an already-confirmed `__vftable` member
- keep helper-compatible names such as `ClassName_vtbl` and `__vftable`
- treat `__cppobj` as optional refinement, not a requirement for the first successful import
- for secondary-base virtual tables, use the IDA-specific `ClassName_XXXX_vtbl` pattern
- use `--alias old=new` during import when namespace-qualified names need flattening for local-type parsing
- if import errors suggest parser trouble, simplify the declaration and retry with preview first

## Stop Conditions

Stop a recovery pass when:

- the object layout is structurally readable and the important offsets are justified by constructor, accessor, serializer, or caller evidence
- the key helper and virtual-target prototypes are corrected enough that callers read coherently after reanalysis
- the remaining confusion is mostly Hex-Rays presentation noise rather than uncertainty about the actual data flow or type relationships

Do not keep pushing for cosmetic pseudocode perfection when:

- large-stack AArch64 prologues still show odd top-of-function value flow after prototype cleanup and reanalysis
- destructor or cleanup paths still lose precise derived-type propagation even though the recovered class layout is already consistent
- the remaining unnamed locals are mostly spill state, scratch temporaries, or compiler artifacts that do not change the safety argument

## Verification checklist

- class size matches the recovered declaration
- base list matches the intended hierarchy
- `type class fields --derived-only` contains the expected subclass fields
- `type class vtable` shows the expected slot names
- runtime virtual targets have function prototypes applied, not just local vtable slot types
- at least one representative base implementation and one representative override decompile with the expected `this` type
- at least one caller of a newly fixed prototype reflects the intended type cleanup
- stale caller casts or bad `this` propagation triggered targeted `reanalyze` on those callers before final readback
- any renamed locals were reread after the last prototype/reanalysis pass
- each committed rename was confirmed by rereading `function locals list --json` and checking the intended `index` or `local_id`
- rename work stayed scoped per function, with a fresh local reread before moving to the next function

Representative readback set:

- one constructor or destructor
- one accessor
- one parser/helper
- one caller of a newly fixed prototype
- one function whose locals were renamed

## Practical caveat

Do not assume every derived field appears strictly after the base size. Real targets can reuse tail padding, so constructor evidence and `this+offset` access patterns still matter.
Treat empty derived classes as the default unless constructor evidence or `this+offset` access proves extra state.
Inherited vtable slot types often keep the base-class `this` type even when the runtime target is a derived override. When improving decompiler quality, prefer the owning implementation class from the runtime target symbol when setting the function prototype.
If demangled signatures or nearby callers reference useful local types that do not yet exist, create placeholder support types early instead of leaving important prototypes generic.
Prefer preserving existing opaque local types unless replacing them is intentionally required for layout recovery.
If you replace an opaque type with a size-only blob or placeholder, record that tradeoff explicitly in the issue log.
Destructor bodies often start by restoring a vtable pointer and then lose precise derived-type propagation in Hex-Rays. When that happens, use function-local retypes on the derived locals after the prototype and reanalysis pass instead of forcing the whole type system harder.
