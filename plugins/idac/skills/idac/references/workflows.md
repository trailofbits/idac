# Common Workflows

Read this for safe mutation, batch, selector calibration, broad discovery, and post-mutation readback.

## Contents

- [Inspect an open GUI target](#inspect-an-open-gui-target)
- [Open a binary](#open-a-binary)
- [Work from an existing database file](#work-from-an-existing-database-file)
- [Recover type information around a function](#recover-type-information-around-a-function)
- [Recover C++ class information](#recover-c-class-information)
- [Safe mutation loop](#safe-mutation-loop)
- [Narrow type edits](#narrow-type-edits)
- [Record findings in the database](#record-findings-in-the-database)
- [Selector calibration](#selector-calibration)
- [Batch](#batch)
- [Broad discovery defaults](#broad-discovery-defaults)
- [Structural inspection and reanalysis](#structural-inspection-and-reanalysis)

## Inspect an open GUI target

```bash
idac doctor
idac targets list --json
idac function metadata "sub_08041337" --instance "<record-id>"
idac decompile "sub_08041337" --instance "<record-id>"
idac decompile "sub_08041337" -o "/tmp/sub_08041337.txt" --instance "<record-id>"
idac xrefs "sub_08041337" --instance "<record-id>"
```

Omit the selector only when exactly one READY Nexus instance exists.
If target discovery is failing rather than merely unknown, read [targets-and-backends.md](targets-and-backends.md) or [troubleshooting.md](troubleshooting.md) before treating diagnostics as part of the normal read workflow.

Live GUI notes:

- if a command will be parsed, use `--json`
- for parsed-read and `--out` defaults, read [cli.md](cli.md)
- for a single large decompile, use `-o/--out` on `decompile`; reserve `--out-file` and `--out-dir` for `decompilemany`
- run one `idac` command at a time per target; Nexus serializes IDA work, and
  background parallel commands can fill the queue or make mutation ordering unclear

## Open a binary

For detailed context selection and first-time import guidance, read [targets-and-backends.md](targets-and-backends.md).

```bash
idac targets list --json
idac database show -c "/path/to/binary" --json
idac decompile "main" -c "/path/to/binary" --f5
```

## Work from an existing database file

```bash
idac doctor
idac database show -c sample.i64
idac decompile "sub_08041337" -c sample.i64
idac decompile "sub_08041337" --f5 -c sample.i64
idac decompilemany "sub_0804" --out-dir "/tmp/function_decompile" -c sample.i64
idac ctree "sub_08041337" -c sample.i64
```

## Recover type information around a function

```bash
idac function prototype show "sub_08041337"
idac function locals list "sub_08041337"
idac function locals list "sub_08041337" --json --out "/tmp/locals.json"
idac preview -o "/tmp/local_rename_preview.json" function locals rename "sub_08041337" "v12" --new-name "value_maybe"
idac type list "example"
idac type deps "ExampleStruct"
idac type struct show "ExampleStruct"
idac type enum show "ExampleEnum"
```

If any demangled or printed signature references a useful type that does not exist locally yet, create a placeholder support struct before continuing with broader class or prototype cleanup.
If you need to check many support-type names, prefer one broad `type list --json --out <path>` artifact and inspect it locally rather than issuing many scattered single-name queries. `type list` requires either a pattern or `--out <path>`.

## Recover C++ class information

For the full class recovery workflow, phased ordering, naming rules, vtable guidance, and verification checklist, read [class-recovery.md](class-recovery.md).

## Safe mutation loop

```bash
idac function prototype show "sub_08041337"
idac function prototype check "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
idac preview -o "/tmp/proto_preview.json" function prototype set "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
idac preview -o "/tmp/proto_file_preview.json" function prototype set "sub_08041337" --decl-file "sub_08041337_proto.h"
idac preview -o "/tmp/local_update_preview.json" function locals update "sub_08041337" "v12" --rename "value_maybe" --decl "unsigned int value_maybe;"
idac preview -o "/tmp/local_rename_preview.json" function locals rename "sub_08041337" "v13" --new-name "entry_count"
idac preview -o "/tmp/local_retype_preview.json" function locals retype "sub_08041337" "v4" --type "unsigned int"
idac preview -o "/tmp/local_retype_decl_preview.json" function locals retype "sub_08041337" "v4" --decl "unsigned int v4;"
idac preview -o "/tmp/local_retype_file_preview.json" function locals retype "sub_08041337" "v4" --decl-file "local_v4.h"
idac type check --decl "typedef struct ExampleStruct { int field_0; } ExampleStruct;"
idac type check --decl-file "recovered_classes.h"
idac preview -o "/tmp/type_preview.json" type declare --decl "typedef struct ExampleStruct { int field_0; } ExampleStruct;"
idac preview -o "/tmp/type_replace_preview.json" type declare --replace --decl-file "recovered_classes.h"
idac preview -o "/tmp/type_clang_preview.json" type declare --clang --decl-file "recovered_templates.hpp"
```

The positional local selectors in these previews are for pre-reanalysis one-off checks. After `misc reanalyze`, committed rename or retype batches should switch to `--index` or `--local-id`; see [Selector calibration](#selector-calibration).

Inspect the relevant preview artifact before committing; standalone preview only prints the artifact location. For example, run `jq . /tmp/proto_preview.json` and confirm the intended `before` and `after` data. Then commit the real change, reanalyze, and read it back:

```bash
idac function prototype set "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
idac misc reanalyze "sub_08041337"
idac function prototype show "sub_08041337"
idac decompile "sub_08041337" --f5
```

Symbol renames go through `misc rename <identifier> <new_name>`. Preview them one-off before committing; they remain rejected from `batch` so each symbol rename has an explicit readback boundary.
Add `--propagate-callers` when you want `function prototype set` to also apply the new callee type at matching caller call sites.
Use `function prototype check` first when the declaration uses custom calling conventions, usercall annotations, or newly imported support types.
Use `type check` before large imports; use `type deps <name>` after import when the dependency-expanded declaration is the clearest audit artifact.

Post-mutation readback commands:

```bash
idac function prototype show "sub_08041337"
idac function locals list "sub_08041337"
idac type struct show "ExampleStruct"
idac type enum show "ExampleEnum"
idac type class show "ExampleDerived"
idac type class vtable "ExampleDerived" --runtime
idac decompile "ExampleDerived__method_1" --f5
```

When you need pseudocode for a whole family, prefer bulk decompile over many one-off `decompile` calls.
- Use `decompilemany "<function-filter>" --f5 --out-dir ...` for name-filtered recovery discovery.
- For multiple explicit functions, write one function name or address per line and use `decompilemany --functions-file ... --f5 --out-dir ...`.
The command writes one `.c` artifact per function plus `manifest.json`. Add `--disasm` or `--ctree` when the same selected functions also need disassembly or Hex-Rays tree artifacts. Treat `manifest.json` as the source of truth for full function names, exact addresses, and artifact paths when long names need shortened filenames. Use `.functions[].address` as the stable exact lookup key.
For symbol-rich families, run one `decompilemany "<family>" --f5 --out-dir ...` capture before the first mutation so you can grep every constructor, destructor, parser, and helper locally. After import and reanalysis, redecompile only the functions you must verify (with `--f5`); do not redo the family-wide dump.
During type or prototype recovery, prefer `decompile --f5` and `decompilemany --f5` so discovery and verification artifacts reflect the latest imported types and prototype changes.
For ordinary exploration and routine readback, rerun a one-off decompile with `--f5` or `--no-cache` only when the output looks stale after reanalysis.
If the default `type declare` parser rejects template-heavy or newer C++ syntax, retry the same import with `--clang`.
When a multi-declaration import fails and the error does not name the culprit, rerun it once with `--bisect` before editing the header by hand:

```bash
idac type declare --replace --bisect --decl-file "recovered_classes.h"
```

That reports the first declaration IDA rejects by line range, says whether it imports on its own, and names by-value members whose types are still opaque. When it imports alone, the failure is ordering: declare the missing support type earlier in the same file. `type check` does not accept `--bisect`.
Before rename-heavy cleanup, fix the shared helper prototypes that dominate the caller bodies, then reanalyze those callers and reread the locals. Prototype cleanup usually improves trustworthiness more than cosmetic renames do.

## Narrow type edits

Once a local struct or enum is close to correct, fix one member at a time instead of re-importing the whole header:

```bash
idac type struct show "ExampleStruct"
idac preview -o "/tmp/field_preview.json" type struct field set "ExampleStruct" "entry_count" --offset 0x18 --decl "unsigned int"
idac type struct field set "ExampleStruct" "entry_count" --offset 0x18 --decl "unsigned int"
idac type struct field rename "ExampleStruct" "field_20" "flags"
idac type enum member set "ExampleEnum" "EXAMPLE_FLAG_RETRY" --value 0x4
```

These commands are preview-capable and batch-safe, and each returns the refreshed struct or enum, so the command output doubles as the readback. `--offset` is a byte offset: an existing field at that exact offset is retyped and renamed, and any other offset adds a field. Reanalyze the functions that use the type afterward, the same as for any other type change.
Prefer `type declare --replace` instead when the layout shifts broadly, when several fields move at once, or when the recovered header is the artifact you want to keep. For the full grammar, read [cli.md](cli.md#struct-field-and-enum-member-edits).

## Record findings in the database

Findings that belong to a specific address survive better in the database than in local notes:

```bash
idac comment set "sub_08041337" "parses the record header; len is attacker-controlled" --scope function
idac comment set "0x100000460" "bounds check happens after the copy" --scope line
idac bookmark add "0x100000460" --comment "missing bounds check"
```

`comment set`/`comment delete` and the mutating `bookmark` commands are preview-capable and batch-safe, so they can close out a recovery batch alongside the readback steps. Keep inferred semantics marked as inferred in the comment text, the same rule as for names and types.

## Selector calibration

```bash
idac function locals list "sub_08041337" --json
idac function locals list "sub_08041337" --json --out "/tmp/locals.json"
idac preview -o "/tmp/local_rename_index_preview.json" function locals rename "sub_08041337" "3" --new-name "value_maybe"
idac preview -o "/tmp/local_rename_id_preview.json" function locals rename "sub_08041337" --local-id "stack(16)@0x100000460" --new-name "value_maybe"
idac preview -o "/tmp/local_plan_preview.json" function locals apply "sub_08041337" --json-file "locals-plan.json"
```

Keep whichever stable selector readbacks cleanly, then use that selector style for the rest of the pass.
If one committed rename misses, stop immediately, reread locals, and recalibrate before continuing.
When using `--local-id` or `--index`, do not combine them with a positional selector.
`function locals list --json` emits the canonical `local_id` string in `<location>@<defea>` form. Copy that exact text for stable-selector mode.
If the locals list is too large to inspect inline, add `--out` and read the JSON artifact locally instead of forcing the terminal buffer.

Example `locals-plan.json` for `function locals apply`:

```json
[
  {"local_id": "stack(16)@0x100000460", "rename": "value_count", "decl": "unsigned int value_count;"},
  {"index": 7, "type": "ExampleStruct *"}
]
```

Local rename caution:

- The current local name is an acceptable selector only for a one-off rename before anything has shifted. For rename batches, and for any rename after a prototype change or reanalysis, capture fresh `function locals list --json` output and select by the exact `local_id` or `index` values it reports — never queue name-only rename batches across mutation phases.
- After each committed rename, reread `function locals list --json` and confirm the intended `index` or `local_id` now shows the new name. Work one function at a time, with a fresh reread between functions.
- Prefer `function locals update` when one local needs both a recovered name and a recovered type in the same pass
- Prefer `function locals apply --json-file` when several locals in one function need coordinated renames or retypes from one fresh locals snapshot
- For `function locals retype`, use `--type` for simple spellings such as `unsigned int` or `ExampleStruct *`. Use `--decl` or `--decl-file` when the retype needs a full declaration, such as arrays or function pointers.
- Use `--decl` for small one-off edits; prefer `--decl-file` in batch files and other long mutation passes
- Prefer `jq` or `sed` for shell inspection of JSON artifacts instead of assuming bare `python` exists
  Example: `idac function locals list "sub_08041337" --json | jq -r '.locals[] | [.index, .local_id, .display_name, .type] | @tsv'`

## Batch

```bash
idac batch "recovery-prototype-preview.idac" --lint --out "/tmp/recovery-prototype-preview.lint.json"
idac batch "recovery-prototype-preview.idac" --fail-fast --out "/tmp/recovery-prototype-preview.json"
jq . "/tmp/recovery-prototype-preview.json"
idac batch "recovery-prototype-commit.idac" --lint --out "/tmp/recovery-prototype-commit.lint.json"
idac batch "recovery-prototype-commit.idac" --fail-fast --out "/tmp/recovery-prototype-commit.json"
```

Batch files should:

- use one `idac` subcommand per line
- omit the leading `idac`
- omit `-c`, `--instance`, and `--timeout`; target and timeout options belong on the wrapper and are rejected on child commands
- use child `--format` / `--json` only when useful; for a read-only child with `--out`, it controls that child's artifact serialization unless a `.json` or `.jsonl` suffix selects that structured format
- omit per-command `--out` for mutation logging; mutating child `--out` is rejected, while read-only children may use it for their own artifacts
- prefer `--decl-file` for long type or prototype text
- always pass `--out` to `batch` so the full step log is captured in a stable artifact
- add `--fail-fast` when later steps depend on earlier checks, previews, or mutations, and for local rename/retype passes that must stop on the first miss
- never place a preview and its matching commit in the same batch; inspect the completed preview journal before launching the commit batch
- keep related `--decl-file`, `--functions-file`, and explicit child artifact paths next to the batch file; relative child paths are resolved from the batch file directory
- prefer one ordered `batch` file over multiple background `idac` processes for mutation passes
- mutating batches without wrapper `batch --out` are rejected before execution
- run `batch --lint --out <path>` before executing mutation batches; lint resolves relative paths, catches command-line parse errors, rejects unsupported batch commands, and warns on risky name-only local selectors after type/prototype/reanalysis phases

```text
# recovery-prototype-preview.idac -- support types already imported
function prototype show "ExampleDerived__method_1"
function prototype check "ExampleDerived__method_1" --decl-file "example_method_1.h"
preview function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
```

Inspect the preview journal before running the matching commit file:

```text
# recovery-prototype-commit.idac
function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
misc reanalyze "ExampleDerived__method_1"
function locals list "ExampleDerived__method_1" --json --out "example_method_1.locals.json"
```

For a type import in batch, use the same separation: `type check` and `preview type declare` in a preview file, inspect its journal, and put `type declare` in the commit file. Declare support types before previewing prototypes that depend on them.

Inspect the fresh locals artifact from the prototype commit and create the local plan before starting a separate cleanup preview:

```text
# recovery-locals-preview.idac
preview function locals apply "ExampleDerived__method_1" --json-file "example_method_1_locals.json"
```

Lint and run that preview with `--fail-fast`, inspect its journal, then run the commit file:

```text
# recovery-locals-commit.idac
function locals apply "ExampleDerived__method_1" --json-file "example_method_1_locals.json"
```

`batch` keeps ordered logging while reusing one Nexus handle for the selected context.
Each step remains a separate operation within that session.
The wrapper artifact starts as `pending`, is checkpointed after every completed line, and becomes terminal only after the Nexus session closes. Ctrl-C writes an `interrupted` terminal record and exits 130.
For larger prototype and local-rename passes, prefer `batch` so the mutation order is explicit and the run leaves behind a stable ordered log.
Keep type/prototype mutation and post-reanalysis local cleanup in separate batches. Build the local cleanup plan from the fresh locals artifact produced after reanalysis, run its preview batch with `--fail-fast`, inspect the completed journal, and only then run its commit batch with `--fail-fast`.
`setup gui` is intentionally rejected from `batch`, and so is `misc rename` — preview
and commit symbol renames one-off. `misc reanalyze` is
batch-safe and belongs between type/prototype mutations and local cleanup in full
recovery batches.

## Broad discovery defaults

- Use `--json --out <path>` by default for `type class candidates`
- If you only want functions, vtables, or RTTI from `type class candidates`, add `--kind` instead of post-filtering a broad mixed list
- Prefer IDA-side filters for broad function discovery: `function list "name1|name2" --regex -i --json --out <path>`, adding `--demangle` when matching display names
- Avoid piping a full unfiltered `function list --demangle` through shell tools unless you genuinely need the whole list locally
- For large `function locals list` runs, prefer `--json --out <path>` so the canonical `local_id` data stays readable after reanalysis drift
- For rename previews on large functions, write the preview to disk with `preview -o ...`, then inspect that JSON artifact with `jq`; standalone preview does not print the payload inline
- The equivalent family reads are `function list [NAME_FILTER]`, `type list [TYPE_FILTER]`, and `type class candidates [CANDIDATE_FILTER]` with optional `--regex` and `-i`
- For strings, scan the relevant segment first with `search strings --scan --segment ...`, then read defined strings back with `search strings [TEXT_FILTER] --segment ... --timeout 30`; see [cli.md](cli.md) for the required flags and dyld-shared-cache limits
- Use `--out <path>` by default for wide string scans on real binaries
- For scoping class-family discovery, read [class-recovery.md](class-recovery.md)

Binary-only analysis mode: bias toward strings, RTTI, vtables, demangled symbols, local types, and call behavior. Do not assume external source, headers, or online lookup.

## Structural inspection and reanalysis

```bash
idac ctree "sub_08041337"
idac ctree "sub_08041337" --level micro --maturity generated
idac misc reanalyze "sub_08041337"
idac decompile "sub_08041337" --f5
```

Mandatory checkpoint:

- after major type or prototype mutations, run `misc reanalyze`
- do that before local renames
- then reread pseudocode or locals instead of assuming propagation
- if callers still show stale casts or bad `this` propagation, reanalyze those callers too and reread them before declaring the pass done
- treat return-type changes as higher risk than parameter-name or local-name changes; if the body does not clearly prove the return value, leave it generic
- stop when the structure, call behavior, and safety-relevant data flow are readable; do not chase perfect pseudocode once the remaining problems are clearly presentation-only
