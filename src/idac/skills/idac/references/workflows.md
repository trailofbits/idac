# Common Workflows

Read this for safe mutation, batch, selector calibration, broad discovery, and post-mutation readback.

## Contents

- [Inspect an open GUI target](#inspect-an-open-gui-target)
- [Open a binary](#open-a-binary)
- [Work from an existing database file](#work-from-an-existing-database-file)
- [Recover type information around a function](#recover-type-information-around-a-function)
- [Recover C++ class information](#recover-c-class-information)
- [Safe mutation loop](#safe-mutation-loop)
- [Selector calibration](#selector-calibration)
- [Batch](#batch)
- [Broad discovery defaults](#broad-discovery-defaults)
- [Structural inspection and reanalysis](#structural-inspection-and-reanalysis)

## Inspect an open GUI target

```bash
idac doctor
idac targets list --json
idac function metadata "sub_08041337" -c "pid:<pid>"
idac decompile "sub_08041337" -c "pid:<pid>"
idac decompile "sub_08041337" -o "/tmp/sub_08041337.txt" -c "pid:<pid>"
idac xrefs "sub_08041337" -c "pid:<pid>"
```

If only one IDA GUI window is open, you can often omit `-c`.
If target discovery is failing rather than merely unknown, read [targets-and-backends.md](targets-and-backends.md) or [troubleshooting.md](troubleshooting.md) before treating diagnostics as part of the normal read workflow.

Live GUI notes:

- if a command will be parsed, use `--json`
- for parsed-read and `--out` defaults, read [cli.md](cli.md)
- for a single large decompile, use `-o/--out` on `decompile`; reserve `--out-file` and `--out-dir` for `decompilemany`
- run one `idac` command at a time per GUI target; the bridge serializes requests internally, and background parallel commands can fill the queue or make mutation ordering unclear

## Open a binary

For detailed context selection and first-time import guidance, read [targets-and-backends.md](targets-and-backends.md).

```bash
idac database open "/path/to/binary" --json
idac targets list --json
idac database show -c "db:/path/to/binary" --json
idac decompile "main" -c "db:/path/to/binary" --f5
```

## Work from an existing database file

```bash
idac doctor
idac database show -c "db:sample.i64"
idac decompile "sub_08041337" -c "db:sample.i64"
idac decompile "sub_08041337" --f5 -c "db:sample.i64"
idac decompilemany "sub_0804" --out-dir "/tmp/function_decompile" -c "db:sample.i64"
idac ctree "sub_08041337" -c "db:sample.i64"
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
idac function prototype check "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
```

The positional local selectors in these previews are for pre-reanalysis one-off checks. After `misc reanalyze`, committed rename or retype batches should switch to `--index` or `--local-id`; see [Selector calibration](#selector-calibration).

Then commit the real change and read it back:

```bash
idac function prototype set "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
idac function prototype show "sub_08041337"
idac decompile "sub_08041337"
```

Symbol renames go through `misc rename <identifier> <new_name>`, which is rejected from both `batch` and `preview`: check the current name first (`function metadata`), commit the rename one-off, and confirm with readback.
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
idac decompile "ExampleDerived__method_1"
```

When you need pseudocode for a whole family, prefer bulk decompile over many one-off `decompile` calls.
- Use `decompilemany "<function-filter>" --out-dir ...` for name-filtered discovery.
- For multiple explicit functions, write one function name or address per line and use `decompilemany --functions-file ... --out-dir ...`.
The command writes one `.c` artifact per function plus `manifest.json`. Add `--disasm` or `--ctree` when the same selected functions also need disassembly or Hex-Rays tree artifacts. Treat `manifest.json` as the source of truth for full function names, exact addresses, and artifact paths when long names need shortened filenames. Use `.functions[].address` as the stable exact lookup key.
For symbol-rich families, run one `decompilemany "<family>" --out-dir ...` capture before the first mutation so you can grep every constructor, destructor, parser, and helper locally. After import and reanalysis, redecompile only the functions you must verify (with `--f5`); do not redo the family-wide dump.
During type or prototype recovery, prefer `decompile --f5` and `decompilemany --f5` so discovery and verification artifacts reflect the latest imported types and prototype changes.
For ordinary exploration and routine readback, rerun a one-off decompile with `--f5` or `--no-cache` only when the output looks stale after reanalysis.
If legacy `type declare` import rejects template-heavy or newer C++ syntax, retry the same import with `--clang`.
Before rename-heavy cleanup, fix the shared helper prototypes that dominate the caller bodies, then reanalyze those callers and reread the locals. Prototype cleanup usually improves trustworthiness more than cosmetic renames do.

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
idac batch "recovery.idac" --out "/tmp/recovery_batch.json"
idac batch "recovery.idac" --lint --out "/tmp/recovery_batch_lint.json"
```

Batch files should:

- use one `idac` subcommand per line
- omit the leading `idac`
- omit `-c`, `--timeout`, and `--format`
- omit per-command `--out` for mutation logging; use child `--out` only when that specific read command must write its own artifact
- prefer `--decl-file` for long type or prototype text
- always pass `--out` to `batch` so the full step log is captured in a stable artifact
- keep related `--decl-file`, `--functions-file`, and explicit child artifact paths next to the batch file; relative child paths are resolved from the batch file directory
- prefer one ordered `batch` file over multiple background `idac` processes for mutation passes
- mutating batches without wrapper `batch --out` are rejected before execution
- run `batch --lint --out <path>` before executing mutation batches; lint resolves relative paths, catches parse errors, rejects unsupported batch commands, and warns on risky name-only local selectors after type/prototype/reanalysis phases

```text
# recovery.idac
type check --decl-file "recovered_classes.h"
type declare --replace --decl-file "recovered_classes.h"
function prototype check "ExampleDerived__method_1" --decl-file "example_method_1.h"
function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
misc reanalyze "ExampleDerived__method_1"
function locals update "ExampleDerived__method_1" --local-id "stack(16)@0x100000460" --rename "value_maybe" --decl-file "example_local.h"
function locals apply "ExampleDerived__method_1" --json-file "example_method_1_locals.json"
function locals rename "ExampleDerived__method_1" --index 6 --new-name "entry_count"
function locals retype "ExampleDerived__method_1" --index 7 --decl-file "example_local_7.h"
preview function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
```

For `idalib`, `batch` keeps ordered logging while reusing the same open database state for the shared `-c db:<path>` locator. Each step is still a separate request.
For larger prototype and local-rename passes, prefer `batch` so the mutation order is explicit and the run leaves behind a stable ordered log.
Setup-only `misc` commands such as `misc plugin install` and `misc skill install` are intentionally rejected from `batch`, and so is `misc rename` — commit symbol renames one-off. `misc reanalyze` is batch-safe and belongs between type/prototype mutations and local cleanup in full recovery batches.

## Broad discovery defaults

- Use `--json --out <path>` by default for `type class candidates`
- If you only want functions, vtables, or RTTI from `type class candidates`, add `--kind` instead of post-filtering a broad mixed list
- Prefer IDA-side filters for broad function discovery: `function list "name1|name2" --regex -i --json --out <path>`, adding `--demangle` when matching display names
- Avoid piping a full unfiltered `function list --demangle` through shell tools unless you genuinely need the whole list locally
- For large `function locals list` runs, prefer `--json --out <path>` so the canonical `local_id` data stays readable after reanalysis drift
- For rename previews on large functions, write the preview to disk with `preview -o ...`, then inspect the JSON with `jq` instead of trusting the inline summary alone
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
idac decompile "sub_08041337"
```

Mandatory checkpoint:

- after major type or prototype mutations, run `misc reanalyze`
- do that before local renames
- then reread pseudocode or locals instead of assuming propagation
- if callers still show stale casts or bad `this` propagation, reanalyze those callers too and reread them before declaring the pass done
- treat return-type changes as higher risk than parameter-name or local-name changes; if the body does not clearly prove the return value, leave it generic
- stop when the structure, call behavior, and safety-relevant data flow are readable; do not chase perfect pseudocode once the remaining problems are clearly presentation-only
