# Common Workflows

This file documents the current public `idac` workflows.

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
- when you want cross-references, use the top-level `xrefs` command rather than looking for a `function xrefs` subcommand
- for a single large decompile, use `-o/--out` on `decompile`; reserve `--out-file` and `--out-dir` for `decompilemany`
- run one `idac` command at a time per GUI target; the bridge serializes requests internally, and background parallel commands can fill the queue or make mutation ordering unclear

## Open a binary

```bash
idac database open "/path/to/binary" --json
idac targets list --json
idac database show -c "db:/path/to/binary" --json
idac decompile "main" -c "db:/path/to/binary" --f5
```

For large binaries or first-time autoanalysis, omit `--timeout` so the import can block indefinitely unless the user asked for a deadline. Do not wrap this import in a shell-level timeout or a tool-call timeout; let the command keep running and poll the session if your tool supports incremental output. `targets list --json` should show a `backend: "idalib"` row for the opened path. If the raw import does not name `main`, decompile `start_ea` / `entry_ea` from `database show --json` or an address from `function list --json`. If the target has multiple architectures, provide the intended architecture slice so IDA does not need an interactive loader choice.

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
idac preview -o "/tmp/local_rename_preview.json" function locals rename "sub_08041337" "v12" --new-name "value_maybe"
idac preview -o "/tmp/local_retype_preview.json" function locals retype "sub_08041337" "v4" --type "unsigned int"
idac preview -o "/tmp/local_retype_decl_preview.json" function locals retype "sub_08041337" "v4" --decl "unsigned int v4;"
idac preview -o "/tmp/local_retype_file_preview.json" function locals retype "sub_08041337" "v4" --decl-file "local_v4.h"
idac preview -o "/tmp/type_preview.json" type declare --decl "typedef struct ExampleStruct { int field_0; } ExampleStruct;"
idac preview -o "/tmp/type_replace_preview.json" type declare --replace --decl-file "recovered_classes.h"
idac preview -o "/tmp/type_clang_preview.json" type declare --clang --decl-file "recovered_templates.hpp"
```

Then commit the real change and read it back:

```bash
idac function prototype set "sub_08041337" --decl "int __fastcall sub_08041337(void *ctx, const unsigned char *buf, unsigned int len)"
idac function prototype show "sub_08041337"
idac decompile "sub_08041337"
```

Add `--propagate-callers` when you want `function prototype set` to also apply the new callee type at matching caller call sites.

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
The command writes one `.c` artifact per function plus `manifest.json`. Add `--disasm` or `--ctree` when the same selected functions also need disassembly or Hex-Rays tree artifacts.
For symbol-rich families, one early discovery capture can be worthwhile before mutations so you can grep every constructor, destructor, parser, and helper locally.
After type import and reanalysis, rerun a narrower verification capture only if the broad artifact is still useful.
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
```

Keep whichever stable selector readbacks cleanly, then use that selector style for the rest of the pass.
If one committed rename misses, stop immediately, reread locals, and recalibrate before continuing.
When using `--local-id` or `--index`, do not combine them with a positional selector.
`function locals list --json` emits the canonical `local_id` string in `<location>@<defea>` form. Copy that exact text for stable-selector mode.
If the locals list is too large to inspect inline, add `--out` and read the JSON artifact locally instead of forcing the terminal buffer.

Local rename caution:

- After major prototype or reanalysis changes, reread `function locals list` before more renames
- Before a rename batch, capture `function locals list --json` and copy exact `local_id` or `index` values instead of guessing local names from stale pseudocode
- Prefer `function locals update` when one local needs both a recovered name and a recovered type in the same pass
- Prefer current local name for straightforward one-off renames. Prefer `--local-id` or `--index` once prototypes or reanalysis may have shifted the local set.
- For `function locals retype`, use `--type` for simple spellings such as `unsigned int` or `ExampleStruct *`. Use `--decl` or `--decl-file` when the retype needs a full declaration, such as arrays or function pointers.
- Do not queue large rename batches by name alone across major mutation phases
- After each committed rename, reread `function locals list --json` and confirm the specific `index` or `local_id` moved to the expected name
- After reanalysis, use `--local-id` or `--index` for every committed rename
- Split rename work per function, and reread `function locals list --json` between functions
- Use `--decl` for small one-off edits; prefer `--decl-file` in batch files and other long mutation passes
- Prefer `jq` or `sed` for shell inspection of JSON artifacts instead of assuming bare `python` exists
  Example: `idac function locals list "sub_08041337" --json | jq -r '.locals[] | [.index, .local_id, .name, .type] | @tsv'`

## Batch

```bash
idac batch "recovery.idac" --out "/tmp/recovery_batch.json"
```

Batch files should:

- use one `idac` subcommand per line
- omit the leading `idac`
- omit `-c`, `--timeout`, `--format`, and `--out`
- prefer `--decl-file` for long type or prototype text
- always pass `--out` to `batch` so the full step log is captured in a stable artifact
- keep related `--decl-file`, `--file`, and per-line `--out` paths next to the batch file; relative child paths are resolved from the batch file directory
- prefer one ordered `batch` file over multiple background `idac` processes for mutation passes

```text
# recovery.idac
type declare --replace --decl-file "recovered_classes.h"
function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
function locals update "ExampleDerived__method_1" "v12" --rename "value_maybe" --decl-file "example_local.h"
function locals rename "ExampleDerived__method_1" "v12" --new-name "value_maybe"
function locals retype "ExampleDerived__method_1" "value_maybe" --decl-file "example_local.h"
preview function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
```

For `idalib`, `batch` keeps ordered logging while reusing the same open database state for the shared `-c db:<path>` locator. Each step is still a separate request.
For larger prototype and rename passes, prefer `batch` so the mutation order is explicit and the run leaves behind a stable ordered log.
Maintenance `misc` commands such as `misc reanalyze` are intentionally rejected from `batch`, so keep maintenance steps outside the saved batch file.

## Broad discovery defaults

- Use `--json --out <path>` by default for `type class candidates`
- If you only want functions, vtables, or RTTI from `type class candidates`, add `--kind` instead of post-filtering a broad mixed list
- Prefer IDA-side filters for broad function discovery: `function list "name1|name2" --regex -i --json --out <path>`, adding `--demangle` when matching display names
- Avoid piping a full unfiltered `function list --demangle` through shell tools unless you genuinely need the whole list locally
- For large `function locals list` runs, prefer `--json --out <path>` so the canonical `local_id` data stays readable after reanalysis drift
- For rename previews on large functions, write the preview to disk with `preview -o ...`, then inspect the JSON with `jq` instead of trusting the inline summary alone
- The equivalent family reads are `function list [NAME_FILTER]`, `type list [TYPE_FILTER]`, and `type class candidates [CANDIDATE_FILTER]` with optional `--regex` and `-i`
- For strings, always pass both `--timeout` and `--segment`, and scan the relevant segment first with `search strings --scan --segment ...`
- After a scan identifies the relevant region or token, use `search strings [TEXT_FILTER] --segment ... --timeout 30` for defined-string readback
- For dyld shared caches, skip defined-string readback and keep `search strings --scan` ranges at 16 MiB or smaller
- Use `--out <path>` by default for wide string scans on real binaries
- Start with confirmed family members first, then widen to callers or adjacent helpers only when the readback requires it
- If symbols and RTTI already identify the family clearly, skip `type class candidates` and go straight to direct family reads

Binary-only analysis mode: bias toward strings, RTTI, vtables, demangled symbols, local types, and call behavior. Do not assume external source, headers, or online lookup.

## Structural inspection and reanalysis

```bash
idac ctree "sub_08041337"
idac ctree "sub_08041337" --level micro --maturity generated
idac misc reanalyze "sub_08041337"
idac decompile "sub_08041337"
```

Mandatory checkpoint:

- after major type or prototype mutations, run `reanalyze`
- do that before local renames
- then reread pseudocode or locals instead of assuming propagation
- if callers still show stale casts or bad `this` propagation, reanalyze those callers too and reread them before declaring the pass done
- treat return-type changes as higher risk than parameter-name or local-name changes; if the body does not clearly prove the return value, leave it generic
- for embedded opaque members, use field-offset subtraction first to estimate size and only then use constructor decompilation as confirmation
- if large-stack AArch64 functions still show suspicious top-of-function value flow after prototype cleanup and reanalysis, treat that as a likely decompiler artifact rather than a reason to keep forcing types
- stop when the structure, call behavior, and safety-relevant data flow are readable; do not chase perfect pseudocode once the remaining problems are clearly presentation-only
