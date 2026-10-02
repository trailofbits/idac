# Mutation and Recovery Workflows

Read this for database edits, selector calibration, batch authoring, and IDAPython.
For target selection and save behavior, use [targets and backends](targets-and-backends.md).

## Contents

- [Safe mutation loop](#safe-mutation-loop)
- [Selector calibration](#selector-calibration)
- [Narrow type edits](#narrow-type-edits)
- [Record findings in the database](#record-findings-in-the-database)
- [Batch](#batch)
- [Broad discovery defaults](#broad-discovery-defaults)
- [Structural inspection and reanalysis](#structural-inspection-and-reanalysis)
- [IDAPython escape hatch](#idapython-escape-hatch)

## Safe mutation loop

Apply the parts relevant to the requested edit:

1. Read the current state and establish the evidence for the change. Before
   `function prototype set`, run `function prototype show`. Validate custom
   calling conventions with `function prototype check`, or use it when validation
   itself is requested. A prototype preview already validates ordinary type edits.
   For headers replacing existing types, preview `type declare --replace` directly;
   it validates the actual replacement and provides before/after data. A separate
   `type check` is useful when validation itself is requested or before a new import.
2. Declare missing support types before dependent prototypes. Start uncertain
   types with minimal structs or placeholders. Importing a type in a preview does
   not make it available to a later prototype preview: preview rolls it back.
3. Preview parser-risky type/prototype edits and uncertain local selectors, then
   inspect `before`, `after`, and `undo`. Confirmed symbol renames, comments, and
   parameter-name edits with `--preserve-cc` can be committed directly and read
   back. Standalone `preview` requires `-o/--out` and prints
   only the artifact location. Commit the inspected change within the user's
   existing authorization; preview inspection is an agent verification step.
4. After meaningful type or prototype changes, run `misc reanalyze` on affected
   functions, then reread pseudocode with `--f5`. Reanalyze callers too when their
   casts or `this` types still look stale.
5. Build local cleanup from fresh locals JSON after reanalysis; see
   [selector calibration](#selector-calibration). Verify the committed state.

Prototype example, with support types already available:

```bash
idac function prototype show "sub_08041337"
idac function prototype check "sub_08041337" --decl-file "sub_08041337_proto.h"
idac preview -o "proto.preview.json" function prototype set "sub_08041337" --decl-file "sub_08041337_proto.h"
jq . proto.preview.json
```

After inspecting the preview:

```bash
idac function prototype set "sub_08041337" --decl-file "sub_08041337_proto.h"
idac misc reanalyze "sub_08041337"
idac function prototype show "sub_08041337"
idac decompile "sub_08041337" --f5
```

Keep the chosen `-c` or `--instance` on these invocations; examples omit it for
readability. On `preview` and `batch`, put it on the wrapper.

Use `--propagate-callers` on `function prototype set` when the task calls for
applying the callee type at matching caller call sites. Return-type changes need
body or caller evidence; retain a generic type when that evidence is insufficient.

For declaration failures, use [troubleshooting](troubleshooting.md). In particular,
an unexplained multi-declaration `type declare` failure warrants one `--bisect`
diagnostic before hand-editing the header; `type check` does not accept `--bisect`.

For straightforward coordinated function renames, prototype edits, and comments, put the known
commands and final readbacks in an ordered `batch --fail-fast --out` file.
Use addresses for functions whose names change during the pass.
Read-only inspections and plain prototype/name changes do not need duplicate
IDAPython verification. Preserve the prototype's calling convention and parameter
types by editing its displayed declaration. Fresh pseudocode is needed when the
task depends on decompiler propagation; a comment-only edit needs comment readback.
Use `function prototype set --preserve-cc` for a parameter-name or return-type edit
that must keep the current ABI. IDA can normalize a parsed `__cdecl` declaration
to `__fastcall`; this flag copies the existing convention into the parsed type
before applying it, avoiding a scripted type edit. Omit it when changing the
calling convention is part of the request.

## Selector calibration

Capture locals after the last prototype/type change and reanalysis:

```bash
idac function locals list "sub_08041337" --json --out "locals.json"
jq -r '.locals[] | [.index, .local_id, .display_name, .type] | @tsv' locals.json
idac preview -o "local.preview.json" function locals rename "sub_08041337" --index 3 --new-name "value_count"
```

Replace the sample index with one from the fresh JSON. Alternatively copy the exact
`local_id` in `<location>@<defea>` form and use `--local-id`. Do not combine either
flag with a positional selector. Current names are suitable for one-off edits
before the local set shifts; use explicit IDs or indices for batches and after
prototype changes or reanalysis. Neither selector is guaranteed to survive another
reanalysis.

For coordinated edits to one function, prefer `function locals apply --json-file`
with a plan derived from that snapshot:

```json
[
  {"local_id": "stack(16)@0x100000460", "rename": "value_count", "decl": "unsigned int value_count;"},
  {"index": 7, "type": "ExampleStruct *"}
]
```

Replace every sample selector and type before use:

```bash
idac preview -o "locals.preview.json" function locals apply "sub_08041337" --json-file "locals-plan.json"
```

Inspect the full before/after lists, then commit and reread `function locals list
--json` to confirm the selected locals. Stop on the first miss, refresh locals, and
recalibrate before continuing. For individual renames, verify each commit; for an
apply plan, verify the full resulting list. Work one function at a time.

Use `function locals update` for a single rename plus retype. `retype --type`
accepts simple spellings; use `--decl` or `--decl-file` for arrays, function pointers,
or full declarations. More examples are in the optional
[templates](templates/README.md).

## Narrow type edits

For a small correction to an existing struct or enum, edit the member directly:

```bash
idac type struct show "ExampleStruct"
idac preview -o "field.preview.json" type struct field set "ExampleStruct" "entry_count" --offset 0x18 --decl "unsigned int"
```

Inspect the preview, then commit the same field edit. `--offset` is a byte offset:
an existing field there is retyped and renamed; another offset adds a field.
Member edits return the refreshed type as readback. Reanalyze functions that use
the changed type. For a broad layout change or a maintained recovered header, use
`type declare --replace` instead. See [member command syntax](cli.md#struct-field-and-enum-member-edits).

## Record findings in the database

When annotation is part of the task, associate evidence with its address using
`comment set` or `bookmark add`. These are preview-capable and batch-safe:

```bash
idac comment set "sub_08041337" "parses the record header" --scope function
idac comment show "sub_08041337" --scope function
```

For a confirmed address and annotation, commit and read back directly; use preview
when the selector or mutation scope is uncertain. Mark inferred semantics explicitly.
For read-only analysis, place findings in the requested report or notes.

## Batch

Use one ordered batch for related operations on the same target. Lint mutation
batches before execution and fix reported issues. When previews are needed,
separate preview and commit files so the journal can be inspected first. For
confirmed renames, comments, and parameter-name edits, one commit batch with
final readbacks is sufficient.

With support types already imported:

```text
# recovery-prototype-preview.idac
function prototype show "ExampleDerived__method_1"
function prototype check "ExampleDerived__method_1" --decl-file "example_method_1.h"
preview function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
```

```text
# recovery-prototype-commit.idac
function prototype set "ExampleDerived__method_1" --decl-file "example_method_1.h"
misc reanalyze "ExampleDerived__method_1"
function locals list "ExampleDerived__method_1" --json --out "example_method_1.locals.json"
```

```bash
idac batch "recovery-prototype-preview.idac" --lint --out "prototype-preview.lint.json"
idac batch "recovery-prototype-preview.idac" --fail-fast --out "prototype-preview.json"
jq . prototype-preview.json
```

After inspecting every preview, lint and run the commit file with `--fail-fast`
and a separate `--out`. Build the local plan from the commit's fresh locals
artifact, then preview and commit that cleanup in separate batches.

Batch grammar and lifecycle:

- One subcommand per line, without the leading `idac`; blank lines and `#`
  comments are allowed.
- `-c`, `--instance`, and `--timeout` belong on the wrapper and are rejected on
  child commands. The wrapper timeout is inherited by child validation.
- Wrapper `--out` is required for persistent mutations. Mutating children cannot
  set `--out`; read-only children may write their own artifacts.
- Relative `--decl-file`, `--json-file`, `--functions-file`, and child output paths
  resolve from the batch file's directory. Keep related files together.
- Child `--json` / `--format` controls read-only artifact serialization unless a
  `.json` or `.jsonl` suffix selects the structured format.
- Use `--fail-fast` for dependencies and local cleanup so execution stops on a
  failed check or selector miss. Lint catches parse errors, missing input files,
  unsupported commands, and risky name-only local selectors.
- `misc rename` is batch-safe and preview-capable; use addresses when names change
  during the batch. `setup gui` is rejected. `misc reanalyze` is batch-safe and
  not preview-capable.
- Batch reuses one Nexus session. Its journal starts `pending`, checkpoints each
  completed line, and becomes terminal after session close. Ctrl-C records
  `interrupted` and exits 130.
- A batch is not a transaction: earlier successful headless mutations remain saved
  if a later step fails. Reread state before resuming an interrupted pass.

## Broad discovery defaults

Use filtered reads to obtain enough evidence for the task:

- `function list "name1|name2" --regex -i --json --out <path>` filters in IDA.
  Add `--demangle` when matching display names.
- `type list [TYPE_FILTER]` and `type class candidates [CANDIDATE_FILTER]` support
  filters too. Use `--kind` on class candidates when only one row category matters.
  An unfiltered type list requires `--out`.
- Search already-defined strings with `search strings`. Use `--scan` when
  string-like bytes are not defined in the database; scanning does not define
  them. Both string and byte searches require `--segment` and `--timeout`.
  Dyld shared caches require a bounded string scan of at most 16 MiB; see
  [CLI search notes](cli.md#common-reads).
- For a family you need to inspect locally, use `decompilemany "<family>" --f5
  --out-dir ...`. For an exact selection, use `--functions-file` with one name or
  address per line. Add `--disasm` or `--ctree` when those artifacts help.
- `manifest.json` records exact addresses, full names, failures, and artifact
  paths. Use `.functions[].address` for exact lookups when long filenames are
  shortened. After mutations, redecompile the functions needed for verification;
  repeat the family capture only if its scope or evidence needs updating.
- Type, function, and candidate lists are top-level JSON arrays (`.[]`); locals
  are wrapped under `.locals[]`.

## Structural inspection and reanalysis

Use `ctree <function>` for Hex-Rays tree inspection, or `ctree <function> --level
micro --maturity generated` for microcode. After type changes, reanalysis and
fresh pseudocode distinguish a propagation problem from presentation noise.
Continue until the requested data flow or type relationships are supported; avoid
cosmetic cleanup that does not improve the result.

## IDAPython escape hatch

Use a small explicit script when first-class commands do not cover the operation.
Use `--script` or a quoted heredoc with `--stdin` for multiline Python; keep
`--code` to simple expressions so shell escaping does not become Python syntax.

```bash
idac py exec --code "result = {'imagebase': hex(idaapi.get_imagebase())}"
idac py exec --script "inspect_slots.py" --json --out "slots.json"
```

Supported inputs are `--code`, `--stdin`, and `--script`, with a fresh namespace
per execution. Core `ida*` modules, `idautils`, `idc`, and `result` are available
when their imports succeed; import other required IDA modules explicitly. Assign
JSON-native data to `result` for structured output. `--script` sets `__file__` to
the local script path, but execution happens inside IDA; that path is not evidence
that sibling files exist in the remote environment. The local `idac` package is
not part of the execution scope.

For IDA 9.4, the following read-only API recipe was verified against the runtime:

```python
import ida_ida, ida_nalt, ida_typeinf
tif = ida_typeinf.tinfo_t()
assert ida_nalt.get_tinfo(tif, ea)
details = ida_typeinf.func_type_data_t()
assert tif.get_func_details(details)
result = {
    "calling_convention": details.get_cc(),
    "arguments": [{"name": arg.name, "type": str(arg.type)} for arg in details],
    "compiler": ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id()),
}
```

Replace `ea` with a confirmed function address. Type retrieval is in `ida_nalt`,
the calling convention is `get_cc()` rather than a `.cc` field, and compiler ID
comes from `ida_ida`. For another runtime version or an unfamiliar API, inspect
its available methods/docstrings before building the full script. Use
`function prototype show` when the displayed signature already answers the question.

`py exec` is not preview-capable and is treated as mutating for save purposes.
Keep inspection scripts read-only when the request is read-only, and verify any
scripted edit explicitly. Do not retry a failed or timed-out scripted mutation
without reading affected state.
