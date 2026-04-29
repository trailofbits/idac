# Architecture Cleanup Plan

This plan describes an incremental cleanup of the `idac` command, operation, dispatch,
preview, batch, and rendering layers. The goal is a simpler internal architecture with
less generated-looking boilerplate, fewer duplicated representations, and a clearer
execution model.

The plan intentionally avoids a big-bang rewrite. Existing fixture and backend behavior
is valuable, especially around IDA, `idalib`, preview undo/readback, and batch path
handling. Each phase should be reviewable and testable on its own.

## Current Problems

The main issues in the current tree are structural rather than local syntax problems.

- Operations have too many representations:
  - CLI argparse namespace
  - command-local request dataclasses with `to_params()`
  - operation parse functions rebuilding second request dataclasses
  - result dataclasses
  - `payload_from_model()` flattening results back to JSON-shaped dicts
- Operation registration has multiple sources of truth:
  - `OperationName` literal in `src/idac/ops/manifest.py`
  - operation family factories
  - `OPERATION_SPEC_MAP`
  - `OperationRegistry`
  - renderer registry drift checks
- `batch` and `preview` redispatch by reparsing CLI commands, mutating private
  `argparse.Namespace` flags, and calling `execute_parsed()` recursively.
- CLI control state is spread across hidden namespace fields such as
  `_uses_context`, `_preview_wrapper`, `_batch_mode`, `_mutating_command`,
  `allow_batch`, and `allow_preview`.
- Text rendering is a separate registry over JSON-shaped dicts, even though most
  renderers are small formatting functions.
- `src/idac/cli2` is migration residue. `src/idac/cli.py` is currently only a shim.

## End State

The intended end state has two small declarative contracts.

```python
@dataclass(frozen=True)
class Op:
    run: Callable[[IdaRuntime, Params], Json]
    mutating: bool = False
    preview: PreviewSpec | None = None
```

```python
@dataclass(frozen=True)
class CommandSpec:
    op: str | None
    params: Callable[[argparse.Namespace], Params] | None
    render: str
    mutating: bool
    run: Callable[[Invocation], CommandResult] | None = None
    allow_batch: bool = True
    allow_preview: bool = True
    context_policy: str = "standard"
    requires_timeout: bool = False
```

Most commands use `op + params + render` and generic dispatch. Special commands
use `run`: `batch`, `preview`, `doctor`, `workspace`, and possibly `decompilemany`.

The final `Invocation` should be pure command data, not a wrapper around argparse:

```python
@dataclass(frozen=True)
class Invocation:
    spec: CommandSpec
    params: dict[str, Any]
    argv: tuple[str, ...]
    context: ResolvedContext | None
    output: OutputSpec
    preview: bool = False
    batch_mode: bool = False
```

During migration, `Invocation` may temporarily carry `argparse.Namespace`, but that
is not the destination.

## Migration Rules

- New execution code reads `args._spec` or `Invocation.spec`.
- Old command handlers may temporarily read `_batch_mode`, `_preview_wrapper`, and
  `_mutating_command`.
- Only `parse_invocation()` may synthesize legacy namespace flags.
- `send_op(args, ...)` is compatibility scaffolding. Schedule its removal.
- Preview state eventually comes from `Invocation.preview` and `CommandSpec.mutating`,
  not namespace flags.
- Relative paths in batch commands are resolved during invocation construction, not
  by leaf execution consulting `invocation.base_dir`.
- Delete dataclasses that merely mirror wire JSON. Keep internal helper dataclasses
  when they represent real internal domain state.
- Keep validation helpers such as `require_str`, `optional_param_int`, and
  `parse_aliases`. Do not replace validation with unstructured `params.get()` sprawl.
- Keep rendering CLI-side. Do not inline text rendering into runtime operations.

## Progress

Last updated: 2026-04-28.

Completed:

- Added transitional `CommandSpec` / `Invocation` support in `src/idac/cli2/invocation.py`.
- Routed normal parsed execution through `run_invocation()`.
- Converted `batch` child execution to parse and run child invocations.
- Converted `preview` wrapped command execution to parse and run child invocations.
- Added `send_invocation_op()` while keeping `send_op(args, ...)` as compatibility scaffolding.
- Converted these operation result shapes to direct dict/list returns:
  - `src/idac/ops/families/segments.py`
  - `src/idac/ops/families/database.py`
  - `src/idac/ops/families/comments.py`
  - `src/idac/ops/families/bookmarks.py`
  - `src/idac/ops/families/functions.py`
  - `src/idac/ops/families/locals.py`
  - `src/idac/ops/families/prototypes.py`
  - `src/idac/ops/families/search.py`
  - `src/idac/ops/families/named_types.py`
  - `src/idac/ops/families/type_declare.py` (kept internal `DeclarationChunk` per the plan)
- `src/idac/ops/families/classes.py` was already dict-shaped; verified during Phase 6 sweep.
- Removed CLI local-variable request dataclasses from `src/idac/cli2/commands/common.py`; selector inference now lives in `local_selector_params()`.
- Flattened the text renderer registry into `src/idac/cli2/renderers/__init__.py` and removed `renderers/_registry.py`.
- Deleted `src/idac/ops/models.py` and the `payload_from_model` export from `idac.ops`. `src/idac/ops/dispatch.py` now turns a `PreviewOutcome` dataclass into its dict shape via a small `_finalize_result` helper.
- Unified `_LIST_COUNT_LABELS` and `_DICT_COUNT_FIELDS` in `src/idac/cli2/serialize.py` into a single `_RESULT_COUNTS` table and replaced the per-render_op branches in `artifact_notice` with two small label tables.
- Replaced `OperationContext` / `OperationSpec` / `OperationRegistry` and the per-family `*_operations()` factories with a single `Op(run, mutating, preview)` dataclass and an `OPERATIONS: dict[str, Op]` table assembled from per-family `*_OPS` dicts. `dispatch(runtime, name, params)` replaces the registry indirection and `run_preview` now takes `(runtime, name, params, runner, spec)`. `names.py` and `misc.py` also dropped residual wire-shape result dataclasses.
- Deleted CLI request dataclasses in `src/idac/cli2/commands/function.py` (`FunctionListRequest`) and `src/idac/cli2/commands/type_commands.py` (`PatternRequest`, `NameRequest`, `TypeDeclareRequest`, `ClassCandidatesRequest`, `ClassFieldsRequest`, `ClassVtableRequest`, `StructFieldSet/Rename/DeleteRequest`, `EnumMemberSet/Rename/DeleteRequest`); each one became a plain `_*_params(args)` helper that returns the param dict directly.
- Started Phase 11 by requiring `parse_invocation()` for every command: `send_op` no longer falls back to legacy `_preview_wrapper` / `_mutating_command` namespace flags, and `function._prototype_set_params` reads preview state from `args._invocation.preview`.
- Converted every `run_*(args)` / `_*(args)` command handler signature in `src/idac/cli2/commands/*.py`, `cli2/batch.py`, and `cli2/preview.py` to take `Invocation`. `run_invocation()` now passes the invocation directly; `bind_root_handler` forwards an invocation. Inside handlers, `args` is read as `invocation.args` until later phases evict the namespace entirely.
- Collapsed `send_op(args, ...)` and `send_invocation_op(invocation, ...)` into a single `send_op(invocation, ...)` entry point in `cli2/commands/common.py`.
- Dropped `_preview_wrapper` and `_batch_mode` namespace flags entirely. State now lives only on `Invocation.preview` / `Invocation.batch_mode`. `cli2/preview.py` and `cli2/batch.py` read state from the invocation; `parse_invocation()` no longer writes legacy flags onto the namespace; `argparse_utils.py` no longer seeds them as defaults.
- Promoted batch-relative path resolution out of a hidden namespace attribute: `Invocation` gained a `base_dir: Path | None` field and `cli2/preview.py` reads `invocation.base_dir` instead of `args._relative_path_base_dir`.

Current next step:

- Phase 11 is now substantively complete for the dispatch surface (no command handler reads namespace flags for batch/preview state, every handler takes `Invocation`, and `send_op` is unified). Two transitional pieces remain before `Invocation.args` can be deleted entirely:
  - Replace per-handler `args = invocation.args` reads with a typed `params: dict[str, Any]` on `Invocation` populated by a `CommandSpec.params` builder, so generic dispatch can run `op + params + render` without touching argparse. This is interleaved with Phase 12.
  - Introduce an `OutputSpec` (format, out, out_dir) on `Invocation` so `main.py`, `batch.py`, and `preview.py` can stop reading `args.format` / `args.out` directly. This is also a Phase 12 concern.

## Phase 0: Characterization Tests

Before structural edits, pin behavior around the tricky redispatch and backend paths.

Add or confirm tests for:

- batch parent context inheritance
- batch relative paths for `--decl-file`, `--functions-file`, and `--out`
- preview of a mutating command
- preview of a read-only command
- preview inside batch
- `decompilemany --functions-file --out-dir`
- GUI and `idalib` response envelope shape

Relevant files:

- `src/idac/cli2/batch.py`
- `src/idac/cli2/preview.py`
- `src/idac/cli2/commands/common.py`
- `src/idac/ops/dispatch.py`
- `src/idac/transport/schema.py`

Validation:

```bash
uv run pytest -q tests/test_cli.py tests/test_preview.py tests/test_dispatch.py tests/test_operation_registry.py
```

## Phase 1: Add CommandSpec And Transitional Invocation

Add `src/idac/cli2/invocation.py`.

Initial transition shape:

```python
@dataclass(frozen=True)
class Invocation:
    spec: CommandSpec
    args: argparse.Namespace
    argv: tuple[str, ...]
    context: ResolvedContext | None
    preview: bool = False
    batch_mode: bool = False
```

Add:

```python
def parse_invocation(
    root_parser: argparse.ArgumentParser,
    argv: list[str],
    *,
    parent: Invocation | argparse.Namespace | None = None,
    base_dir: Path | None = None,
) -> Invocation: ...

def run_invocation(invocation: Invocation) -> CommandResult: ...
```

`parse_invocation()` should:

- parse argv
- attach/read `CommandSpec`
- resolve parent context
- resolve batch-relative paths immediately when `base_dir` is provided
- synthesize legacy namespace flags for compatibility
- return an invocation ready to execute

`run_invocation()` can initially call existing `run(args)` handlers.

Touch points:

- `src/idac/cli2/argparse_utils.py`: attach `_spec` when creating commands
- `src/idac/cli2/execute.py`: route through invocation execution
- `src/idac/cli2/context.py`: expose context resolution as an invocation-building step
- `src/idac/cli2/path_resolution.py`: run path resolution during `parse_invocation()`

Validation:

```bash
uv run pytest -q tests/test_cli.py tests/test_cli2_request_builders.py
```

## Phase 2: Convert Batch To Invocation Redispatch

Update `src/idac/cli2/batch.py` so each non-comment line becomes an invocation:

```python
argv = shlex.split(line)
child = parse_invocation(root_parser, argv, parent=batch_invocation, base_dir=batch_dir)
if not child.spec.allow_batch:
    raise CliUserError("command is not available in batch mode")
result = run_invocation(child)
```

Remove normal-path recursive `execute_parsed()` usage from batch.

Batch should still redispatch commands, not raw ops. Batch files are written in CLI
syntax and must preserve CLI behavior such as `--decl-file`, output options, aliases,
context inheritance, and validation.

Validation:

```bash
uv run pytest -q tests/test_cli.py
```

## Phase 3: Convert Preview To Invocation Redispatch

Update `src/idac/cli2/preview.py` so the wrapped command becomes an invocation:

```python
child = parse_invocation(root_parser, tokens, parent=preview_invocation)
if not child.spec.allow_preview:
    raise CliUserError("command is not available in preview mode")
child = replace(child, preview=True)
result = run_invocation(child)
```

Make preview concepts explicit:

- `Invocation.preview`: user requested preview wrapper
- `CommandSpec.mutating`: command is mutating
- `Op.preview`: operation supports undo/readback preview
- preview dispatch result: normalized before/after/result/readback payload

Do not leave preview state hidden in `_preview_wrapper` permanently.

Validation:

```bash
uv run pytest -q tests/test_preview.py tests/test_cli.py
```

## Phase 4: Add Invocation-Aware Send Path And Schedule send_op Removal

`src/idac/cli2/commands/common.py:send_op()` currently reads namespace flags:

- `_preview_wrapper`
- `_mutating_command`

Add an invocation-aware path:

```python
def send_invocation_op(
    invocation: Invocation,
    *,
    op: str,
    params: dict[str, Any],
    render_op: str | None = None,
    preview: bool | None = None,
) -> CommandResult:
    preview_requested = (
        invocation.preview and invocation.spec.mutating
        if preview is None
        else preview
    )
    ...
```

During transition:

- keep `send_op(args, ...)`
- make `parse_invocation()` the only writer of the legacy preview flags
- start moving simple command handlers to invocation-aware dispatch

Exit criteria:

- `send_op(args, ...)` has no new call sites
- preview behavior is tested through `Invocation.preview`

Validation:

```bash
uv run pytest -q tests/test_preview.py tests/test_cli.py
```

## Phase 5: Pilot Dict Result Conversion

Convert one small operation family from result dataclasses to JSON-shaped dict/list
returns. Do not start with `functions.py`; use a lower-risk family first.

Good pilots:

- `src/idac/ops/families/segments.py` - done
- `src/idac/ops/families/comments.py` - done
- `src/idac/ops/families/bookmarks.py` - done
- `src/idac/ops/families/database.py` - done

Keep request dataclasses temporarily if that reduces diff size. Keep
`payload_from_model()` temporarily so mixed dataclass/dict families still work.

Validation:

```bash
uv run pytest -q tests/test_ops_helpers.py tests/test_renderers.py
```

## Phase 6: Convert Remaining Wire Result Dataclasses

Convert the remaining families to return plain JSON-shaped data.

Suggested order:

1. `src/idac/ops/families/functions.py` - done
2. `src/idac/ops/families/locals.py` - done
3. `src/idac/ops/families/prototypes.py`
4. `src/idac/ops/families/search.py`
5. `src/idac/ops/families/classes.py`
6. `src/idac/ops/families/named_types.py`
7. `src/idac/ops/families/type_declare.py`

Already converted:

- `src/idac/ops/families/segments.py`
- `src/idac/ops/families/database.py`
- `src/idac/ops/families/comments.py`
- `src/idac/ops/families/bookmarks.py`
- `src/idac/ops/families/functions.py`
- `src/idac/ops/families/locals.py`
- `src/idac/ops/families/prototypes.py`
- `src/idac/ops/families/search.py`
- `src/idac/ops/families/classes.py` (already dict-shaped at the start of the sweep)
- `src/idac/ops/families/named_types.py`
- `src/idac/ops/families/type_declare.py`

For `type_declare.py`, keep internal types such as `DeclarationChunk` if they make
the parse/diagnose/bisect flow clearer. Only remove wire-shape conversions that exist
solely to be flattened.

Validation:

```bash
uv run pytest -q tests/test_ops_helpers.py tests/test_idalib_*.py tests/test_renderers.py
```

## Phase 7: Delete payload_from_model

Once all operation results are already JSON-shaped:

- delete `src/idac/ops/models.py`
- remove `payload_from_model(result)` from `src/idac/ops/dispatch.py`
- remove imports of `payload_from_model`
- update tests that import wire result dataclasses to use dict keys

Validation:

```bash
uv run pytest -q tests/test_ops_helpers.py tests/test_idalib_*.py tests/test_renderers.py
```

## Phase 8: Simplify Renderers

Now that payloads are consistently dict/list:

- delete `src/idac/cli2/renderers/_registry.py`
- define one `TEXT_RENDERERS` dict directly in the renderer module
- keep rendering separate from runtime operations
- delete helpers only when they obscure simple formatting
- simplify plural/count handling in `src/idac/cli2/serialize.py`

Do not scatter renderers across runtime op modules.

Validation:

```bash
uv run pytest -q tests/test_renderers.py tests/test_output.py tests/test_cli.py
```

## Phase 9: Collapse Operation Dispatch

Replace the current operation stack:

- `src/idac/ops/base.py`
- `src/idac/ops/registry.py`
- `src/idac/ops/manifest.py`
- `src/idac/ops/dispatch.py`

with a single operation table:

```python
OPERATIONS: dict[str, Op] = {
    **DATABASE_OPS,
    **SEGMENT_OPS,
    **FUNCTION_OPS,
    ...
}
```

Derived values only:

```python
SUPPORTED_OPERATIONS = ("list_targets", *OPERATIONS)
MUTATING_OPERATIONS = tuple(name for name, op in OPERATIONS.items() if op.mutating)
PREVIEW_UNSUPPORTED_OPERATIONS = tuple(
    name for name, op in OPERATIONS.items()
    if op.mutating and op.preview is None
)
```

Preview becomes:

```python
run_preview(runtime, op_name, params, runner, spec)
```

Remove:

- `OperationContext`
- `OperationRegistry`
- `OperationSpec`
- `OperationName`
- `function_operations()` and similar factories
- direct test-only wrappers such as `op_decompile()` and `op_function_frame()`

Tests should call either:

```python
OPERATIONS["decompile"].run(runtime, params)
```

or a small dispatch helper:

```python
dispatch(runtime, "decompile", params)
```

Validation:

```bash
uv run pytest -q tests/test_dispatch.py tests/test_operation_registry.py tests/test_preview.py tests/test_ops_helpers.py
```

## Phase 10: Delete CLI Request Dataclasses

Remove `to_params()` classes where they merely mirror dicts.

Examples:

- `LocalSelector`, `LocalRenameRequest`, `LocalRetypeRequest`, and
  `LocalUpdateRequest` in `src/idac/cli2/commands/common.py`
- `FunctionListRequest` in `src/idac/cli2/commands/function.py`
- small request classes in `src/idac/cli2/commands/type_commands.py`

Keep real parsing logic. For example, local selector inference should survive as
plain param-building helpers:

```python
def local_selector_params(
    args: argparse.Namespace,
    *,
    name_param: Literal["old_name", "local_name"],
    require_selector: bool = True,
) -> dict[str, Any]:
    ...
```

Then:

```python
def local_rename_params(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "identifier": str(args.function),
        "new_name": str(args.new_name),
        **local_selector_params(args, name_param="old_name"),
    }
```

Delete or rewrite `tests/test_cli2_request_builders.py` once the builder objects no
longer exist.

Validation:

```bash
uv run pytest -q tests/test_cli2_request_builders.py tests/test_cli.py tests/test_ops_helpers.py
```

## Phase 11: Evict argparse.Namespace From Invocation

This phase turns the transitional invocation into the planned pure-data invocation.

Change `parse_invocation()` so it consumes argparse and returns:

- `params`
- `context`
- `output`
- `spec`
- `argv`
- preview/batch mode

Final shape:

```python
@dataclass(frozen=True)
class Invocation:
    spec: CommandSpec
    params: dict[str, Any]
    argv: tuple[str, ...]
    context: ResolvedContext | None
    output: OutputSpec
    preview: bool = False
    batch_mode: bool = False
```

Then:

- convert simple handlers from `run(args)` to `run(invocation)`
- generic dispatch reads `invocation.params`
- output serialization reads `invocation.output`
- delete remaining hidden namespace flags
- delete `send_op(args, ...)`
- delete compatibility writes from `parse_invocation()`

Validation:

```bash
uv run pytest -q tests/test_cli.py tests/test_preview.py tests/test_dispatch.py
```

## Phase 12: Table-Drive Boring Commands

Only table-drive commands after the lower layers are simplified.

Good candidates:

- `function metadata`
- `function frame`
- `function stackvars`
- `function callers`
- `function callees`
- `segment list`
- `bookmark show/add/set/delete`
- `comment show/set/delete`
- simple `type`, `struct`, and `enum` commands

Keep bespoke:

- `batch`
- `preview`
- `doctor`
- `workspace`
- `type declare`
- `decompilemany`, unless it is promoted to a real operation or workflow service

Validation:

```bash
uv run pytest -q tests/test_cli.py tests/test_renderers.py
```

## Phase 13: Rename cli2 To cli

Do this last because it is mechanically noisy and has little architectural value.

Steps:

- move `src/idac/cli2/` to `src/idac/cli/`
- replace the current `src/idac/cli.py` shim with the actual entry point, or use a
  clean package entry
- update source and test imports
- keep this as a separate commit with minimal logic changes

Validation:

```bash
uv run pytest -q tests/test_cli.py
make lint
```

## Suggested Commit Sequence

1. Add characterization tests.
2. Add `CommandSpec` and transitional `Invocation`.
3. Convert `batch` redispatch to invocations.
4. Convert `preview` redispatch to invocations.
5. Add invocation-aware send path.
6. Pilot dict-result conversion on one small op family.
7. Convert remaining op families.
8. Delete `payload_from_model()`.
9. Simplify renderer registry.
10. Collapse operation dispatch to `OPERATIONS`.
11. Delete CLI request dataclasses while keeping parsing helpers.
12. Evict `argparse.Namespace` from `Invocation`.
13. Table-drive repetitive commands.
14. Rename `cli2` to `cli`.

## Broad Validation

Use targeted tests after each phase, then broader validation before merging a larger
series:

```bash
uv run pytest -q tests/test_cli.py tests/test_preview.py tests/test_dispatch.py tests/test_operation_registry.py
uv run pytest -q tests/test_ops_helpers.py tests/test_renderers.py tests/test_output.py
uv run pytest -q tests/test_idalib_*.py
make lint
make test
```

For fixture refreshes or anything that spawns IDA or `idat`, use isolated `IDAUSR`
as described in `AGENTS.md`.
