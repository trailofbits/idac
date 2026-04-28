# Development

## Local setup

```bash
uv sync
```

Common commands:

```bash
make format
make lint
make test
make check
make audit
uv run idac --full-help
```

## Testing

Run the test suite:

```bash
uv sync
uv run pytest -q
```

When changing the operation layer, start with targeted suites before broad runs:

```bash
uv run pytest -q tests/test_ops_helpers.py
uv run pytest -q tests/test_preview.py
uv run pytest -q tests/test_idalib_types.py
uv run pytest -q tests/test_idalib_name_locals_semantics.py
uv run pytest -q tests/test_idalib_struct_enum_semantics.py
uv run pytest -q tests/test_vtable_helpers.py
```

These cover most of the high-churn operation surfaces:

- operation manifest / dispatch / preview plumbing
- `type declare` parsing, diagnostics, alias rewrites, and bisect behavior
- local variable mutation semantics
- struct / enum preview round-trips
- vtable slot and pointer-width helpers

## Operation Layer Structure

`src/idac/ops/runtime.py` is the shared toolkit layer. Put reusable IDA lookups, normalization, and helper reads there when they are likely to be shared across multiple command families.

The live operation modules in `src/idac/ops/families/` should stay focused on:

- command-specific orchestration
- request validation and user-facing error messages
- typed request/result models and result shaping

For operation metadata:

- `src/idac/ops/manifest.py` is the source of truth for supported operations, mutation flags, and preview metadata
- `src/idac/ops/dispatch.py` should derive handler registration from the operation manifest and typed registry, not maintain a parallel operation list
- `src/idac/ops/preview.py` should remain a thin wrapper around `PreviewSpec` behavior
- `src/idac/ops/helpers/` should hold shared parameter parsing and matching helpers that do not belong on `IdaRuntime`

For `type declare` internals:

- keep `DeclarationChunk` as the internal representation through parse, diagnostics, and bisect flows
- convert to plain dicts only at boundaries that actually need serialized output
- prefer small helpers for optional bisect / trial-parse control flow instead of growing `op_type_declare` inline

For preview behavior:

- preview mode performs a real mutation under IDA undo, then captures the before/after state and undoes it
- remember that previewed mutating operations apply the change before undoing it
- if preview formatting changes, prefer putting defaults on `PreviewSpec` rather than duplicating fallback logic in the wrapper

For output and transport boundaries:

- `src/idac/cli2/renderers/__init__.py` owns text rendering
- `src/idac/transport/schema.py` owns wire request/response schema definitions

### Fixture binaries

The repo includes fixture binaries and IDA databases under [fixtures](../fixtures).
The committed fixture binaries and `.i64` databases are Mach-O ARM64 artifacts generated on macOS/Apple Silicon.

Representative class-recovery fixture artifacts:

- source: [fixtures/src/handler_hierarchy.cpp](../fixtures/src/handler_hierarchy.cpp)
- importable type header: [fixtures/src/handler_hierarchy.hpp](../fixtures/src/handler_hierarchy.hpp)
- build helper: [fixtures/scripts/build_handler_hierarchy.sh](../fixtures/scripts/build_handler_hierarchy.sh)
- database helper: [fixtures/scripts/make_handler_hierarchy_idbs.sh](../fixtures/scripts/make_handler_hierarchy_idbs.sh)

### IDA batch runs and fixture regeneration

When regenerating fixture `.i64` files or running any workflow that invokes `idat`, avoid using the live `~/.idapro` directly. A globally installed `idac_bridge_plugin.py` can import the current checkout and break batch analysis if the repo is mid-change.

Use an isolated `IDAUSR` that keeps the license/config files but leaves `plugins/` empty:

```bash
tmpdir=$(mktemp -d /tmp/idac-test-idapro.XXXXXX)
cp ~/.idapro/ida.reg "$tmpdir"/
cp ~/.idapro/ida-config.json "$tmpdir"/ 2>/dev/null || true
cp ~/.idapro/idapro_*.hexlic "$tmpdir"/ 2>/dev/null || true
mkdir -p "$tmpdir/plugins"
export IDAUSR="$tmpdir"
```

Then regenerate the committed class fixture artifacts:

```bash
bash fixtures/scripts/build_handler_hierarchy.sh
bash fixtures/scripts/make_handler_hierarchy_idbs.sh
```

If `idat` logs mention plugin import errors from `~/.idapro/plugins/idac_bridge_plugin.py`, rerun with the isolated `IDAUSR` before assuming the fixture or CLI code is at fault.

### Test coverage

Current suite covers:

- GUI transport
- `idalib` backend reads
- type/struct/enum commands
- class commands and `type declare --replace`
- local variable commands
- preview behavior
- timeout handling
- `doctor`
- `ctree`
- `reanalyze`

### Live GUI tests

Optional live GUI transport coverage uses a real Unix socket bridge service and is skipped by default:

```bash
IDAC_RUN_LIVE_GUI_TESTS=1 uv run pytest -q -m gui_live tests/test_gui_transport_live.py
```
