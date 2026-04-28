# AGENTS

## Repo Overview

`idac` is a CLI for IDA Pro with two execution paths:

- `gui`: talks to a live IDA desktop session through the bridge plugin
- `idalib`: opens `.i64` / `.idb` files in a short-lived headless worker

Most implementation lives under `src/idac`:

- `src/idac/cli.py`: command registration and argument parsing
- `src/idac/ops/`: typed operation families, manifest, dispatch, preview execution, runtime helpers, and shared helper modules
- `src/idac/cli2/renderers/`: text rendering
- `src/idac/transport/schema.py`: wire request/response schema
- `src/idac/transport/`: GUI bridge transport and `idalib` worker transport
- `plugin/`: IDA GUI bridge plugin code
- `tests/`: CLI and backend coverage
- `fixtures/`: committed binaries, databases, logs, and source used by tests
- `docs/` and `src/idac/skills/idac/`: user-facing command docs and agent-oriented usage guidance

## Working Style

- Prefer `uv run ...` for repo-local commands.
- Prefer targeted tests first, then broader validation if the change touches shared behavior.
- Treat committed fixture artifacts as part of the product surface. If you change fixture symbols, fixture source, or docs/examples that depend on them, regenerate the fixture outputs too.
- Do not revert unrelated worktree changes. This repo may contain user-owned untracked recovery artifacts and local editor files.
- In `src/idac/cli2`, keep `argparse.Namespace` at the parser boundary. Use direct `args.foo` access for fields guaranteed by that subcommand, and reserve `vars(args).get(...)` for wrapper or `argparse.SUPPRESS` cases.
- For command-local argument normalization in `src/idac/cli2/commands/`, prefer `_foo_request(args) -> FooRequest` plus `FooRequest.to_params()` rather than spreading selector/default coercion through handlers.
- When request-building logic becomes nontrivial, add a focused unit test for the builder itself in addition to end-to-end CLI coverage.

## Reverse-Engineering Defaults

- Work from the binary first. Do not search the web or external source trees unless the user explicitly asks for that or the task is specifically about external correlation.
- During type or prototype recovery, always use `idac decompile --f5` or `idac decompilemany --f5` so readback reflects the latest imported types and signatures. `--f5` is the same as `--no-cache`.
- Before `function prototype set`, run `function prototype show` to read the current signature and confirm what is changing.
- After meaningful type or prototype mutations, run `idac misc reanalyze ...` before local rename-heavy cleanup, then reread pseudocode or locals instead of assuming propagation.
- Before batch local renames, capture `idac function locals list <func> --json` and prefer `--local-id` or `--index` selectors once prototypes or reanalysis may have shifted the local set.
- Stop a rename batch on the first miss. Reread locals, recalibrate selectors, and only then continue.
- Declare support types before dependent prototypes. If a prototype references a missing type, create the placeholder type first and retry.
- Prefer minimal `struct` declarations first. Start with the vtable pointer and directly observed fields, keep uncertain names provisional, and use blob padding for unknown regions instead of guessed scalars.

## Common Commands

Initial setup:

```bash
uv sync
```

Useful local commands:

```bash
uv run idac --help
uv run idac --full-help
make format
make lint
make test
make check
uv run pytest -q tests/test_idalib_classes.py
IDAC_RUN_LIVE_GUI_TESTS=1 uv run pytest -q -m gui_live tests/test_gui_transport_live.py
```

Prefer targeted `idac <command> --help` when you already know the likely command family. Use `idac --full-help` when you need the full command tree in one pass.

## Codebase Notes

When changing commands or request/response shapes:

- update CLI wiring in `src/idac/cli.py`
- update the operation implementation in `src/idac/ops/`
- update renderers/schema if output shape changed
- update tests and any affected docs under `README.md`, `docs/`, or `src/idac/skills/idac/`

When changing the operation layer, keep these boundaries in mind:

- `src/idac/ops/runtime.py` is the shared toolkit for reusable IDA-facing helpers. Prefer adding cross-operation lookup, normalization, and readback helpers there instead of duplicating them across op modules.
- keep `src/idac/ops/families/` focused on command-family orchestration, typed request/result models, and user-facing error messages
- `src/idac/ops/manifest.py` is the source of truth for supported ops, mutation flags, and preview metadata
- `src/idac/ops/dispatch.py` should derive handler registration from the manifest and registry, not maintain a parallel operation list
- `src/idac/ops/preview.py` should stay thin. If preview behavior changes, prefer encoding defaults and policy in `PreviewSpec` rather than branching in wrappers.
- `src/idac/cli2/renderers/__init__.py` owns text rendering. Before adding another formatter, look for an existing helper or adjacent renderer that can absorb the behavior.
- for `type declare`, keep `DeclarationChunk` as the internal representation through parse / diagnose / bisect flows and only convert to plain dicts at the API boundary when needed by tests or wire output
- if you are tempted to add a module-level wrapper around an `IdaRuntime` method, prefer calling the runtime instance method directly unless tests or external callers genuinely need the free function
- shared non-runtime helpers should live under `src/idac/ops/helpers/`

When changing GUI bridge behavior:

- check both `plugin/` and `src/idac/transport/gui.py`
- keep protocol expectations aligned across the plugin and the CLI transport
- add or update the optional `gui_live` test when the Unix socket contract changes

When changing `idalib` behavior:

- inspect `src/idac/transport/idalib.py` and `src/idac/transport/idalib_worker.py`
- use targeted `idalib` tests before running the whole suite

## Fixtures

The primary class-recovery fixture is:

- source: `fixtures/src/handler_hierarchy.cpp`
- local type header: `fixtures/src/handler_hierarchy.hpp`
- build script: `fixtures/scripts/build_handler_hierarchy.sh`
- database script: `fixtures/scripts/make_handler_hierarchy_idbs.sh`

The committed artifacts are:

- `fixtures/build/handler_hierarchy`
- `fixtures/build/handler_hierarchy.stripped`
- `fixtures/idb/handler_hierarchy.i64`
- `fixtures/idb/handler_hierarchy_stripped.i64`
- `fixtures/idb/handler_hierarchy.log`
- `fixtures/idb/handler_hierarchy_stripped.log`

There is also a smaller `tiny` fixture used for lighter database/backend checks.

## IDA User Dir Isolation

When running fixture-generation commands or any test flow that opens IDA or `idat`, do not rely on the live `~/.idapro` directory.

Reason:

- the installed `~/.idapro/plugins/idac_bridge_plugin.py` can import the current checkout and break batch runs if the repo is mid-change
- fixture regeneration should not depend on whatever plugins happen to be installed globally
- tests and fixture refreshes should not mutate the user's real IDA profile

Use an isolated `IDAUSR` that keeps the license/config files but omits `plugins/`.

### Temporary isolated `IDAUSR`

Run from the repo root:

```bash
tmpdir=$(mktemp -d /tmp/idac-test-idapro.XXXXXX)
cp ~/.idapro/ida.reg "$tmpdir"/
cp ~/.idapro/ida-config.json "$tmpdir"/ 2>/dev/null || true
cp ~/.idapro/idapro_*.hexlic "$tmpdir"/ 2>/dev/null || true
mkdir -p "$tmpdir/plugins"
export IDAUSR="$tmpdir"
```

This preserves the license/config that `idat` needs, while ensuring no globally installed plugins are loaded.

## Fixture Regeneration Workflow

Rebuild the neutral class fixture and regenerate its databases/logs with the isolated `IDAUSR`:

```bash
bash fixtures/scripts/build_handler_hierarchy.sh
bash fixtures/scripts/make_handler_hierarchy_idbs.sh
```

If you also need the tiny fixture refreshed:

```bash
bash fixtures/scripts/build_tiny.sh
bash fixtures/scripts/make_idbs.sh
```

If `idat` logs show plugin import errors from `~/.idapro/plugins/idac_bridge_plugin.py`, rerun with an isolated `IDAUSR` before assuming the fixture or code under test is broken.

## Test Guidance

Normal repo tests can run without `IDAUSR`, but keep the isolated directory exported when you are doing fixture refreshes or any workflow that may spawn `idat`.

Typical commands:

```bash
uv run pytest -q tests/test_idalib_classes.py
uv run pytest -q
```

Useful targeted suites for operation-layer work:

```bash
uv run pytest -q tests/test_ops_helpers.py
uv run pytest -q tests/test_preview.py
uv run pytest -q tests/test_idalib_types.py
uv run pytest -q tests/test_idalib_name_locals_semantics.py
uv run pytest -q tests/test_idalib_struct_enum_semantics.py
uv run pytest -q tests/test_vtable_helpers.py
```

These are especially useful when editing:

- preview / manifest / registry wiring
- `type declare` diagnostics or bisect behavior
- local-variable mutation and preview behavior
- class / vtable helper logic

Optional live GUI transport coverage is marked with `@pytest.mark.gui_live` and skipped unless `IDAC_RUN_LIVE_GUI_TESTS=1` is set.

## Skill Install Targets

The bundled `idac` skill supports both Claude Code and Codex equally.

- default install targets:
  - `~/.claude/skills/idac`
  - `~/.codex/skills/idac`
- custom install destination:
  - `idac misc skill install --dest /custom/path/idac`

For fixture-driven class tests, prefer updating and validating:

- `tests/conftest.py`
- `tests/test_idalib_classes.py`
- `README.md`
- `src/idac/skills/idac/`

## Agent Guardrails

- Do not modify the real `~/.idapro/plugins` contents as part of routine repo work.
- Do not point fixture-generation commands at the live `~/.idapro` unless the user explicitly asks for that.
- Do not leave docs/examples referencing old fixture symbol names after a rename.
- When changing committed fixture symbols, verify the asserted mangled names from the rebuilt binary or regenerated database instead of guessing.
- Do not stage `PLAN.md`; keep it as local planning scratch unless the user explicitly says otherwise.
- Leave unrelated untracked scratch directories and recovery artifacts alone unless the user explicitly asks to clean them up.
