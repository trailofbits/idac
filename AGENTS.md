# AGENTS

## Repo Overview

`idac` is an ida-nexus-backed CLI for IDA Pro. The same public Nexus API attaches
to live GUI databases and opens `.i64` databases or binaries in managed headless
workers. There is no alternate transport or compatibility fallback.

Most implementation lives under `src/idac`:

- `src/idac/cli/`: command registration, argument parsing, batch/preview orchestration, and text rendering
- `src/idac/nexus.py`: public ida-nexus discovery, selection, lifecycle, compatibility, and execution boundary
- `src/idac/remote_ops.py`: the self-contained operation module uploaded through `ida_nexus.RemoteModule`
- `src/idac/operations.py`: the retained public operation inventory
- `src/idac/doctor.py` and `src/idac/setup.py`: exact-stack diagnostics and installation
- `tests/`: CLI and backend coverage
- `fixtures/`: committed binaries, databases, logs, and source used by tests
- `docs/` and `plugins/idac/skills/idac/`: user-facing command docs and agent-oriented usage guidance

## Working Style

- Prefer `uv run ...` for repo-local commands.
- Prefer targeted tests first, then broader validation if the change touches shared behavior.
- Treat committed fixture artifacts as part of the product surface. If you change fixture symbols, fixture source, or docs/examples that depend on them, regenerate the fixture outputs too.
- Do not revert unrelated worktree changes. This repo may contain user-owned untracked recovery artifacts and local editor files.
- In `src/idac/cli`, keep `argparse.Namespace` at the parser boundary. Use direct `args.foo` access for fields guaranteed by that subcommand, and reserve `vars(args).get(...)` for wrapper or `argparse.SUPPRESS` cases.
- For command-local argument normalization in `src/idac/cli/commands/`, prefer a focused `_foo_params(args) -> dict[str, object]` builder rather than spreading selector/default coercion through handlers.
- Do not add tiny one- to three-expression helpers unless they own a meaningful responsibility or remove real duplication.
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
uv run pytest -q -m "not requires_ida"
uv run pytest -q -m requires_ida
IDAC_RUN_NEXUS_GUI_TESTS=1 IDAC_NEXUS_GUI_RECORD_ID='<record-id>' \
  uv run pytest -q -m nexus_gui_live
```

Prefer targeted `idac <command> --help` when you already know the likely command family. Use `idac --full-help` when you need the full command tree in one pass.

## Codebase Notes

When changing commands or request/response shapes:

- update CLI wiring in `src/idac/cli/`
- update the operation implementation and registry in `src/idac/remote_ops.py`
- update `src/idac/operations.py` and renderers if the operation/output surface changed
- update tests and any affected docs under `README.md`, `docs/`, or `plugins/idac/skills/idac/`

When changing the operation layer, keep these boundaries in mind:

- `src/idac/remote_ops.py` must remain importable outside IDA, self-contained, JSON-native, and free of imports from the local `idac` package.
- `remote_ops.dispatch(db, op, params, preview)` is the only uploaded dispatch entrypoint; do not add alternate wire paths or per-operation uploads.
- Keep the remote operation registry immutable and request state local. Do not add process-global mutable caches or compatibility handlers.
- `src/idac/cli/renderers/__init__.py` owns text rendering. Before adding another formatter, look for an existing helper or adjacent renderer that can absorb the behavior.
- for `type declare`, keep `DeclarationChunk` as the internal representation through parse / diagnose / bisect flows and only convert to plain dicts at the API boundary when needed by tests or wire output
- if you are tempted to add a module-level wrapper around an `IdaRuntime` method, prefer calling the runtime instance method directly unless tests or external callers genuinely need the free function

When changing Nexus behavior:

- use only supported public `ida_nexus` Python exports; do not read its private registry, issue raw HTTP requests, or add MCP/legacy fallbacks
- preserve exact READY-record selection, one session per top-level command, a 300-second lease keepalive, headless autoanalysis, and headless save-on-successful-mutation semantics
- validate the pinned remote stack before dispatch and fail closed on any mismatch
- add or update `tests/test_nexus_session.py` and the optional `nexus_gui_live` coverage when lifecycle behavior changes

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

- globally installed IDA plugins can import local packages or otherwise change batch behavior while the checkout is mid-change
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

If `idat` logs show plugin import errors, rerun with an isolated `IDAUSR` before assuming the fixture or code under test is broken.

## Test Guidance

Normal repo tests can run without `IDAUSR`, but keep the isolated directory exported when you are doing fixture refreshes or any workflow that may spawn `idat`.

Test durable behavior, not implementation shape. Prefer public CLI/API results, persisted
state, wire contracts, and required lifecycle or safety invariants. Do not assert private
helper boundaries, incidental call order, mock choreography, source layout, or constants
that have no user-visible effect. Avoid duplicating the same behavior at several layers;
keep the lowest-cost test that exercises the real contract. A refactor that preserves
behavior should not require rewriting tests.

Typical commands:

```bash
uv run pytest -q tests/test_nexus_classes.py
uv run pytest -q
```

Useful targeted suites for operation-layer work:

```bash
uv run pytest -q tests/test_ops_helpers.py
uv run pytest -q tests/test_preview.py
uv run pytest -q tests/test_nexus_types.py
uv run pytest -q tests/test_nexus_name_locals_semantics.py
uv run pytest -q tests/test_nexus_struct_enum_semantics.py
uv run pytest -q tests/test_vtable_helpers.py
```

These are especially useful when editing:

- preview / manifest / registry wiring
- `type declare` diagnostics or bisect behavior
- local-variable mutation and preview behavior
- class / vtable helper logic

Optional live GUI Nexus coverage is marked with `@pytest.mark.nexus_gui_live` and
skipped unless `IDAC_RUN_NEXUS_GUI_TESTS=1` and an exact
`IDAC_NEXUS_GUI_RECORD_ID` are set. Use only a disposable GUI database: the test
explicitly saves, verifies an on-disk snapshot, and then restores a temporary comment.

## Agent Plugin Distribution

`plugins/idac` is the canonical Agent Plugins v1 package, separate from the Python
package. Its manifest is `plugins/idac/plugin.json`, and its skill is
`plugins/idac/skills/idac`. The repository catalog at
`.agents/plugins/marketplace.json` must point directly to `./plugins/idac`. Do not add
client-specific manifests or fallback copies. The CLI has no command that installs or
prints plugin content, so do not add runtime package code that reads these assets.

For fixture-driven class tests, prefer updating and validating:

- `tests/conftest.py`
- `tests/test_nexus_classes.py`
- `README.md`
- `plugins/idac/skills/idac/`

## Release Process

Releases are automated end to end by GitHub Actions. Do not bump the version
in `pyproject.toml`/`uv.lock` by hand, create `v*` tags, or publish to PyPI
manually — the workflows own all of that.

To cut a release:

1. Dispatch the `prepare release` workflow on `main`:

   ```bash
   gh workflow run prepare-release.yml                   # bump the minor version
   gh workflow run prepare-release.yml -f version=X.Y.Z  # or release an explicit version
   ```

2. Wait for the run to finish. It commits the version bump to a new
   `release/vX.Y.Z` branch:

   ```bash
   gh run watch "$(gh run list --workflow=prepare-release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
   git ls-remote origin 'refs/heads/release/*'
   ```

3. Open a pull request from the release branch:

   ```bash
   gh pr create --head release/vX.Y.Z --title "Prepare release vX.Y.Z" \
     --body "Merging this pull request publishes vX.Y.Z automatically."
   ```

4. Merge the PR through the merge queue like any other PR. Once a `release/*`
   PR merges into `main`, the `publish release` workflow tags the merge
   commit, creates the GitHub release, and publishes to PyPI. No further
   action is needed.

Notes:

- The prepare workflow has Claude draft the `CHANGELOG.md` section for the new
  version on the release branch (requires the `ANTHROPIC_API_KEY` actions
  secret); review and edit that entry as part of the release PR. The changelog
  covers user-facing changes only, so CI, release tooling, tests, and internal
  refactoring stay out of it even when they dominate the release.
- The GitHub release notes are the new version's `CHANGELOG.md` section plus a
  compare link, so editing that section in the release PR is the way to change
  what the release page says. Publishing fails if the section is missing.
- The new version must be strictly newer than every existing `v*` tag; the
  prepare workflow fails otherwise.
- If the `release/vX.Y.Z` branch already exists from an earlier attempt,
  delete it before dispatching the workflow again.

## Agent Guardrails

- Do not modify the real `~/.idapro/plugins` contents as part of routine repo work.
- Do not point fixture-generation commands at the live `~/.idapro` unless the user explicitly asks for that.
- Do not leave docs/examples referencing old fixture symbol names after a rename.
- When changing committed fixture symbols, verify the asserted mangled names from the rebuilt binary or regenerated database instead of guessing.
- Do not stage `PLAN.md`; keep it as local planning scratch unless the user explicitly says otherwise.
- Leave unrelated untracked scratch directories and recovery artifacts alone unless the user explicitly asks to clean them up.
