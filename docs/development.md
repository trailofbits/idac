# Development

## Local setup

`idac` requires Python 3.11 or newer and pins its IDA integration stack to
`ida-nexus==0.7.0` (protocol 6) and `ida-domain==0.5.1`.

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

Install the matching IDA GUI component when testing a live desktop session:

```bash
uv run idac setup gui
uv run idac doctor
```

`setup gui` delegates installation to pinned `ida-hcli==0.19.2` and installs the
`ida-nexus` v0.7.0 release with ida-domain 0.5.1. Do not copy integration files into
IDA by hand.

## Testing

The suite has two main layers, split by the `requires_ida` marker:

- `make test-unit` runs parser, client-session, remote-bundle, renderer, and helper
  tests without IDA.
- `make test-integration` drives real Nexus-managed IDA 9.4+ workers against copied
  fixture databases. The tests are skipped when a supported licensed IDA installation
  is unavailable.
- `make coverage` runs the full suite with line coverage. Work executed inside IDA is
  outside the local Python coverage process, so use the integration assertions—not
  the local percentage—to judge the remote operation bundle.

Start with focused tests for the surface being changed, then run the broader suite:

```bash
uv run pytest -q tests/test_nexus_session.py tests/test_remote_ops.py
uv run pytest -q tests/test_ops_helpers.py tests/test_preview.py
uv run pytest -q -m requires_ida
uv run pytest -q
```

## Nexus execution structure

`src/idac/nexus.py` is the sole client-side IDA integration boundary. It uses public
ida-nexus APIs for discovery, selection, database handles, leases, analysis waits,
execution, and saves. Keep these invariants when changing it:

- `-c/--context` is a filesystem path to an `.i64` or input binary;
  `--instance` is an exact Nexus discovery record ID.
- A top-level invocation owns one lazily opened handle. Batch and preview children reuse
  it and cannot switch contexts.
- Headless opens request auto-analysis and wait for completion; attaching to a live GUI
  does not force analysis. The default headless analysis wait is finite (120 seconds),
  and an explicit `--timeout` overrides it. Analysis or compatibility failure retires
  the newly opened headless worker with `save=False`.
- Headless leases use a 300-second keepalive. Successful headless mutations are saved
  before another remote request or release; GUI saves remain explicit.
- Selection, timeout, disconnect, remote, and version failures propagate without retry,
  target switching, or alternate execution paths.
- Retiring poisoned headless state may briefly retry only Nexus `instance_busy` or
  `instance_shared` responses on the same exact worker while its prior lease callback
  finishes. This cleanup never redispatches the interrupted idac operation.
- A failed mutating dispatch or arbitrary Python execution has an uncertain IDB outcome.
  Remote failures are treated as dirty so headless finalization attempts one checkpoint;
  a failed headless save poisons the session and retires its exact worker with
  `save=False`, preventing an implicit retry at keepalive expiry. A failed preview or
  locally interrupted request follows the same discard path after prior completed steps
  have been checkpointed.
- Import only supported ida-nexus exports. Do not depend on its private registry,
  authentication, or HTTP implementation.

`src/idac/remote_ops.py` is uploaded as one self-contained `RemoteModule` source asset.
IDA does not import the local `idac` package. Keep request state and IDA objects out of
module globals, accept and return JSON-native values, and keep the source comfortably
below Nexus's 4 MiB upload ceiling.

The registry in the remote source owns IDA handlers, mutation flags, and preview
support. Keep its exported operation set in parity with the client operation list and
renderer coverage. Preview applies a real mutation, reads the temporary state, and
restores it through IDA undo or an operation-specific rollback within one remote execution.

For type declaration internals, keep `DeclarationChunk` through parsing, diagnosis,
and bisect flows; convert it to plain dictionaries only at serialization boundaries.
For reusable remote behavior, add a meaningful helper only when it reduces genuine
duplication or complexity. Keep one-off operations inline instead of introducing tiny
forwarding functions.

## Fixture binaries

The repository includes fixture binaries and `.i64` databases under
[fixtures](../fixtures). The committed class-recovery artifacts are Mach-O ARM64 files
generated on macOS/Apple Silicon.

Representative sources and helpers:

- [fixtures/src/handler_hierarchy.cpp](../fixtures/src/handler_hierarchy.cpp)
- [fixtures/src/handler_hierarchy.hpp](../fixtures/src/handler_hierarchy.hpp)
- [fixtures/scripts/build_handler_hierarchy.sh](../fixtures/scripts/build_handler_hierarchy.sh)
- [fixtures/scripts/make_handler_hierarchy_idbs.sh](../fixtures/scripts/make_handler_hierarchy_idbs.sh)

### IDA isolation

Fixture generation and tests that start IDA must not use the live `~/.idapro` profile.
Create an isolated `IDAUSR`, copy only the license/configuration files that IDA needs,
and leave its integration directory empty unless the test explicitly installs Nexus:

```bash
tmpdir=$(mktemp -d /tmp/idac-test-idapro.XXXXXX)
cp ~/.idapro/ida.reg "$tmpdir"/
cp ~/.idapro/ida-config.json "$tmpdir"/ 2>/dev/null || true
cp ~/.idapro/idapro_*.hexlic "$tmpdir"/ 2>/dev/null || true
mkdir -p "$tmpdir/plugins"
export IDAUSR="$tmpdir"
```

Then regenerate the class fixture artifacts:

```bash
bash fixtures/scripts/build_handler_hierarchy.sh
bash fixtures/scripts/make_handler_hierarchy_idbs.sh
```

The shared pytest fixture creates equivalent per-test isolation. When a live-GUI test
needs Nexus installed, point `IDAUSR` at that isolated profile before running
`idac setup gui`.

## Live Nexus GUI tests

Optional live desktop coverage is skipped by default. Start IDA 9.4+ with the matching
Nexus component loaded, use `idac targets list --json` to obtain the exact record ID
of a disposable database, then run:

```bash
IDAC_RUN_NEXUS_GUI_TESTS=1 \
IDAC_NEXUS_GUI_RECORD_ID='<record-id>' \
uv run pytest -q -m nexus_gui_live
```

This test previews a comment mutation, commits it without saving, proves a copied on-disk
database is unchanged, reattaches to prove the edit remains live in GUI memory, explicitly
saves it, checks that copy in a fresh headless worker, then restores and saves the original
comment. It never auto-selects a GUI target. Because an explicit
database save also checkpoints unrelated pending GUI edits, do not point it at a working
database.

The normal integration suite uses Nexus-managed headless workers and does not require a
desktop session.

## Continuous integration

Pull requests run lint and the no-IDA unit suite. Merge-queue runs additionally install
IDA 9.4 and execute the complete Nexus integration suite. Keep the pinned client,
in-IDA component, and ida-domain version synchronized whenever this baseline changes.
