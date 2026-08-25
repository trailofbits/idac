# Tests

Test layout:

- `test_cli*.py`: parser, wrapper, context, and artifact behavior
- `test_nexus_session.py`: public ida-nexus selection, leases, execution, errors,
  analysis waits, keepalive, and save policy
- `test_remote_ops.py` and focused helper tests: remote dispatch, preview,
  result-shape, and operation semantics
- fixture-backed integration tests: real Nexus-managed IDA workers, including raw
  binary import, mutation, type, local, class, and vtable behavior
- `test_doctor.py` and `test_setup.py`: exact-stack diagnosis and pinned setup commands

Running tests:

```bash
uv run pytest -q -m "not requires_ida"
uv run pytest -q -m requires_ida
uv run pytest -q
```

Fixture notes:

- `fixtures/idb/tiny.i64` is the lightweight database for execution and mutation tests.
- `fixtures/idb/handler_hierarchy.i64` and `handler_hierarchy_stripped.i64` cover class
  and vtable flows.
- Tests open copied databases or temporary fixture binaries so each case can mutate
  safely.
- Headless integration requires Python 3.11+, IDA 9.4+, `ida-nexus==0.7.0`
  (protocol 6), and `ida-domain==0.5.1`.

Optional live Nexus GUI tests are skipped by default. Start a matching IDA session and
select its exact record ID from `idac targets list --json`, and enable them with:

```bash
IDAC_RUN_NEXUS_GUI_TESTS=1 \
IDAC_NEXUS_GUI_RECORD_ID='<record-id>' \
uv run pytest -q -m nexus_gui_live
```

The selected GUI database must be disposable. The lifecycle test temporarily changes
a line comment, explicitly saves the database, verifies a copied on-disk snapshot in a
fresh headless worker, closes and reattaches, then restores and saves the original
comment. It never auto-selects a GUI target.

Tests that start IDA receive a per-test isolated `IDAUSR` through the shared `idac_env`
fixture. It copies only required license/configuration files and does not depend on the
user's live IDA profile. Fixture regeneration outside pytest must use equivalent
isolation as documented in the repository `AGENTS.md`.
