Test layout:

- `test_cli*.py`: CLI parser, wrapper, and artifact behavior
- `test_gui_transport*.py`, `test_bridge.py`, `test_dispatch.py`, `test_doctor.py`: GUI bridge and transport behavior
- `test_idalib_*.py`: fixture-backed `idalib` integration coverage, including a raw-binary open workflow
- `test_operation_registry.py`, `test_ops_helpers.py`, `test_string_search.py`, `test_search_bytes.py`, `test_vtable_helpers.py`: focused unit coverage for operation helpers

Running tests:

```bash
uv run pytest -q
uv run pytest -q tests/test_idalib_types.py
uv run pytest -q tests/test_gui_transport.py
```

Fixture notes:

- `fixtures/idb/tiny.i64` is the lightweight database for backend and mutation tests.
- `fixtures/idb/handler_hierarchy.i64` and `handler_hierarchy_stripped.i64` cover class and vtable flows.
- Tests open copied databases or temporary fixture binaries under a temporary runtime directory so each case can mutate safely.

Live GUI tests:

- `tests/test_gui_transport_live.py` is optional and skipped by default.
- Enable it with `IDAC_RUN_LIVE_GUI_TESTS=1`.

IDA isolation:

- When regenerating fixtures or running workflows that spawn `idat`, use an isolated `IDAUSR`.
- The repo `AGENTS.md` documents the recommended isolation pattern so tests do not depend on the live `~/.idapro` profile.
