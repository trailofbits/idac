from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from idac.operations import MUTATING_OPERATIONS, REMOTE_OPERATIONS
from tests.remote_ops_harness import dispatch_with_runtime

REMOTE_OPS_PATH = Path(__file__).parents[1] / "src/idac/remote_ops.py"


@pytest.fixture(scope="module")
def remote_ops() -> ModuleType:
    module_name = "_idac_remote_ops_test"
    spec = importlib.util.spec_from_file_location(module_name, REMOTE_OPS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_remote_operation_inventory_matches_client_contract(remote_ops: ModuleType) -> None:
    # REMOTE_OPERATIONS is a hand-maintained literal, so the dedup check is not redundant.
    assert len(REMOTE_OPERATIONS) == len(set(REMOTE_OPERATIONS))
    assert set(remote_ops.SUPPORTED_OPERATIONS) == set(REMOTE_OPERATIONS)
    assert set(remote_ops.MUTATING_OPERATIONS) == MUTATING_OPERATIONS


def test_dispatch_preview_is_json_native_and_rolls_back(remote_ops: ModuleType) -> None:
    class FakeRuntime:
        def __init__(self) -> None:
            self.value = "before"

    def parse(params):
        return str(params["value"])

    def run(context, request):
        context.runtime.value = request
        return {"value": request}

    def capture(context, _request):
        return {"value": context.runtime.value}

    def rollback(context, _request, before):
        context.runtime.value = before["value"]

    operation = remote_ops.OperationSpec(
        name="probe",
        parse=parse,
        run=run,
        mutating=True,
        preview=remote_ops.PreviewSpec(
            capture_before=capture,
            capture_after=capture,
            rollback=rollback,
        ),
    )
    runtime = FakeRuntime()
    result = dispatch_with_runtime(
        runtime,
        "probe",
        {"value": "after"},
        preview=True,
        module=remote_ops,
        operation=operation,
    )

    assert result == {
        "result": {"value": "after"},
        "before": {"value": "before"},
        "after": {"value": "after"},
        "persisted": False,
        "preview": True,
        "preview_mode": "rollback",
    }
    assert runtime.value == "before"


def test_dispatch_rejects_unknown_and_unsupported_preview(remote_ops: ModuleType) -> None:
    with pytest.raises(remote_ops.IdaOperationError, match="preview must be a boolean"):
        remote_ops.dispatch(object(), "database_info", {}, 1)
    with pytest.raises(remote_ops.IdaOperationError, match="preview must be passed as the dispatch argument"):
        remote_ops.dispatch(object(), "database_info", {"preview": True}, False)
    with pytest.raises(remote_ops.IdaOperationError, match="does not accept replace or bisect"):
        remote_ops.dispatch(object(), "type_declare_check", {"decl": "typedef int value;", "replace": True}, False)

    with pytest.raises(remote_ops.IdaOperationError, match="unsupported operation: missing"):
        remote_ops.dispatch(object(), "missing", {}, False)

    with pytest.raises(remote_ops.IdaOperationError, match="preview is not supported"):
        remote_ops.dispatch(object(), "reanalyze", {"identifier": "entry"}, True)


@pytest.mark.parametrize("raise_after_mutation", [False, True])
def test_dispatch_rolls_back_failed_undo_backed_mutations(remote_ops: ModuleType, raise_after_mutation: bool) -> None:
    class FakeUndo:
        def __init__(self, runtime) -> None:
            self.runtime = runtime

        def create_undo_point(self, **_kwargs) -> bool:
            return True

        def perform_undo(self) -> bool:
            self.runtime.value = "before"
            return True

    class FakeRuntime:
        def __init__(self) -> None:
            self.value = "before"

        def mod(self, name: str) -> FakeUndo:
            assert name == "ida_undo"
            return FakeUndo(self)

    def run(context, _request):
        context.runtime.value = "mutated"
        if raise_after_mutation:
            raise RuntimeError("readback failed")
        return {"success": False, "errors": 1}

    operation = remote_ops.OperationSpec(
        name="probe",
        parse=lambda params: params,
        run=run,
        mutating=True,
        preview=remote_ops.PreviewSpec(
            capture_before=lambda context, _request: context.runtime.value,
            capture_after=lambda context, _request: context.runtime.value,
            use_undo=True,
        ),
    )
    runtime = FakeRuntime()
    if raise_after_mutation:
        with pytest.raises(RuntimeError, match="readback failed"):
            dispatch_with_runtime(runtime, "probe", {}, module=remote_ops, operation=operation)
    else:
        assert dispatch_with_runtime(runtime, "probe", {}, module=remote_ops, operation=operation) == {
            "success": False,
            "errors": 1,
        }

    assert runtime.value == "before"


def test_dispatch_undo_preview_restores_on_base_exception_and_runs_cleanup(remote_ops: ModuleType) -> None:
    class AbortPreview(BaseException):
        pass

    class FakeUndo:
        def __init__(self, runtime) -> None:
            self.runtime = runtime

        @staticmethod
        def create_undo_point(**_kwargs) -> bool:
            return True

        def perform_undo(self) -> bool:
            self.runtime.value = "before"
            return True

    class FakeRuntime:
        def __init__(self) -> None:
            self.value = "before"
            self.cleaned_up = False

        def mod(self, name: str) -> FakeUndo:
            assert name == "ida_undo"
            return FakeUndo(self)

    def run(context, _request):
        context.runtime.value = "mutated"
        raise AbortPreview

    def cleanup(context, _request) -> None:
        context.runtime.cleaned_up = True
        raise RuntimeError("cleanup failed")

    operation = remote_ops.OperationSpec(
        name="probe",
        parse=lambda params: params,
        run=run,
        mutating=True,
        preview=remote_ops.PreviewSpec(
            capture_before=lambda context, _request: context.runtime.value,
            capture_after=lambda context, _request: context.runtime.value,
            cleanup=cleanup,
            use_undo=True,
        ),
    )
    runtime = FakeRuntime()

    with pytest.raises(AbortPreview):
        dispatch_with_runtime(runtime, "probe", {}, preview=True, module=remote_ops, operation=operation)

    assert runtime.value == "before"
    assert runtime.cleaned_up is True


@pytest.mark.parametrize("failure_stage", ["runner", "after_capture"])
def test_dispatch_manual_preview_rolls_back_primary_failures(remote_ops: ModuleType, failure_stage: str) -> None:
    class FakeRuntime:
        def __init__(self) -> None:
            self.value = "before"

    def capture(context, _request):
        if failure_stage == "after_capture" and context.runtime.value == "mutated":
            raise RuntimeError("after capture failed")
        return context.runtime.value

    def run(context, _request):
        context.runtime.value = "mutated"
        if failure_stage == "runner":
            raise RuntimeError("runner failed")
        return {"changed": True}

    def rollback(context, _request, before) -> None:
        context.runtime.value = before

    operation = remote_ops.OperationSpec(
        name="probe",
        parse=lambda params: params,
        run=run,
        mutating=True,
        preview=remote_ops.PreviewSpec(capture_before=capture, capture_after=capture, rollback=rollback),
    )
    runtime = FakeRuntime()

    with pytest.raises(RuntimeError, match=r"runner failed|after capture failed"):
        dispatch_with_runtime(runtime, "probe", {}, preview=True, module=remote_ops, operation=operation)

    assert runtime.value == "before"


def test_dispatch_manual_preview_reports_rollback_failure_with_primary_cause(remote_ops: ModuleType) -> None:
    class FakeRuntime:
        value = "before"

    def capture(context, _request):
        if context.runtime.value == "mutated":
            raise RuntimeError("after capture failed")
        return context.runtime.value

    def run(context, _request):
        context.runtime.value = "mutated"
        return {"changed": True}

    def rollback(_context, _request, _before) -> None:
        raise RuntimeError("rollback failed")

    operation = remote_ops.OperationSpec(
        name="probe",
        parse=lambda params: params,
        run=run,
        mutating=True,
        preview=remote_ops.PreviewSpec(capture_before=capture, capture_after=capture, rollback=rollback),
    )
    runtime = FakeRuntime()

    with pytest.raises(RuntimeError, match="rollback failed") as excinfo:
        dispatch_with_runtime(runtime, "probe", {}, preview=True, module=remote_ops, operation=operation)

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == "after capture failed"
