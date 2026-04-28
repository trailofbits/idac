from __future__ import annotations

import threading
import time

from idac.transport.dispatch import DispatcherBusyError, DispatcherStoppedError, SerializedDispatcher


def test_serialized_dispatcher_runs_calls_in_submission_order() -> None:
    dispatcher = SerializedDispatcher("test-dispatcher")
    dispatcher.start()
    seen: list[int] = []
    ready = threading.Event()

    def first() -> int:
        ready.set()
        time.sleep(0.05)
        seen.append(1)
        return 1

    def second() -> int:
        seen.append(2)
        return 2

    first_thread = threading.Thread(target=lambda: dispatcher.call("first", first))
    second_result: list[int] = []
    second_thread = threading.Thread(target=lambda: second_result.append(dispatcher.call("second", second)))

    first_thread.start()
    ready.wait(timeout=1.0)
    second_thread.start()
    first_thread.join(timeout=1.0)
    second_thread.join(timeout=1.0)
    dispatcher.stop()

    assert seen == [1, 2]
    assert second_result == [2]


def test_serialized_dispatcher_rejects_calls_after_stop() -> None:
    dispatcher = SerializedDispatcher("test-dispatcher")
    dispatcher.start()
    dispatcher.stop()

    try:
        dispatcher.call("stopped", lambda: None)
    except DispatcherStoppedError as exc:
        assert "not running" in str(exc)
    else:  # pragma: no cover - defensive failure branch
        raise AssertionError("expected dispatcher stop to reject new calls")


def test_serialized_dispatcher_rejects_calls_when_queue_is_full() -> None:
    dispatcher = SerializedDispatcher("test-dispatcher", max_pending=1)
    dispatcher.start()
    entered = threading.Event()
    release = threading.Event()

    def blocking() -> int:
        entered.set()
        release.wait(timeout=1.0)
        return 1

    thread = threading.Thread(target=lambda: dispatcher.call("blocking", blocking))
    thread.start()
    entered.wait(timeout=1.0)

    try:
        dispatcher.call("overflow", lambda: 2)
    except DispatcherBusyError as exc:
        assert "queue is full" in str(exc)
    else:  # pragma: no cover - defensive failure branch
        raise AssertionError("expected full dispatcher queue to reject new calls")
    finally:
        release.set()
        thread.join(timeout=1.0)
        dispatcher.stop()


def test_serialized_dispatcher_reports_queue_metrics_for_queued_call() -> None:
    dispatcher = SerializedDispatcher("test-dispatcher")
    dispatcher.start()
    entered = threading.Event()
    release = threading.Event()
    result_holder: list[int] = []
    metrics_holder = []

    def blocking() -> int:
        entered.set()
        release.wait(timeout=1.0)
        return 1

    first_thread = threading.Thread(target=lambda: dispatcher.call("blocking", blocking))

    def second_call() -> None:
        result, metrics = dispatcher.call_with_metrics("queued", lambda: 2)
        result_holder.append(result)
        metrics_holder.append(metrics)

    second_thread = threading.Thread(target=second_call)

    first_thread.start()
    entered.wait(timeout=1.0)
    second_thread.start()

    deadline = time.monotonic() + 1.0
    while dispatcher.pending_count() != 2 and time.monotonic() < deadline:
        time.sleep(0.01)

    time.sleep(0.02)
    release.set()
    first_thread.join(timeout=1.0)
    second_thread.join(timeout=1.0)
    dispatcher.stop()

    assert result_holder == [2]
    assert len(metrics_holder) == 1
    metrics = metrics_holder[0]
    assert metrics.queue_depth_at_enqueue == 1
    assert metrics.queue_wait_seconds > 0.0
    assert metrics.run_seconds >= 0.0


def test_serialized_dispatcher_wait_for_idle_times_out_while_call_is_running() -> None:
    dispatcher = SerializedDispatcher("test-dispatcher")
    dispatcher.start()
    entered = threading.Event()
    release = threading.Event()

    def blocking() -> int:
        entered.set()
        release.wait(timeout=1.0)
        return 1

    thread = threading.Thread(target=lambda: dispatcher.call("blocking", blocking))
    thread.start()
    entered.wait(timeout=1.0)

    assert dispatcher.wait_for_idle(timeout=0.01) is False

    release.set()
    thread.join(timeout=1.0)

    assert dispatcher.wait_for_idle(timeout=1.0) is True
    dispatcher.stop()


def test_serialized_dispatcher_stop_fails_queued_calls_with_shutdown_error() -> None:
    dispatcher = SerializedDispatcher("test-dispatcher")
    dispatcher.start()
    entered = threading.Event()
    release = threading.Event()
    errors: list[str] = []

    def blocking() -> int:
        entered.set()
        release.wait(timeout=1.0)
        return 1

    def queued_call() -> None:
        try:
            dispatcher.call("queued", lambda: 2)
        except DispatcherStoppedError as exc:
            errors.append(str(exc))

    first_thread = threading.Thread(target=lambda: dispatcher.call("blocking", blocking))
    second_thread = threading.Thread(target=queued_call)

    first_thread.start()
    entered.wait(timeout=1.0)
    second_thread.start()

    deadline = time.monotonic() + 1.0
    while dispatcher.pending_count() != 2 and time.monotonic() < deadline:
        time.sleep(0.01)

    dispatcher.stop(join_timeout=0.01)
    release.set()
    first_thread.join(timeout=1.0)
    second_thread.join(timeout=1.0)

    assert errors == ["test-dispatcher dispatcher is shutting down"]
