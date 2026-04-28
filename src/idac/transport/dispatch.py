from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar, cast

T = TypeVar("T")


class DispatcherStoppedError(RuntimeError):
    """Raised when a serialized dispatcher is unavailable or shutting down."""

    pass


class DispatcherBusyError(RuntimeError):
    """Raised when a serialized dispatcher refuses new work."""

    pass


@dataclass(frozen=True)
class DispatchMetrics:
    """Timing and queue metrics recorded for one dispatcher call."""

    queue_depth_at_enqueue: int
    queue_wait_seconds: float
    run_seconds: float


@dataclass
class DispatchCall:
    """One queued call executed by a serialized dispatcher."""

    label: str
    fn: Callable[[], Any]
    queue_depth_at_enqueue: int = 0
    done: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    error: BaseException | None = None
    enqueued_at: float = field(default_factory=time.monotonic)
    started_at: float | None = None
    finished_at: float | None = None


class SerializedDispatcher:
    """Run queued calls one-at-a-time in FIFO order."""

    def __init__(
        self,
        name: str,
        *,
        runner: Callable[[Callable[[], Any]], Any] | None = None,
        max_pending: int | None = None,
    ) -> None:
        self._name = name
        self._runner = runner or self._run_inline
        self._queue: queue.Queue[DispatchCall | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._stopping = False
        self._max_pending = max_pending
        self._pending = 0

    @staticmethod
    def _run_inline(fn: Callable[[], T]) -> T:
        return fn()

    def start(self) -> None:
        """Start the background worker if it is not already running."""

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stopping = False
            thread = threading.Thread(
                target=self._worker,
                name=f"{self._name}-dispatcher",
                daemon=True,
            )
            thread.start()
            self._thread = thread

    def stop(self, *, join_timeout: float = 1.0) -> None:
        """Stop the worker and fail any queued-but-not-started calls."""

        with self._lock:
            if self._thread is None:
                return
            self._stopping = True
            thread = self._thread
            self._thread = None
            self._queue.put(None)

        self._fail_pending_calls()
        thread.join(timeout=join_timeout)

    def call(self, label: str, fn: Callable[[], T]) -> T:
        """Queue a call and wait until it has run."""

        result, _ = self.call_with_metrics(label, fn)
        return result

    def call_with_metrics(self, label: str, fn: Callable[[], T]) -> tuple[T, DispatchMetrics]:
        """Queue a call, wait until it has run, and return timing metrics."""

        with self._lock:
            thread = self._thread
            if self._stopping or thread is None or not thread.is_alive():
                raise DispatcherStoppedError(f"{self._name} dispatcher is not running")
            if self._max_pending is not None and self._pending >= self._max_pending:
                raise DispatcherBusyError(
                    f"{self._name} dispatcher queue is full ({self._pending}/{self._max_pending})"
                )
            queue_depth_at_enqueue = self._pending
            self._pending += 1

        call = DispatchCall(
            label=label,
            fn=fn,
            queue_depth_at_enqueue=queue_depth_at_enqueue,
        )
        self._queue.put(call)
        call.done.wait()
        if call.error is not None:
            raise call.error
        started_at = call.started_at or call.enqueued_at
        finished_at = call.finished_at or started_at
        metrics = DispatchMetrics(
            queue_depth_at_enqueue=call.queue_depth_at_enqueue,
            queue_wait_seconds=max(0.0, started_at - call.enqueued_at),
            run_seconds=max(0.0, finished_at - started_at),
        )
        return cast(T, call.result), metrics

    def pending_count(self) -> int:
        """Return the number of accepted calls that are queued or running."""

        with self._lock:
            return self._pending

    def max_pending(self) -> int | None:
        """Return the configured maximum accepted pending calls."""

        return self._max_pending

    def wait_for_idle(self, timeout: float | None = None) -> bool:
        """Wait until no accepted calls are queued or running."""

        deadline = None if timeout is None else time.monotonic() + timeout
        with self._idle:
            while self._pending != 0:
                if deadline is None:
                    self._idle.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._idle.wait(timeout=remaining)
            return True

    def _fail_pending_calls(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return
            if item is None:
                self._queue.put(None)
                return
            item.error = DispatcherStoppedError(f"{self._name} dispatcher is shutting down")
            item.done.set()
            self._queue.task_done()
            with self._idle:
                self._pending = max(0, self._pending - 1)
                if self._pending == 0:
                    self._idle.notify_all()

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            try:
                item.started_at = time.monotonic()
                item.result = self._runner(item.fn)
            except BaseException as exc:
                item.error = exc
            finally:
                item.finished_at = time.monotonic()
                item.done.set()
                self._queue.task_done()
                with self._idle:
                    self._pending = max(0, self._pending - 1)
                    if self._pending == 0:
                        self._idle.notify_all()
