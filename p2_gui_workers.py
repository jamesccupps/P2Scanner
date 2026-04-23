"""
p2_gui_workers.py — Threading & stdout capture for the P2 Scanner GUI.

The p2_scanner library is synchronous and prints progress to stdout. For a
responsive GUI we run scanner calls in a single-worker background thread and
redirect stdout/stderr into a queue the UI thread can drain.

Single-worker on purpose: PXCs have a small peer-session budget (8–16) and
running parallel scans against the same panel is a good way to cause
"Max peer sessions reached" failures. Serialize the work; the user can still
interact with the UI while a scan runs.
"""

from __future__ import annotations

import queue
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout, redirect_stderr
from typing import Any, Callable, Hashable, Tuple


class QueueWriter:
    """File-like adapter. Writes into `log_queue` as (term, line) tuples.

    `term` is '\\n' for normal lines, '\\r' for carriage-return progress
    updates (which the log pane uses to overwrite in place), or '' for a
    final flush of partial buffer contents.
    """

    def __init__(self, log_queue: "queue.Queue[Tuple[str, str]]") -> None:
        self._q = log_queue
        self._buf = ""

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._buf += s
        # Drain any complete lines (terminated by \n or \r). Emit them in
        # order with their terminator; \r lines let the log pane overwrite
        # the previous line, which is how the scanner's "Verifying: 4/12"
        # progress displays work on a real terminal.
        while True:
            nl = self._buf.find("\n")
            cr = self._buf.find("\r")
            if nl < 0 and cr < 0:
                break
            if nl < 0:
                end, term = cr, "\r"
            elif cr < 0:
                end, term = nl, "\n"
            elif cr < nl:
                end, term = cr, "\r"
            else:
                end, term = nl, "\n"
            line = self._buf[:end]
            self._buf = self._buf[end + 1 :]
            self._q.put((term, line))
        return len(s)

    def flush(self) -> None:
        if self._buf:
            self._q.put(("", self._buf))
            self._buf = ""


class TaskRunner:
    """Submits scanner calls to a single background worker.

    Results arrive on `result_queue` as tuples:
        (task_id, 'ok', return_value, elapsed_seconds)
        (task_id, 'error', (exception, traceback_str), elapsed_seconds)

    Only one task may be in flight at once. submit() returns False if busy.
    """

    def __init__(
        self,
        log_queue: "queue.Queue[Tuple[str, str]]",
        result_queue: "queue.Queue[tuple]",
    ) -> None:
        self.log_queue = log_queue
        self.result_queue = result_queue
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="p2-worker"
        )
        self._lock = threading.Lock()
        self._busy = False
        self._current_task: Hashable = None

    @property
    def busy(self) -> bool:
        return self._busy

    @property
    def current_task(self) -> Hashable:
        return self._current_task

    def submit(
        self,
        task_id: Hashable,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        """Try to submit. Returns True if accepted, False if worker busy."""
        with self._lock:
            if self._busy:
                return False
            self._busy = True
            self._current_task = task_id
        self._executor.submit(self._run, task_id, func, args, kwargs)
        return True

    def _run(
        self,
        task_id: Hashable,
        func: Callable[..., Any],
        args: tuple,
        kwargs: dict,
    ) -> None:
        start = time.time()
        writer = QueueWriter(self.log_queue)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                result = func(*args, **kwargs)
                writer.flush()
            self.result_queue.put((task_id, "ok", result, time.time() - start))
        except BaseException as e:  # noqa: BLE001 - we want to surface everything
            try:
                writer.flush()
            except Exception:
                pass
            tb = traceback.format_exc()
            self.result_queue.put(
                (task_id, "error", (e, tb), time.time() - start)
            )
        finally:
            with self._lock:
                self._busy = False
                self._current_task = None

    def shutdown(self, wait: bool = False) -> None:
        self._executor.shutdown(wait=wait)
