from __future__ import annotations

import os
import queue
import signal
import threading
import time
from collections.abc import Iterator
from subprocess import Popen


class ScanInterruptedError(RuntimeError):
    """Raised when Reconmancer intentionally interrupts a stalled scan."""


def _parent_pid(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as handle:
            raw = handle.read()
    except OSError:
        return None

    # comm is wrapped in parentheses and can contain spaces. Everything after
    # the final ')' starts with: state, ppid, ...
    closing = raw.rfind(")")

    if closing < 0:
        return None

    fields = raw[closing + 1 :].strip().split()

    if len(fields) < 2:
        return None

    try:
        return int(fields[1])
    except ValueError:
        return None


def _children_of(pid: int) -> list[int]:
    """Return direct Linux child PIDs by inspecting /proc."""

    output: list[int] = []

    try:
        entries = os.listdir("/proc")
    except OSError:
        return output

    for entry in entries:
        if not entry.isdigit():
            continue

        child_pid = int(entry)

        if child_pid == pid:
            continue

        if _parent_pid(child_pid) == pid:
            output.append(child_pid)

    return output


def _process_tree(root_pid: int) -> list[int]:
    """Return descendants first, root last."""

    seen: set[int] = set()
    ordered: list[int] = []

    def visit(pid: int) -> None:
        if pid in seen:
            return

        seen.add(pid)

        for child in _children_of(pid):
            visit(child)

        ordered.append(pid)

    visit(root_pid)
    return ordered


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False

    return True


def terminate_process_tree(
    process: Popen,
    *,
    grace_seconds: float = 8.0,
) -> None:
    """
    Stop a tool subprocess and its descendants without touching the worker.

    This matters for Katana headless/deep where Chromium can have several
    descendant processes. Existing scan output is left untouched.
    """

    root_pid = int(process.pid)
    pids = _process_tree(root_pid)

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass

    deadline = time.monotonic() + max(0.0, grace_seconds)

    while time.monotonic() < deadline:
        if not any(_pid_alive(pid) for pid in pids):
            break
        time.sleep(0.2)

    for pid in pids:
        if not _pid_alive(pid):
            continue

        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass

    try:
        process.wait(timeout=2)
    except Exception:
        pass


def iter_process_stdout(
    process: Popen,
    *,
    idle_timeout_seconds: int,
    engine_name: str,
) -> Iterator[str]:
    """
    Yield stdout lines while enforcing one simple no-output timeout.

    There is deliberately no maximum runtime. A scan may run indefinitely as
    long as the tool continues to emit output. This is intended for tools such
    as HTTPX and Katana where line-oriented output is a useful progress signal.
    """

    if process.stdout is None:
        raise RuntimeError(f"{engine_name} stdout pipe is unavailable.")

    timeout = max(0, int(idle_timeout_seconds))

    if timeout == 0:
        yield from process.stdout
        return

    line_queue: queue.Queue[object] = queue.Queue()
    end_marker = object()

    def reader() -> None:
        try:
            for line in process.stdout:
                line_queue.put(line)
        finally:
            line_queue.put(end_marker)

    thread = threading.Thread(
        target=reader,
        name=f"reconmancer-{engine_name.lower()}-stdout",
        daemon=True,
    )
    thread.start()

    last_output = time.monotonic()

    while True:
        try:
            item = line_queue.get(timeout=1.0)
        except queue.Empty:
            if process.poll() is not None:
                break

            idle_for = time.monotonic() - last_output

            if idle_for >= timeout:
                reason = (
                    f"{engine_name} produced no output for "
                    f"{timeout} seconds; scan interrupted."
                )

                terminate_process_tree(process)
                raise ScanInterruptedError(reason)

            continue

        if item is end_marker:
            break

        last_output = time.monotonic()
        yield str(item)
