"""Run bounded commands and terminate every descendant in their process group."""
import os
from contextlib import contextmanager
from pathlib import Path
import signal
import stat
import subprocess
import time

SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}


def install_signal_handlers():
    """Route terminal loss and termination through normal exception cleanup."""
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    for signum in (signal.SIGHUP, signal.SIGTERM):
        if signal.getsignal(signum) != signal.SIG_IGN:
            signal.signal(signum, terminate)


def exited(process):
    """Observe an owned child's exit without releasing its PID or group ID."""
    if hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    # macOS Python lacks waitid. An unreaped child remains ours, including while
    # ps observes its zombie state; unlike Popen.poll(), ps cannot reap it.
    status = subprocess.run(["ps", "-o", "stat=", "-p", str(process.pid)],
                            capture_output=True, text=True, check=True).stdout.strip()
    return status.startswith("Z")


@contextmanager
def command(argv, **options):
    """Own a command's session and the cleanup of cooperating nested runners."""
    parent = os.environ.get("REQUESTSEAL_CLEANUP_FD")
    parent = int(parent) if parent else None
    if parent is not None:
        try:
            identity = os.fstat(parent)
            if (not stat.S_ISFIFO(identity.st_mode) or
                    os.environ.get("REQUESTSEAL_CLEANUP_ID") != f"{identity.st_dev}:{identity.st_ino}"):
                parent = None
        except OSError:
            parent = None  # An intermediate exec may close inherited descriptors.
    reader, writer = os.pipe()
    os.set_blocking(reader, False)
    process = None
    registered = False
    try:
        if parent is not None:
            os.write(parent, b"+")
            registered = True
        identity = os.fstat(writer)
        environment = dict(options.pop("env", os.environ), REQUESTSEAL_CLEANUP_FD=str(writer),
                           REQUESTSEAL_CLEANUP_ID=f"{identity.st_dev}:{identity.st_ino}")
        process = subprocess.Popen(argv, env=environment, start_new_session=True,
                                   pass_fds=(writer,), **options)
        process.cleanup_reader = reader
        process.cleanup_pending = 0
        process.cleanup_closed = False
        os.close(writer)
        writer = None
        yield process
    finally:
        try:
            if process is not None:
                stop_group(process)
        finally:
            os.close(reader)
            if writer is not None:
                os.close(writer)
            if registered:
                os.write(parent, b"-")


def nested_cleanup_pending(process):
    if not hasattr(process, "cleanup_reader"):
        return False
    while not process.cleanup_closed:
        try:
            events = os.read(process.cleanup_reader, 4096)
        except BlockingIOError:
            break
        if not events:
            process.cleanup_closed = True
            break
        process.cleanup_pending += events.count(b"+") - events.count(b"-")
    return not process.cleanup_closed and process.cleanup_pending > 0


def stop_group(process):
    """Terminate descendants before reaping the leader, keeping its pgid owned."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        if process.returncode is not None:
            return  # A reaped leader's process group ID can already have been reused.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            # macOS can deny signaling an exited, unreaped group leader.
            process.wait()
            return
        deadline = time.monotonic() + 5
        while True:
            pending = nested_cleanup_pending(process)
            # Nested runners register before spawning a separate session and
            # acknowledge only after cleaning it. Wait for those acknowledgments
            # before KILL, so an outer deadline cannot cut off inner cleanup.
            if not pending and (exited(process) or time.monotonic() >= deadline):
                break
            time.sleep(0.01)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            process.wait(timeout=0)  # Discharge the macOS error only on proven exit.
        process.wait()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def run(argv, cwd=Path(__file__).resolve().parents[1], timeout=900, extra_env=None):
    argv = list(map(str, argv))
    print("RUN " + " ".join(argv), flush=True)
    environment = dict(os.environ)
    if extra_env:
        environment.update(extra_env)
    with command(argv, cwd=cwd, env=environment) as process:
        deadline = time.monotonic() + timeout
        while not exited(process):
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(argv, timeout)
            time.sleep(0.01)
    status = process.returncode
    if status:
        raise subprocess.CalledProcessError(status, argv)
