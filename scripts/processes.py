"""Run bounded commands and terminate every descendant in their process group."""
import os
from pathlib import Path
import signal
import subprocess
import time


def install_signal_handlers():
    """Route terminal loss and termination through normal exception cleanup."""
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, terminate)


def stop_group(process):
    """Terminate descendants before reaping the leader, keeping its pgid owned."""
    if process.returncode is not None:
        return  # A reaped leader's process group ID can already have been reused.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        # macOS can deny signaling an exited, unreaped group leader.
        process.wait()
        return
    # Do not wait/poll the leader here: reaping it permits process-group ID reuse
    # while a TERM-resistant descendant can still be alive.
    time.sleep(5)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        process.wait(timeout=0)  # Discharge the macOS error only on proven exit.
    process.wait()


def run(argv, cwd=Path(__file__).resolve().parents[1], timeout=900, extra_env=None):
    argv = list(map(str, argv))
    print("RUN " + " ".join(argv), flush=True)
    environment = dict(os.environ)
    if extra_env:
        environment.update(extra_env)
    process = subprocess.Popen(argv, cwd=cwd, env=environment, start_new_session=True)
    try:
        status = process.wait(timeout=timeout)
    except BaseException:
        stop_group(process)
        raise
    if status:
        raise subprocess.CalledProcessError(status, argv)
