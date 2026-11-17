"""Run bounded commands and terminate every descendant in their process group."""
import os
from pathlib import Path
import signal
import subprocess


def run(argv, cwd=Path(__file__).resolve().parents[1], timeout=900, extra_env=None):
    argv = list(map(str, argv))
    print("RUN " + " ".join(argv), flush=True)
    environment = dict(os.environ)
    if extra_env:
        environment.update(extra_env)
    process = subprocess.Popen(argv, cwd=cwd, env=environment, start_new_session=True)
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # The runtime may outlive its launcher, including after SIGTERM.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if status:
        raise subprocess.CalledProcessError(status, argv)
