"""Process deadlines exercised with real launchers and surviving child runtimes."""
import ast
import fcntl
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check
import processes
import sbom


class ProcessGroupTest(unittest.TestCase):
    def test_both_entry_points_share_the_runner_and_handle_timeout_errors(self):
        self.assertIs(processes.run, check.run)
        self.assertIs(processes.run, sbom.run)
        for script in ("check.py", "sbom.py"):
            tree = ast.parse((ROOT / "scripts" / script).read_text())
            handlers = [node for node in ast.walk(tree.body[-1]) if isinstance(node, ast.ExceptHandler)
                        and isinstance(node.type, ast.Attribute)
                        and ast.unparse(node.type) == "subprocess.TimeoutExpired"]
            self.assertEqual(1, len(handlers), script)
            self.assertIn("deadline exceeded", ast.unparse(handlers[0]).lower())

    def test_success_failure_cwd_and_environment_use_real_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            processes.run([sys.executable, "-B", "-c",
                           'import os; from pathlib import Path; '
                           'assert Path.cwd() == Path(os.environ["EXPECTED_DIRECTORY"]); '
                           'Path("completed").write_text("done")'],
                          cwd=directory, extra_env={"EXPECTED_DIRECTORY": directory}, timeout=10)
            self.assertEqual("done", (Path(directory) / "completed").read_text())
        with self.assertRaises(subprocess.CalledProcessError) as error:
            processes.run([sys.executable, "-B", "-c", "raise SystemExit(7)"], timeout=10)
        self.assertEqual(7, error.exception.returncode)

    def test_timeout_kills_runtime_even_after_its_launcher_exits_on_term(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "runtime.lock"
            ready = Path(directory) / "ready"
            runtime = (
                'import fcntl, pathlib, signal, sys, time; '
                'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                'handle = open(sys.argv[1], "w"); fcntl.flock(handle, fcntl.LOCK_EX); '
                'pathlib.Path(sys.argv[2]).write_text(str(__import__("os").getpid())); time.sleep(30)'
            )
            launcher = (
                'import pathlib, subprocess, sys, time; '
                'subprocess.Popen([sys.executable, "-B", "-c", sys.argv[1], sys.argv[2], sys.argv[3]]); '
                '\nwhile not pathlib.Path(sys.argv[3]).exists(): time.sleep(0.01)\n'
                'time.sleep(30)'
            )
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    processes.run([sys.executable, "-B", "-c", launcher, runtime, lock, ready], timeout=3)
                self.assertTrue(ready.exists(), "the real descendant acquired its lock before timeout")
                # A released lock proves the runtime died, without confusing an
                # already-dead orphan awaiting reaping with a running process.
                with lock.open() as handle:
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.01)
                    fcntl.flock(handle, fcntl.LOCK_UN)
            finally:
                if ready.exists():
                    try:
                        os.kill(int(ready.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
