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
        self.assertIs(processes.stop_group, check.stop_group)
        for script in ("check.py", "sbom.py"):
            tree = ast.parse((ROOT / "scripts" / script).read_text())
            handlers = [node for node in ast.walk(tree.body[-1]) if isinstance(node, ast.ExceptHandler)
                        and isinstance(node.type, ast.Attribute)
                        and ast.unparse(node.type) == "subprocess.TimeoutExpired"]
            self.assertEqual(1, len(handlers), script)
            self.assertIn("deadline exceeded", ast.unparse(handlers[0]).lower())
            calls = [node for node in ast.walk(tree.body[-1]) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == "install_signal_handlers"]
            self.assertEqual(1, len(calls), script)

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

    def assert_tree_stopped(self, signum=None, startup_delay=0):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "runtime.lock"
            ready = Path(directory) / "ready"
            runtime = (
                'import fcntl, pathlib, signal, sys, time; '
                'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                'handle = open(sys.argv[1], "w"); fcntl.flock(handle, fcntl.LOCK_EX); '
                f'time.sleep({startup_delay}); '
                'pathlib.Path(sys.argv[2]).write_text(str(__import__("os").getpid())); time.sleep(120)'
            )
            launcher = (
                'import subprocess, sys; '
                'child = subprocess.Popen([sys.executable, "-B", "-c", sys.argv[1], sys.argv[2], sys.argv[3]]); '
                'child.wait()'
            )
            runner = (
                'import sys; sys.path.insert(0, "scripts"); '
                'from processes import install_signal_handlers, run; '
                'install_signal_handlers(); '
                'run([sys.executable, "-B", "-c", *sys.argv[1:]], timeout=35)'
            )
            parent = subprocess.Popen([sys.executable, "-B", "-c", runner, launcher, runtime, str(lock), str(ready)],
                                      cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                deadline = time.monotonic() + 30
                while not ready.exists() or not ready.read_text().strip():
                    if parent.poll() is not None:
                        output, errors = parent.communicate()
                        self.fail(f"runner exited before its descendant was ready: {output!r} {errors!r}")
                    if time.monotonic() >= deadline:
                        self.fail("real descendant did not create its ready file within 30 seconds")
                    time.sleep(0.01)
                if signum is not None:
                    os.kill(parent.pid, signum)
                _, errors = parent.communicate(timeout=45)
                if signum is None:
                    self.assertNotEqual(0, parent.returncode)
                    self.assertIn(b"TimeoutExpired", errors)
                elif signum == signal.SIGINT:
                    self.assertIn(parent.returncode, (130, -signal.SIGINT))
                    self.assertIn(b"KeyboardInterrupt", errors)
                else:
                    self.assertEqual(128 + signum, parent.returncode, errors)
                # A released lock distinguishes a dead orphan awaiting reaping
                # from a surviving grandchild, without relying on process names.
                with lock.open() as handle:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                self.fail("grandchild still holds its runtime lock after parent cleanup")
                            time.sleep(0.01)
                    fcntl.flock(handle, fcntl.LOCK_UN)
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.communicate()
                if ready.exists():
                    try:
                        os.kill(int(ready.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_timeout_kills_runtime_even_after_its_launcher_exits_on_term(self):
        self.assert_tree_stopped()

    def test_keyboard_interrupt_kills_the_grandchild(self):
        self.assert_tree_stopped(signal.SIGINT)

    def test_hangup_to_cli_parent_kills_the_grandchild(self):
        self.assert_tree_stopped(signal.SIGHUP)

    def test_ready_poll_allows_slow_real_descendant_startup(self):
        self.assert_tree_stopped(signal.SIGINT, startup_delay=4)

    def test_termination_to_cli_parent_kills_the_grandchild(self):
        self.assert_tree_stopped(signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
