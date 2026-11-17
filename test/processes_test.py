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

    def runtime_identity(self, pid, owner):
        # Confirm ancestry before binding a PID from a file. The test's
        # unreaped parent anchors the tree even if the runtime setsid().
        listing = subprocess.run(["ps", "-axo", "pid=,ppid="],
                                 capture_output=True, text=True, check=True).stdout
        parents = dict(map(int, row.split()) for row in listing.splitlines())
        ancestor = pid
        while ancestor in parents and ancestor != owner:
            ancestor = parents[ancestor]
        self.assertEqual(owner, ancestor, "ready-file PID does not belong to the test's process tree")
        group, session = os.getpgid(pid), os.getsid(pid)
        pidfd = os.pidfd_open(pid) if hasattr(os, "pidfd_open") else None
        return group, session, pidfd

    def test_closed_inherited_cleanup_descriptor_does_not_break_a_new_runner(self):
        # Popen closes descriptors by default, while environment variables pass
        # through. Exercise that actual exec boundary, as a test runner does.
        leaf = ('import sys; sys.path.insert(0, "scripts"); from processes import run; '
                'run([sys.executable, "-B", "-c", "pass"], timeout=10)')
        intermediary = ('import subprocess, sys; '
                        'subprocess.run([sys.executable, "-B", "-c", sys.argv[1]], check=True, timeout=15)')
        processes.run([sys.executable, "-B", "-c", intermediary, leaf], timeout=20)

    def test_ready_file_pid_cannot_authorize_signaling_an_unrelated_process(self):
        children = [subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(60)"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    for _ in range(2)]
        try:
            with self.assertRaisesRegex(AssertionError, "does not belong"):
                self.runtime_identity(children[1].pid, children[0].pid)
            self.assertIsNone(children[1].poll(), "ownership rejection signaled an unrelated process")
        finally:
            for child in children:
                child.terminate()
                child.wait(timeout=10)

    def assert_tree_stopped(self, signum=None, startup_delay=0, repeated=False, nested=False, fast=False):
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
                'import subprocess, sys, signal; '
                + ('signal.signal(signal.SIGTERM, signal.SIG_IGN); ' if repeated else '') +
                'child = subprocess.Popen([sys.executable, "-B", "-c", sys.argv[1], sys.argv[2], sys.argv[3]], '
                'stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); '
                'child.wait()'
            )
            runner = (
                'import sys, signal; sys.path.insert(0, "scripts"); '
                'signal.signal(signal.SIGINT, signal.default_int_handler); '
                'from processes import install_signal_handlers, run; '
                'install_signal_handlers(); '
                'run([sys.executable, "-B", "-c", *sys.argv[1:]], timeout=8)'
            )
            arguments = [runner, runtime] if nested else [launcher, runtime]
            log = (Path(directory) / "output").open("w+b")
            parent = subprocess.Popen([sys.executable, "-B", "-c", runner, *arguments, str(lock), str(ready)],
                                      cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
            runtime_pid = runtime_group = runtime_session = pidfd = None
            try:
                deadline = time.monotonic() + 30
                while not ready.exists() or not ready.read_text().strip():
                    if parent.poll() is not None:
                        self.fail("runner exited before its descendant was ready: " + (Path(directory) / "output").read_text())
                    if time.monotonic() >= deadline:
                        self.fail("real descendant did not create its ready file within 30 seconds")
                    time.sleep(0.01)
                runtime_pid = int(ready.read_text())
                runtime_group, runtime_session, pidfd = self.runtime_identity(runtime_pid, parent.pid)
                started = time.monotonic()
                if signum is not None:
                    os.kill(parent.pid, signum)
                    if repeated:
                        time.sleep(1)
                        os.kill(parent.pid, signal.SIGINT)
                try:
                    parent.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.fail("runner did not finish descendant cleanup within 15 seconds")
                errors = (Path(directory) / "output").read_bytes()
                if fast:
                    self.assertLess(time.monotonic() - started, 2, "TERM-responsive leader incurred the full grace period")
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
                    parent.terminate()  # Let the real runner clean up its group.
                # pidfds bind the exact runtime on Linux. On macOS verify the
                # test-owned group and session before signaling a ready-file PID.
                if runtime_pid is not None:
                    try:
                        if pidfd is not None:
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        elif (os.getpgid(runtime_pid), os.getsid(runtime_pid)) == (runtime_group, runtime_session):
                            os.kill(runtime_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finally:
                        if pidfd is not None:
                            os.close(pidfd)
                try:
                    parent.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    parent.kill()
                    parent.wait(timeout=10)
                log.close()

    def test_timeout_kills_runtime_even_after_its_launcher_exits_on_term(self):
        self.assert_tree_stopped()

    def test_keyboard_interrupt_kills_the_grandchild(self):
        self.assert_tree_stopped(signal.SIGINT, fast=True)

    def test_hangup_to_cli_parent_kills_the_grandchild(self):
        self.assert_tree_stopped(signal.SIGHUP)

    def test_ready_poll_allows_slow_real_descendant_startup(self):
        self.assert_tree_stopped(signal.SIGINT, startup_delay=4)

    def test_termination_to_cli_parent_kills_the_grandchild(self):
        self.assert_tree_stopped(signal.SIGTERM)

    def test_two_interrupts_cannot_abort_cleanup(self):
        self.assert_tree_stopped(signal.SIGINT, repeated=True)

    def test_nested_runner_finishes_its_cleanup_before_outer_kill(self):
        self.assert_tree_stopped(signal.SIGINT, nested=True)

    def test_inherited_ignored_hangup_remains_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            source = (
                'import signal, sys, time; from pathlib import Path; '
                'sys.path.insert(0, "scripts"); '
                'signal.signal(signal.SIGINT, signal.default_int_handler); '
                'from processes import install_signal_handlers; install_signal_handlers(); '
                'Path(sys.argv[1]).write_text("ready"); time.sleep(60)'
            )
            parent = subprocess.Popen([sys.executable, "-B", "-c", source, str(ready)], cwd=ROOT,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_IGN))
            try:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    self.assertIsNone(parent.poll(), "ignored-hangup runner exited before readiness")
                    self.assertLess(time.monotonic(), deadline, "ignored-hangup runner never became ready")
                    time.sleep(0.01)
                os.kill(parent.pid, signal.SIGHUP)
                time.sleep(0.2)
                self.assertIsNone(parent.poll(), "install_signal_handlers overrode inherited SIG_IGN")
            finally:
                parent.terminate()
                parent.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
