"""Process deadlines exercised with real launchers and surviving child runtimes."""
import ast
import fcntl
import json
import os
from pathlib import Path
import subprocess
import signal
import select
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check
import processes
import sbom


def linux_process(pid):
    # comm may contain spaces and parentheses; the final ')' ends that field.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return fields[0], int(fields[1]), int(fields[2]), int(fields[3])


def runtime_identity(pid, owner):
    pidfd = os.pidfd_open(pid) if hasattr(os, "pidfd_open") else None
    try:
        if sys.platform.startswith("linux"):
            ancestor = pid
            while ancestor != owner and ancestor > 1:
                ancestor = linux_process(ancestor)[1]
            _, _, group, session = linux_process(pid)
            if select.select([pidfd], [], [], 0)[0]:
                raise AssertionError("ready-file process exited during ancestry verification")
        else:
            # /proc and pidfds are Linux facilities; only BSD/macOS need ps.
            listing = subprocess.run(["ps", "-axo", "pid=,ppid="],
                                     capture_output=True, text=True, check=True, timeout=10).stdout
            parents = dict(map(int, row.split()) for row in listing.splitlines())
            ancestor = pid
            while ancestor in parents and ancestor != owner:
                ancestor = parents[ancestor]
            group, session = os.getpgid(pid), os.getsid(pid)
        if ancestor != owner:
            raise AssertionError("ready-file PID does not belong to the test's process tree")
        return group, session, pidfd
    except BaseException:
        if pidfd is not None:
            os.close(pidfd)
        raise


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
        return runtime_identity(pid, owner)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux descriptor exhaustion probe")
    def test_event_registration_failure_still_kills_and_reaps_the_child(self):
        source = '''import errno, os, resource, signal, sys
sys.path.insert(0, "scripts")
from processes import ProcessEvents, command
limits = resource.getrlimit(resource.RLIMIT_NOFILE)
pid = None
def exhaust(frame, event, arg):
    global pid
    if event == "call" and frame.f_code is ProcessEvents.__init__.__code__:
        sys.settrace(None)
        pid = frame.f_locals["process"].pid
        resource.setrlimit(resource.RLIMIT_NOFILE, (0, limits[1]))
    return exhaust
sys.settrace(exhaust)
try:
    try:
        with command(["sleep", "60"]):
            raise AssertionError("event registration ignored descriptor exhaustion")
    except OSError as error:
        assert error.errno == errno.EMFILE, error
finally:
    sys.settrace(None)
    resource.setrlimit(resource.RLIMIT_NOFILE, limits)
try:
    child, _ = os.waitpid(pid, os.WNOHANG)
except ChildProcessError:
    pass
else:
    if child == 0:
        os.killpg(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    raise AssertionError("event registration failure retained its child")
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=15)

    @unittest.skipUnless(sys.platform.startswith("linux"), "pidfds bind Linux process identity")
    def test_pidfd_binds_identity_before_ancestry_reads(self):
        with processes.command(["sleep", "60"]) as child:
            observed = []

            def observe(frame, event, operation):
                if event == "c_call" and operation is os.pidfd_open:
                    observed.append("pidfd")
                elif event == "call" and frame.f_code in (linux_process.__code__, subprocess.run.__code__):
                    observed.append("ancestry")

            sys.setprofile(observe)
            try:
                _, _, pidfd = self.runtime_identity(child.pid, os.getpid())
            finally:
                sys.setprofile(None)
            try:
                self.assertEqual("pidfd", observed[0])
                self.assertIn("ancestry", observed)
            finally:
                os.close(pidfd)

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
            arguments = [runner] * int(nested) + [runtime] if nested else [launcher, runtime]
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

    def test_deeper_nested_runners_finish_before_outer_deadline(self):
        self.assert_tree_stopped(signal.SIGINT, nested=3)

    def test_signal_permission_denial_names_the_live_process_group(self):
        # A real Python audit policy denies this signal. Keep it in a disposable
        # interpreter because installed audit hooks cannot be removed.
        source = '''import signal, sys
sys.path.insert(0, "scripts")
from processes import command, signal_group
denied = True
def policy(event, args):
    if denied and event == "os.killpg" and args[1] == signal.SIGKILL:
        raise PermissionError("signal denied by audit policy")
sys.addaudithook(policy)
with command(["sleep", "10"]) as child:
    try:
        try:
            signal_group(child, signal.SIGKILL)
        except PermissionError as error:
            assert str(child.pid) in str(error) and "permission denied" in str(error)
        else:
            raise AssertionError("signal denial was discarded")
    finally:
        denied = False
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=15)

    def test_exit_event_does_not_reap_the_owned_child(self):
        with processes.command([sys.executable, "-B", "-c", "pass"]) as child:
            self.assertTrue(processes.exited(child, timeout=10))
            self.assertIsNone(child.returncode)
            if hasattr(os, "waitid"):
                status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
                self.assertEqual(child.pid, status.si_pid)
            self.assertEqual(0, child.wait(timeout=1))

    def test_wait_uses_negligible_cpu_for_a_real_sleep(self):
        started = time.process_time()
        wall = time.monotonic()
        sleeps = []
        def observe(frame, event, function):
            if event == "c_call" and getattr(function, "__name__", None) == "sleep":
                sleeps.append(function)
        sys.setprofile(observe)
        try:
            processes.run(["sleep", "2"], timeout=10)
        finally:
            sys.setprofile(None)
        self.assertEqual([], sleeps, "command wait sleep-polled")
        self.assertGreater(time.monotonic() - wall, 1.9)
        self.assertLess(time.process_time() - started, 0.08)

    def test_dead_nested_runner_cannot_hold_cleanup_open(self):
        # Keep a pidfd on the inner session: SIGKILL makes that runner unable to
        # clean its own sleep, so the test must discharge that unavoidable orphan.
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "orphan"
            inner = ('import os,sys,time; from pathlib import Path; sys.path.insert(0,"scripts"); '
                     'from processes import command; '
                     '\nwith command(["sleep","1017"]) as child:\n'
                     ' Path(sys.argv[1]).write_text(str(child.pid))\n'
                     ' while not Path(sys.argv[2]).exists(): time.sleep(0.01)\n'
                     ' os.kill(os.getpid(),9)')
            shell = 'trap "" TERM; python3 -B -c "$1" "$2" "$3"; sleep 30'
            with processes.command(["bash", "-c", shell, "bash", inner, str(ready), str(ready.with_suffix(".release"))], cwd=ROOT) as outer:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                pid = int(ready.read_text())
                group, session, pidfd = self.runtime_identity(pid, outer.pid)
                try:
                    ready.with_suffix(".release").write_text("exit")
                    time.sleep(0.1)
                    started = time.monotonic()
                    with self.assertRaises(subprocess.TimeoutExpired):
                        # Exercise run(), including the stale '+' registration.
                        processes.run(["bash", "-c", 'trap "" TERM; '
                                       'python3 -B -c "$1"; sleep 30', "bash",
                                       'import os; os.write(int(os.environ["REQUESTSEAL_CLEANUP_FD"]), b"+"); '
                                       'os.kill(os.getpid(),9)'], timeout=2)
                    self.assertLess(time.monotonic() - started, 9)
                    started = time.monotonic()
                    processes.stop_group(outer)
                    self.assertLess(time.monotonic() - started, 7)
                finally:
                    try:
                        if pidfd is not None:
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        elif (os.getpgid(pid), os.getsid(pid)) == (group, session):
                            os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finally:
                        if pidfd is not None:
                            os.close(pidfd)

    def test_cleanup_pipe_is_drained_during_normal_run_and_notebook_read(self):
        writer = ('import os; fd=int(os.environ["REQUESTSEAL_CLEANUP_FD"]); '
                  '[os.write(fd,b"+-") for _ in range(70000)]; print("DONE")')
        processes.run([sys.executable, "-B", "-c", writer], timeout=10)
        with processes.command([sys.executable, "-B", "-c", writer], stdout=subprocess.PIPE) as child:
            try:
                self.assertEqual("DONE\n", check.read_notebook(child, 10, 1024))
            finally:
                child.stdout.close()

    def test_broken_acknowledgment_does_not_replace_original_error(self):
        reader, writer = os.pipe()
        identity = os.fstat(writer)
        source = '''import os, sys
sys.path.insert(0, "scripts")
from processes import command
try:
    with command(["sleep", "0.1"]):
        os.read(int(sys.argv[1]), 1)
        raise ValueError("original error")
except ValueError as error:
    assert str(error) == "original error"
else:
    raise AssertionError("original exception lost")
'''
        release_reader, release_writer = os.pipe()
        environment = dict(os.environ, REQUESTSEAL_CLEANUP_FD=str(writer),
                           REQUESTSEAL_CLEANUP_ID=f"{identity.st_dev}:{identity.st_ino}")
        child = subprocess.Popen([sys.executable, "-B", "-c", source, str(release_reader)],
                                 cwd=ROOT, env=environment, pass_fds=(writer, release_reader))
        try:
            os.close(writer)
            writer = None
            self.assertTrue(select.select([reader], [], [], 10)[0])
            self.assertEqual(b"+", os.read(reader, 1))
            os.close(reader)
            reader = None
            os.write(release_writer, b"x")
            self.assertEqual(0, child.wait(timeout=10))
        finally:
            for fd in (reader, writer, release_reader, release_writer):
                if fd is not None:
                    os.close(fd)
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)

    def test_signal_in_registration_window_still_acknowledges_cleanup(self):
        reader, writer = os.pipe()
        identity = os.fstat(writer)
        source = '''import os, signal, sys
from pathlib import Path
sys.path.insert(0, "scripts")
from processes import command
line = next(i for i, text in enumerate(Path("scripts/processes.py").read_text().splitlines(), 1)
            if text.strip() == "registered = True")
def interrupt(frame, event, arg):
    if event == "line" and frame.f_code.co_name == "command" and frame.f_lineno == line:
        sys.settrace(None)
        os.kill(os.getpid(), signal.SIGINT)
    return interrupt
signal.signal(signal.SIGINT, signal.default_int_handler)
sys.settrace(interrupt)
try:
    with command(["sleep", "1"]):
        raise AssertionError("pending interrupt was not delivered")
except KeyboardInterrupt:
    pass
'''
        child = subprocess.Popen([sys.executable, "-B", "-c", source], cwd=ROOT, pass_fds=(writer,),
                                 env=dict(os.environ, REQUESTSEAL_CLEANUP_FD=str(writer),
                                          REQUESTSEAL_CLEANUP_ID=f"{identity.st_dev}:{identity.st_ino}"))
        os.close(writer)
        try:
            self.assertEqual(0, child.wait(timeout=10))
            self.assertEqual(b"+-", os.read(reader, 4096))
        finally:
            os.close(reader)
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)

    def test_signals_before_cleanup_entry_preserve_ownership_mask_and_original_error(self):
        source = r'''import json, os, signal, subprocess, sys
from pathlib import Path
sys.path.insert(0, "scripts")
from processes import command, install_signal_handlers, temporary_directory
install_signal_handlers()
signal.signal(signal.SIGINT, signal.default_int_handler)
signum = int(sys.argv[3])
original = sys.argv[4] == "original"
lines = Path("scripts/processes.py").read_text().splitlines()
entries = {i for i, line in enumerate(lines, 1) if line.strip() == "with blocked_signals():"}
bursts = set()
def burst():
    for _ in range(64):
        os.kill(os.getpid(), signum)
def interrupt(frame, event, arg):
    if (event == "line" and frame.f_code.co_name in ("command", "temporary_directory")
            and frame.f_lineno in entries):
        bursts.add(frame.f_code.co_name)
        burst()
    return interrupt
def removal(event, args):
    if event == "shutil.rmtree" and args[0] == scratch:
        bursts.add("removal")
        burst()
sys.addaudithook(removal)
try:
    with temporary_directory(prefix="burst-", dir=sys.argv[1]) as scratch:
        with command(["sleep", "60"], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL) as child:
            Path(sys.argv[2]).write_text(json.dumps([child.pid, scratch]))
            os.read(int(sys.argv[5]), 1)
            sys.settrace(interrupt)
            if original:
                raise ValueError("original error")
except BaseException as error:
    sys.settrace(None)
    if original:
        assert isinstance(error, ValueError) and str(error) == "original error", repr(error)
    elif signum == signal.SIGINT:
        assert isinstance(error, KeyboardInterrupt), repr(error)
    else:
        assert isinstance(error, SystemExit) and error.code == 128 + signum, repr(error)
else:
    raise AssertionError("cleanup signal was lost")
assert {"command", "temporary_directory", "removal"} <= bursts, bursts
assert not Path(scratch).exists(), scratch
assert not ({signal.SIGINT, signal.SIGTERM, signal.SIGHUP} & signal.pthread_sigmask(signal.SIG_BLOCK, set()))
try:
    os.waitpid(child.pid, os.WNOHANG)
except ChildProcessError:
    pass
else:
    raise AssertionError("child was not reaped")
print("cleanup complete; original exception and mask preserved")
'''
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            for original in ("original", "signal"):
                with self.subTest(signum=signum, exception=original), tempfile.TemporaryDirectory() as directory:
                    ready = Path(directory) / "ready"
                    reader, writer = os.pipe()
                    release_reader, release_writer = os.pipe()
                    identity = os.fstat(writer)
                    env = dict(os.environ, REQUESTSEAL_CLEANUP_FD=str(writer),
                               REQUESTSEAL_CLEANUP_ID=f"{identity.st_dev}:{identity.st_ino}")
                    child = subprocess.Popen([sys.executable, "-B", "-c", source, directory,
                                              str(ready), str(signum), original, str(release_reader)],
                                             cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                             pass_fds=(writer, release_reader))
                    os.close(writer)
                    os.close(release_reader)
                    pidfd = None
                    try:
                        deadline = time.monotonic() + 10
                        while not ready.exists() or not ready.read_text():
                            self.assertIsNone(child.poll())
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.005)
                        pid, scratch = json.loads(ready.read_text())
                        _, _, pidfd = self.runtime_identity(pid, child.pid)
                        os.write(release_writer, b"x")
                        output = child.communicate(timeout=15)[0]
                        self.assertEqual(0, child.returncode, output.decode())
                        self.assertFalse(Path(scratch).exists())
                        self.assertEqual(b"+-", os.read(reader, 4096))
                        if pidfd is not None:
                            self.assertTrue(select.select([pidfd], [], [], 0)[0])
                    finally:
                        if child.poll() is None:
                            child.terminate()
                            child.wait(timeout=10)
                        child.stdout.close()
                        if pidfd is not None:
                            try:
                                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            os.close(pidfd)
                        os.close(reader)
                        os.close(release_writer)

    def test_standalone_stop_group_defers_signals_before_its_mask_entry(self):
        source = r'''import os, signal, subprocess, sys
sys.path.insert(0, "scripts")
from processes import stop_group
child = subprocess.Popen(["sleep", "60"], start_new_session=True)
code = getattr(stop_group, "__wrapped__", stop_group).__code__
def interrupt(frame, event, arg):
    if event == "call" and frame.f_code is code:
        sys.settrace(None)
        for _ in range(64):
            os.kill(os.getpid(), signal.SIGINT)
    return interrupt
try:
    sys.settrace(interrupt)
    try:
        stop_group(child)
    except KeyboardInterrupt:
        pass
    else:
        raise AssertionError("standalone cleanup discarded its interrupt")
    assert child.returncode is not None, "standalone cleanup retained its child"
    assert not ({signal.SIGINT, signal.SIGTERM, signal.SIGHUP} & signal.pthread_sigmask(signal.SIG_BLOCK, set()))
finally:
    sys.settrace(None)
    if child.returncode is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=10)

    def test_owner_pid_file_is_atomically_published(self):
        source = r'''import os, runpy, sys
from pathlib import Path
path = Path(sys.argv[1])
renames = []
def audit(event, args):
    if event == "os.rename" and args[1] == str(path):
        assert Path(args[0]).read_text().isdigit()
        assert not path.exists()
        renames.append(event)
def observe(frame, event, arg):
    if event == "return" and frame.f_code.co_name == "open" and frame.f_locals.get("self") == path:
        if "w" in frame.f_locals.get("mode", ""):
            assert path.read_text().isdigit(), "pid file exposed before its contents"
    return observe
sys.addaudithook(audit)
sys.settrace(observe)
sys.argv = ["scripts/processes.py", "--pid-file", str(path), "--", "sleep", "0.1"]
try:
    runpy.run_path("scripts/processes.py", run_name="__main__")
except SystemExit as error:
    assert error.code == 0, error
sys.settrace(None)
assert renames == ["os.rename"], renames
assert path.read_text().isdigit()
assert list(path.parent.iterdir()) == [path], list(path.parent.iterdir())
'''
        with tempfile.TemporaryDirectory() as directory:
            child = subprocess.Popen([sys.executable, "-B", "-c", source, str(Path(directory) / "pid")],
                                     cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                child.wait(timeout=10)
                self.assertEqual(0, child.returncode, child.stdout.read().decode())
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)
                child.stdin.close()
                child.stdout.close()

    def test_cli_statuses_identify_child_signal_deadline_and_nonzero_exit(self):
        for source, timeout, status, diagnostic in (
                ("import os,signal; os.kill(os.getpid(),signal.SIGTERM)", "10", 143, b""),
                ("import time; time.sleep(60)", "0.1", 124, b"requestseal-owner: command deadline"),
                ("raise SystemExit(7)", "10", 7, b""),
                ("import time; time.sleep(60)", "inf", 125, b"requestseal-owner:")):
            with self.subTest(status=status):
                child = subprocess.Popen([sys.executable, "-B", "scripts/processes.py", "--timeout", timeout,
                                          "--", sys.executable, "-B", "-c", source], cwd=ROOT,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                try:
                    child.wait(timeout=10)
                    output = child.stdout.read()
                    self.assertEqual(status, child.returncode, output)
                    if diagnostic:
                        self.assertTrue(output.startswith(diagnostic), output)
                        self.assertEqual(1, len(output.splitlines()))
                    else:
                        self.assertEqual(b"", output)
                finally:
                    if child.poll() is None:
                        child.terminate()
                        child.wait(timeout=10)
                    child.stdin.close()
                    child.stdout.close()

    def test_cleanup_wait_ignores_every_caller_descriptor(self):
        with processes.command([sys.executable, "-B", "-c",
                                'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                                'print("ready",flush=True); time.sleep(60)'], stdout=subprocess.PIPE) as child:
            self.assertEqual(b"ready\n", child.stdout.readline())
            pipes = [os.pipe() for _ in range(3)]
            try:
                for (reader, writer), label in zip(pipes, ("output", "stderr", "notebook")):
                    child.events.register(reader, label)
                    os.close(writer)  # Every EOF remains readable until unregistered.
                wall, cpu = time.monotonic(), time.process_time()
                processes.stop_group(child)
                elapsed = time.monotonic() - wall
                used = time.process_time() - cpu
                print(f"caller-descriptor cleanup: wall={elapsed:.3f}s cpu={used:.4f}s", flush=True)
                self.assertLess(used, elapsed * 0.1)
                self.assertTrue(all(reader not in child.events.files for reader, _ in pipes))
            finally:
                for reader, _ in pipes:
                    os.close(reader)
                child.stdout.close()

    def test_port_owner_eof_kills_a_separate_command_session(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            source = ('import os,signal,time; from pathlib import Path; '
                      'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                      'Path(__import__("sys").argv[1]).write_text(str(os.getpid())); time.sleep(120)')
            parent = subprocess.Popen([sys.executable, "-B", "scripts/processes.py", "--timeout", "30", "--",
                                       sys.executable, "-B", "-c", source, str(ready)], cwd=ROOT,
                                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pidfd = None
            try:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    self.assertIsNone(parent.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                pid = int(ready.read_text())
                _, _, pidfd = self.runtime_identity(pid, parent.pid)
                parent.stdin.close()
                started = time.monotonic()
                _, status, usage = os.wait4(parent.pid, 0)
                parent.returncode = os.waitstatus_to_exitcode(status)
                elapsed = time.monotonic() - started
                used = usage.ru_utime + usage.ru_stime
                print(f"owner EOF cleanup: wall={elapsed:.3f}s cpu={used:.4f}s", flush=True)
                self.assertLess(used, elapsed * 0.1)
                self.assertEqual(125, parent.returncode)
                if pidfd is not None:
                    self.assertTrue(select.select([pidfd], [], [], 2)[0])
            finally:
                if parent.poll() is None:
                    parent.terminate()
                    parent.wait(timeout=10)
                if not parent.stdin.closed:
                    parent.stdin.close()
                if pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.close(pidfd)

    @unittest.skipUnless(sys.platform.startswith("linux"), "pidfds bind the runtime after BEAM death")
    def test_beam_death_cleans_the_runtime_owned_by_its_port(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            runtime = ('import os,signal,sys,time; from pathlib import Path; '
                       'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                       'Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(120)')
            beam = ('Code.require_file("test/support/system_command.ex"); '
                    'RequestSeal.SystemCommand.run(System.find_executable("python3"), System.argv())')
            with processes.command(["elixir", "-e", beam, "--", "-B", "-c", runtime, str(ready)],
                                   cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as parent:
                deadline = time.monotonic() + 20
                while not ready.exists():
                    self.assertFalse(processes.exited(parent, timeout=0))
                    self.assertLess(time.monotonic(), deadline, "BEAM port did not start its real runtime")
                    time.sleep(0.01)
                pid = int(ready.read_text())
                _, _, pidfd = self.runtime_identity(pid, parent.pid)
                try:
                    os.kill(parent.pid, signal.SIGKILL)
                    self.assertTrue(select.select([pidfd], [], [], 10)[0],
                                    "runtime survived the death of its BEAM port owner")
                finally:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.close(pidfd)

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
