"""Process deadlines exercised with real launchers and surviving child runtimes."""
import fcntl
import json
import math
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
import processes


def cleanup_process(process):
    """Stop a test-owned group before reaping its leader, including on timeout."""
    if process.returncode is not None:
        return
    try:
        processes.signal_group(process, signal.SIGTERM)
        processes.signal_group(process, signal.SIGCONT)
        # The owner needs its full five-second budget to clean separate child
        # sessions. Keep its identity unreaped and allow propagation overhead.
        processes.exited(process, timeout=10)
    finally:
        processes.signal_group(process, signal.SIGKILL)
        process.wait(timeout=10)


def run_owned_process(argv, *, input=None, stdin=None, capture_output=False, timeout=10, **options):
    """Collect an owner result without subprocess.run's owner-only timeout kill."""
    if input is not None:
        if stdin is not None:
            raise ValueError("input and stdin are mutually exclusive")
        stdin = subprocess.PIPE
    if capture_output:
        options.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process = subprocess.Popen(argv, stdin=stdin, start_new_session=True, **options)
    try:
        output, error = process.communicate(input, timeout=timeout)
        return subprocess.CompletedProcess(argv, process.returncode, output, error)
    finally:
        try:
            cleanup_process(process)
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


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
    def test_import_preserves_the_default_interrupt_handler(self):
        processes.run([sys.executable, "-B", "-c", '''import signal, sys
sys.path.insert(0, "scripts")
assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
import processes
assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
assert before == {number: signal.getsignal(number) for number in before}
'''], timeout=10)

    def test_import_from_a_worker_thread_has_no_signal_side_effects(self):
        processes.run([sys.executable, "-B", "-c", '''import signal, sys, threading
sys.path.insert(0, "scripts")
errors = []
def load():
    try:
        import processes
    except BaseException as error:
        errors.append(error)
worker = threading.Thread(target=load)
worker.start()
worker.join()
assert not errors, errors
assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
'''], timeout=10)

    def test_success_failure_cwd_and_environment_use_real_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            processes.run([sys.executable, "-B", "-c",
                           'import os; from pathlib import Path; '
                           'assert Path.cwd() == Path(os.environ["EXPECTED_DIRECTORY"]).resolve(); '
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
        children = []
        try:
            for _ in range(2):
                children.append(subprocess.Popen(
                    [sys.executable, "-B", "-c", "import time; time.sleep(60)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
            with self.assertRaisesRegex(AssertionError, "does not belong"):
                self.runtime_identity(children[1].pid, children[0].pid)
            self.assertIsNone(children[1].poll(), "ownership rejection signaled an unrelated process")
        finally:
            for child in children:
                cleanup_process(child)

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
                cleanup_process(parent)
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

    @unittest.skipUnless(sys.platform == "darwin", "Darwin group signals can race an unreaped leader's exit")
    def test_darwin_group_signals_preserve_cleanup_during_the_leaders_exit(self):
        # TERM followed immediately by CONT covers XNU's transition from a
        # signalable member to a zombie, while its exit event is being posted.
        for iteration in range(128):
            with self.subTest(iteration=iteration):
                child = subprocess.Popen(["sleep", "60"], start_new_session=True)
                try:
                    processes.signal_group(child, signal.SIGTERM)
                    processes.signal_group(child, signal.SIGCONT)
                finally:
                    try:
                        cleanup_process(child)
                    finally:
                        if child.returncode is None:
                            child.kill()
                            child.wait(timeout=10)

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

    def test_cleanup_pipe_is_drained_during_normal_run(self):
        writer = ('import os; fd=int(os.environ["REQUESTSEAL_CLEANUP_FD"]); '
                  '[os.write(fd,b"+-") for _ in range(70000)]; print("DONE")')
        processes.run([sys.executable, "-B", "-c", writer], timeout=10)

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
                                 cwd=ROOT, env=environment, pass_fds=(writer, release_reader), start_new_session=True)
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
            cleanup_process(child)

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
                                          REQUESTSEAL_CLEANUP_ID=f"{identity.st_dev}:{identity.st_ino}"),
                                          start_new_session=True)
        os.close(writer)
        try:
            self.assertEqual(0, child.wait(timeout=10))
            self.assertEqual(b"+-", os.read(reader, 4096))
        finally:
            os.close(reader)
            cleanup_process(child)

    def test_signals_before_cleanup_entry_preserve_ownership_mask_and_exception_context(self):
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
    if signum == signal.SIGINT:
        assert isinstance(error, KeyboardInterrupt), repr(error)
    else:
        assert isinstance(error, SystemExit) and error.code == 128 + signum, repr(error)
    if original:
        assert isinstance(error.__context__, ValueError), repr(error.__context__)
        assert str(error.__context__) == "original error", repr(error.__context__)
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
print("cleanup complete; exception context and mask preserved")
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
                                             pass_fds=(writer, release_reader), start_new_session=True)
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
                        cleanup_process(child)
                        child.stdout.close()
                        if pidfd is not None:
                            try:
                                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            os.close(pidfd)
                        os.close(reader)
                        os.close(release_writer)

    def test_standalone_stop_group_defers_signals_without_explicit_installation(self):
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

    def test_standalone_file_and_event_cleanup_install_dispatchers(self):
        source = '''import os, signal, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, "scripts")
from processes import ProcessEvents, write_pid_file
with tempfile.TemporaryDirectory() as directory:
    child = subprocess.Popen(["sleep", "60"], start_new_session=True)
    events = ProcessEvents(child)
    operation = write_pid_file if sys.argv[1] == "file" else events.close
    code = operation.__wrapped__.__code__
    def interrupt(frame, event, arg):
        if event == "call" and frame.f_code is code:
            sys.settrace(None)
            os.kill(os.getpid(), signal.SIGINT)
        return interrupt
    try:
        sys.settrace(interrupt)
        try:
            if sys.argv[1] == "file":
                operation(Path(directory) / "pid", child.pid)
            else:
                operation()
        except KeyboardInterrupt:
            if sys.argv[1] == "file":
                assert (Path(directory) / "pid").read_text() == str(child.pid)
                assert list(Path(directory).iterdir()) == [Path(directory) / "pid"]
            else:
                if events.pidfd is not None:
                    try:
                        os.fstat(events.pidfd)
                    except OSError:
                        pass
                    else:
                        raise AssertionError("event queue retained its pidfd")
                if events.queue is not None:
                    assert events.queue.closed
        else:
            raise AssertionError("standalone cleanup lost SIGINT")
    finally:
        sys.settrace(None)
        if sys.argv[1] == "file":
            events.close()
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
'''
        for operation in ("file", "events"):
            with self.subTest(operation=operation):
                processes.run([sys.executable, "-B", "-c", source, operation], timeout=10)

    def test_standalone_cleanup_in_finally_keeps_a_terminating_exception(self):
        source = '''import os, signal, subprocess, sys
sys.path.insert(0, "scripts")
from processes import stop_group
def terminate(signum, frame):
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, terminate)
child = subprocess.Popen(["sleep", "60"], start_new_session=True)
original = KeyboardInterrupt()
def interrupt(frame, event, arg):
    if event == "call" and frame.f_code is stop_group.__wrapped__.__code__:
        sys.settrace(None)
        os.kill(os.getpid(), signal.SIGTERM)
    return interrupt
try:
    try:
        raise original
    finally:
        sys.settrace(interrupt)
        stop_group(child)
except BaseException as error:
    assert error is original, repr(error)
    assert child.returncode is not None, "finally cleanup retained its child"
else:
    raise AssertionError("finally cleanup suppressed the terminating exception")
finally:
    sys.settrace(None)
    if child.returncode is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=10)

    def test_protected_cleanup_from_a_worker_does_not_install_handlers(self):
        source = '''import signal, subprocess, sys, tempfile, threading
from pathlib import Path
sys.path.insert(0, "scripts")
from processes import ProcessEvents, stop_group, temporary_directory, write_pid_file
before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
errors = []
def work():
    try:
        with temporary_directory() as directory:
            child = subprocess.Popen(["sleep", "60"], start_new_session=True)
            try:
                write_pid_file(Path(directory) / "pid", child.pid)
                events = ProcessEvents(child)
                events.close()
            finally:
                stop_group(child)
    except BaseException as error:
        errors.append(error)
worker = threading.Thread(target=work)
worker.start()
worker.join(10)
assert not worker.is_alive()
assert not errors, errors
assert before == {number: signal.getsignal(number) for number in before}
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=15)

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
                                     cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            try:
                child.wait(timeout=10)
                self.assertEqual(0, child.returncode, child.stdout.read().decode())
            finally:
                cleanup_process(child)
                child.stdin.close()
                child.stdout.close()

    def test_cleanup_inside_a_handled_exception_delivers_interrupt(self):
        source = '''import os, signal, sys
from pathlib import Path
sys.path.insert(0, "scripts")
from processes import install_signal_handlers, temporary_directory
install_signal_handlers()
scratch = None
def interrupt(event, args):
    if event == "shutil.rmtree" and args[0] == scratch:
        os.kill(os.getpid(), signal.SIGINT)
sys.addaudithook(interrupt)
try:
    try:
        raise ValueError("already handled")
    except ValueError:
        with temporary_directory() as scratch:
            pass
except KeyboardInterrupt:
    assert not Path(scratch).exists()
else:
    raise AssertionError("cleanup inside except discarded SIGINT")
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=10)

    def test_standalone_cleanup_inside_except_delivers_interrupt(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
from processes import install_signal_handlers, stop_group
import subprocess
install_signal_handlers()
child = subprocess.Popen(["sleep", "60"], start_new_session=True)
code = stop_group.__wrapped__.__code__
def interrupt(frame, event, arg):
    if event == "call" and frame.f_code is code:
        sys.settrace(None)
        os.kill(os.getpid(), signal.SIGINT)
    return interrupt
try:
    try:
        raise ValueError("already handled")
    except ValueError:
        sys.settrace(interrupt)
        stop_group(child)
except KeyboardInterrupt:
    assert child.returncode is not None
else:
    raise AssertionError("standalone cleanup inside except discarded SIGINT")
finally:
    sys.settrace(None)
    if child.returncode is None:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=10)

    def test_dispatcher_after_cleanup_does_not_treat_a_handled_error_as_in_flight(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
import processes
processes.install_signal_handlers()
finished = []
def interrupt(frame, event, arg):
    if (event == "line" and frame.f_code is processes._CleanupContext.__exit__.__code__
            and frame.f_locals.get("finished")
            and frame.f_locals["function"].__name__ == "__exit__"):
        sys.settrace(None)
        os.kill(os.getpid(), signal.SIGINT)
    return interrupt
try:
    try:
        raise ValueError("already handled")
    except ValueError:
        sys.settrace(interrupt)
        with processes.cleanup_on_exit(finished.append, True):
            pass
except KeyboardInterrupt:
    assert finished == [True], finished
else:
    raise AssertionError("dispatcher discarded SIGINT after cleanup")
finally:
    sys.settrace(None)
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=10)

    def test_interrupt_then_termination_during_cleanup_exits_143(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
from processes import cleanup_on_exit, install_signal_handlers
install_signal_handlers()
def cleanup():
    os.kill(os.getpid(), signal.SIGINT)
    os.kill(os.getpid(), signal.SIGTERM)
with cleanup_on_exit(cleanup):
    pass
'''
        result = processes.run([sys.executable, "-B", "-c", source], timeout=10,
                               capture_output=True, check=False)
        self.assertEqual(143, result.returncode, result.stderr)
        self.assertEqual(b"KeyboardInterrupt\n", result.stderr)

    def test_interrupt_during_termination_delivery_keeps_exit_143(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
import processes
processes.install_signal_handlers()
injected = False
def interrupt():
    global injected
    injected = True
    os.kill(os.getpid(), signal.SIGINT)
def terminate(signum, frame):
    try:
        raise SystemExit(128 + signum)
    finally:
        if sys.argv[1] == "handler":
            interrupt()
signal.signal(signal.SIGTERM, terminate)
def observe(frame, event, arg):
    if (event == "exception" and frame.f_code is processes._deliver_pending.__code__
            and arg[0] is SystemExit and frame.f_locals.get("failure") is arg[1]
            and sys.argv[1] == "delivery" and not injected):
        sys.settrace(None)
        interrupt()
    return observe
sys.settrace(observe)
try:
    with processes.cleanup_on_exit(os.kill, os.getpid(), signal.SIGTERM):
        pass
except SystemExit:
    assert injected, "test did not inject SIGINT in the raise path"
    raise
'''
        for window in ("handler", "delivery"):
            with self.subTest(window=window):
                result = processes.run([sys.executable, "-B", "-c", source, window], timeout=10,
                                       capture_output=True, check=False)
                self.assertEqual(143, result.returncode, result.stderr)
                self.assertEqual(b"KeyboardInterrupt\n" if window == "handler" else b"", result.stderr)

    def test_distinct_pending_signals_use_class_then_arrival_order(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
from processes import cleanup_on_exit, install_signal_handlers
install_signal_handlers()
received = []
for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(number, lambda signum, frame: received.append(signum))
def cleanup():
    for number in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        os.kill(os.getpid(), number)
    assert received == [], received
with cleanup_on_exit(cleanup):
    pass
assert received == [signal.SIGHUP, signal.SIGTERM, signal.SIGINT], received
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=10)

    def test_raising_handlers_do_not_discard_other_distinct_pending_signals(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
from processes import cleanup_on_exit, install_signal_handlers
install_signal_handlers()
received = []
def handler(signum, frame):
    received.append(signum)
    if signum == signal.SIGINT:
        raise KeyboardInterrupt("interrupt handler failed")
    raise SystemExit(128 + signum)
for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(number, handler)
def cleanup():
    for number in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
        os.kill(os.getpid(), number)
try:
    with cleanup_on_exit(cleanup):
        pass
except SystemExit as error:
    assert error.code == 128 + signal.SIGHUP, error
else:
    raise AssertionError("pending handlers did not raise")
assert received == [signal.SIGHUP, signal.SIGTERM, signal.SIGINT], received
'''
        result = processes.run([sys.executable, "-B", "-c", source], timeout=10,
                               capture_output=True)
        self.assertEqual(b"SystemExit: 143\nKeyboardInterrupt: interrupt handler failed\n", result.stderr)

    def test_pending_interrupt_chains_the_exception_crossing_cleanup(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
from processes import cleanup_on_exit, install_signal_handlers
install_signal_handlers()
original = ValueError("original failure")
try:
    with cleanup_on_exit(os.kill, os.getpid(), signal.SIGINT):
        raise original
except KeyboardInterrupt as error:
    assert error.__context__ is original, repr(error.__context__)
else:
    raise AssertionError("in-flight Exception discarded SIGINT")
'''
        processes.run([sys.executable, "-B", "-c", source], timeout=10)

    def test_pending_termination_reports_the_exception_crossing_cleanup(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
from processes import cleanup_on_exit, install_signal_handlers
install_signal_handlers()
original = ValueError("original failure")
try:
    with cleanup_on_exit(os.kill, os.getpid(), signal.SIGTERM):
        raise original
except SystemExit as error:
    assert error.__context__ is original, repr(error.__context__)
    raise
'''
        result = processes.run([sys.executable, "-B", "-c", source], timeout=10,
                               capture_output=True, check=False)
        self.assertEqual(143, result.returncode, result.stderr)
        self.assertEqual(b"ValueError: original failure\n", result.stderr)

    def test_owner_prefixes_the_original_exception_and_signal_outcome(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
import processes
def terminate(frame, event, arg):
    if event == "call" and frame.f_code is processes.stop_group.__wrapped__.__code__:
        sys.settrace(None)
        os.kill(os.getpid(), signal.SIGTERM)
    return terminate
sys.argv = ["processes.py", "--", "sleep", "60"]
sys.settrace(terminate)
raise SystemExit(processes.main())
'''
        result = run_owned_process([sys.executable, "-B", "-c", source], cwd=ROOT,
                                input=b"", capture_output=True, timeout=10)
        self.assertEqual(143, result.returncode, result.stderr)
        self.assertEqual([
            b"requestseal-owner: EOFError: command owner closed stdin",
            b"requestseal-owner: received SIGTERM",
        ], result.stderr.splitlines())

    def test_original_exception_is_reported_before_a_dropped_pending_handler(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
import processes
processes.install_signal_handlers()
original = ValueError(sys.argv[1])
def cleanup():
    os.kill(os.getpid(), signal.SIGINT)
    os.kill(os.getpid(), signal.SIGTERM)
try:
    with processes.cleanup_on_exit(cleanup):
        raise original
except SystemExit as error:
    assert error.code == 143, error
    assert error.__context__ is original, repr(error.__context__)
    raise
'''
        for message in ("original failure", ""):
            with self.subTest(message=message):
                result = processes.run([sys.executable, "-B", "-c", source, message], timeout=10,
                                       capture_output=True, check=False)
                self.assertEqual(143, result.returncode, result.stderr)
                first = b"ValueError: original failure" if message else b"ValueError"
                self.assertEqual(first + b"\nKeyboardInterrupt\n", result.stderr)

    def test_in_flight_terminating_exceptions_keep_precedence(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
from processes import cleanup_on_exit, install_signal_handlers
install_signal_handlers()
original = KeyboardInterrupt() if sys.argv[1] == "interrupt" else SystemExit(19)
try:
    with cleanup_on_exit(os.kill, os.getpid(), signal.SIGTERM):
        raise original
except BaseException as error:
    assert error is original, repr(error)
else:
    raise AssertionError("terminating exception was lost")
'''
        for original in ("interrupt", "exit"):
            with self.subTest(original=original):
                processes.run([sys.executable, "-B", "-c", source, original], timeout=10)

    def test_exit_wait_ignores_eof_caller_descriptors_without_consuming_them(self):
        with processes.command(["sleep", "60"]) as child:
            reader, writer = os.pipe()
            try:
                child.events.register(reader, "caller")
                os.close(writer)
                wall, cpu = time.monotonic(), time.process_time()
                self.assertFalse(processes.exited(child, timeout=2))
                self.assertGreater(time.monotonic() - wall, 1.9)
                self.assertLess(time.process_time() - cpu, 0.08)
                self.assertEqual("caller", child.events.files[reader])
                self.assertEqual(b"", os.read(reader, 1))
            finally:
                child.events.unregister(reader)
                os.close(reader)

    def test_stop_group_signals_and_reaps_after_a_registered_fd_is_closed(self):
        with processes.command(["sleep", "60"]) as child:
            reader, writer = os.pipe()
            try:
                child.events.register(reader, "caller")
                os.close(reader)
                processes.stop_group(child)
                self.assertIsNotNone(child.returncode)
                self.assertNotIn(reader, child.events.files)
            finally:
                os.close(writer)

    @unittest.skipUnless(hasattr(select, "kqueue"), "macOS/BSD kqueue descriptor removal")
    def test_kqueue_unregister_tolerates_a_closed_descriptor(self):
        with processes.command(["sleep", "60"]) as child:
            self.assertIsNotNone(child.events.queue)
            reader, writer = os.pipe()
            try:
                child.events.register(reader, "caller")
                os.close(reader)
                child.events.unregister(reader)
                self.assertNotIn(reader, child.events.files)
            finally:
                os.close(writer)

    def test_stop_group_continues_a_stopped_child_before_waiting(self):
        with processes.command(["sleep", "60"]) as child:
            os.killpg(child.pid, signal.SIGSTOP)
            pid, status = os.waitpid(child.pid, os.WUNTRACED)
            self.assertEqual(child.pid, pid)
            self.assertTrue(os.WIFSTOPPED(status))
            started = time.monotonic()
            processes.stop_group(child)
            self.assertLess(time.monotonic() - started, 2)
            self.assertIsNotNone(child.returncode)

    def test_owner_termination_command_continues_a_stopped_child(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            owner = subprocess.Popen(
                [sys.executable, "-B", "scripts/processes.py", "--pid-file", str(pid_file),
                 "--", "sleep", "60"], cwd=ROOT,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not pid_file.exists():
                    self.assertIsNone(owner.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                pid = int(pid_file.read_text())
                owner.stdin.write(b"signal SIGSTOP\n")
                owner.stdin.flush()
                self.assertTrue(select.select([owner.stdout], [], [], 5)[0])
                self.assertEqual(b"requestseal-owner: signal SIGSTOP\n", owner.stdout.readline())
                deadline = time.monotonic() + 5
                while True:
                    state = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                                           capture_output=True, text=True, check=True, timeout=5).stdout
                    if state.strip().startswith("T"):
                        break
                    self.assertLess(time.monotonic(), deadline, "child never stopped")
                    time.sleep(0.01)
                started = time.monotonic()
                owner.stdin.write(b"signal SIGTERM\n")
                owner.stdin.flush()
                status = owner.wait(timeout=3)
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual(143, status, owner.stderr.read())
                self.assertEqual(b"requestseal-owner: signal SIGTERM\n", owner.stdout.read())
            finally:
                cleanup_process(owner)
                owner.stdin.close()
                owner.stdout.close()
                owner.stderr.close()

    def test_cli_statuses_identify_child_signal_deadline_and_nonzero_exit(self):
        for source, timeout, status, diagnostic in (
                ("import os,signal; os.kill(os.getpid(),signal.SIGTERM)", "10", 143, b""),
                ("import time; time.sleep(60)", "0.1", 124, b"requestseal-owner: command deadline"),
                ("raise SystemExit(7)", "10", 7, b""),
                ("import time; time.sleep(60)", "10", 125, b"requestseal-owner: invalid owner command"),
                ("pass", "10", 0, b"")):
            with self.subTest(status=status):
                child = subprocess.Popen([sys.executable, "-B", "scripts/processes.py", "--timeout", timeout,
                                          "--", sys.executable, "-B", "-c", source], cwd=ROOT,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         start_new_session=True)
                try:
                    if status == 125:
                        child.stdin.write(b"invalid\n")
                        child.stdin.flush()
                    child.wait(timeout=10)
                    output = child.stdout.read()
                    self.assertEqual(status, child.returncode, output)
                    if diagnostic:
                        self.assertTrue(output.startswith(diagnostic), output)
                        self.assertEqual(1, len(output.splitlines()))
                    else:
                        self.assertEqual(b"", output)
                finally:
                    cleanup_process(child)
                    child.stdin.close()
                    child.stdout.close()

    def test_cli_rejects_invalid_timeouts_before_spawning(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "spawned"
            pid_file = Path(directory) / "pid"
            source = 'from pathlib import Path; import sys; Path(sys.argv[1]).touch()'
            for timeout in ("inf", "-inf", "nan", "3000000", "2147483648", "3000000000", "0", "-1",
                            str(math.nextafter(processes.maximum_timeout(), float("inf")))):
                # 3,000,000 exceeds epoll's limit but fits a kqueue timespec.
                if timeout == "3000000" and processes.maximum_timeout() >= 3_000_000:
                    continue
                with self.subTest(timeout=timeout):
                    result = run_owned_process(
                        [sys.executable, "-B", "scripts/processes.py", "--timeout=" + timeout,
                         "--pid-file", str(pid_file), "--", sys.executable, "-B", "-c", source, str(ready)],
                        cwd=ROOT, input=b"", capture_output=True, timeout=10)
                    self.assertEqual(2, result.returncode, result.stderr)
                    self.assertIn(b"usage:", result.stderr)
                    self.assertEqual(1, result.stderr.count(b"requestseal-owner:"))
                    self.assertNotIn(b"Traceback", result.stderr)
                    self.assertFalse(ready.exists())
                    self.assertFalse(pid_file.exists(), "owner spawned a child before validating timeout")

    @unittest.skipUnless(hasattr(select, "kqueue"), "macOS/BSD kqueue timeout seconds bound")
    def test_kqueue_timeout_bound_is_int32_seconds(self):
        self.assertEqual(2147483647, processes.maximum_timeout())
        self.assertEqual(2147483647, processes.command_timeout("2147483647"))

    def test_cli_accepts_the_native_event_timeout_boundary(self):
        child = subprocess.Popen(
            [sys.executable, "-B", "scripts/processes.py", "--timeout", str(processes.maximum_timeout()),
             "--", "sleep", "0.1"], cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            status = child.wait(timeout=10)
            stderr = child.stderr.read()
            self.assertEqual(0, status, stderr)
            self.assertEqual(b"", stderr)
        finally:
            cleanup_process(child)
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()

    def test_cli_usage_errors_and_help_have_owner_diagnostics(self):
        for arguments, status in (([], 2), (["--unknown"], 2), (["--help"], 0)):
            with self.subTest(arguments=arguments):
                result = run_owned_process([sys.executable, "-B", "scripts/processes.py", *arguments],
                                        cwd=ROOT, capture_output=True, timeout=10)
                self.assertEqual(status, result.returncode, result.stderr)
                self.assertIn(b"usage:", result.stdout + result.stderr)
                self.assertEqual(1, result.stderr.count(b"requestseal-owner:"))
                self.assertNotIn(b"Traceback", result.stderr)

    def test_owner_signals_report_after_stopping_the_group_without_tracebacks(self):
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as directory:
                ready = Path(directory) / "ready"
                lock = Path(directory) / "lock"
                source = ('import fcntl,os,sys,time; from pathlib import Path; '
                          'handle=open(sys.argv[2],"w"); fcntl.flock(handle,fcntl.LOCK_EX); '
                          'Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)')
                with processes.command(
                        [sys.executable, "-B", "scripts/processes.py", "--", sys.executable,
                         "-B", "-c", source, str(ready), str(lock)], cwd=ROOT,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as owner:
                    pidfd = None
                    try:
                        deadline = time.monotonic() + 10
                        while not ready.exists() or not ready.read_text():
                            self.assertFalse(processes.exited(owner, timeout=0))
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.005)
                        pid = int(ready.read_text())
                        _, _, pidfd = self.runtime_identity(pid, owner.pid)
                        os.kill(owner.pid, signum)
                        # Keep owner stdin open so EOF cannot win the signal race.
                        self.assertTrue(processes.exited(owner, timeout=10))
                        stdout, stderr = owner.communicate(timeout=1)
                        self.assertEqual(128 + signum, owner.returncode, stderr)
                        self.assertEqual(b"", stdout)
                        self.assertEqual(
                            f"requestseal-owner: received {signal.Signals(signum).name}\n".encode(), stderr)
                        with lock.open() as handle:
                            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            fcntl.flock(handle, fcntl.LOCK_UN)
                        if pidfd is not None:
                            self.assertTrue(select.select([pidfd], [], [], 0)[0])
                    finally:
                        if pidfd is not None:
                            os.close(pidfd)

    def test_owner_eof_and_explicit_stop_have_prefixed_statuses(self):
        for request, status, message in ((b"", 125, b"command owner closed stdin"),
                                         (b"stop\n", 0, b"command stopped")):
            with self.subTest(request=request):
                result = run_owned_process(
                    [sys.executable, "-B", "scripts/processes.py", "--", "sleep", "60"],
                    cwd=ROOT, input=request, capture_output=True, timeout=10)
                self.assertEqual(status, result.returncode, result.stderr)
                self.assertEqual(b"requestseal-owner: " + message + b"\n", result.stderr)

    def test_owner_chosen_outcome_survives_signals_during_classification_and_reporting(self):
        source = '''import inspect, os, signal, sys
sys.path.insert(0, "scripts")
import processes
outcome, window = sys.argv[1:]
lines, start = inspect.getsourcelines(processes._owner_main)
classification = next(start + index for index, line in enumerate(lines)
                      if line.strip() == "if isinstance(error, KeyboardInterrupt):")
catching = next(start + index + 1 for index, line in enumerate(lines)
                if line.strip() == ("except (KeyboardInterrupt, SystemExit) as error:"
                                    if outcome == "signal" else "except Exception as error:"))
first = False
second = False
tool = sys.monitoring.DEBUGGER_ID
events = sys.monitoring.events
def entering(code, offset):
    global first, second
    if outcome == "signal" and not first and code is processes.ProcessEvents.select.__code__:
        first = True
        os.kill(os.getpid(), signal.SIGTERM)
    if not second and window == "report" and code is processes._report.__code__:
        second = True
        os.kill(os.getpid(), signal.SIGINT if outcome == "signal" else signal.SIGTERM)
def line(code, number):
    global second
    if not second and ((window == "classify" and number == classification)
                       or (window == "catch" and number == catching)):
        second = True
        os.kill(os.getpid(), signal.SIGINT if outcome == "signal" else signal.SIGTERM)
# Monitoring callbacks remain registered when the first signal raises. A trace
# callback would be removed by CPython and never inject the second signal.
sys.monitoring.use_tool_id(tool, "owner-signals")
sys.monitoring.register_callback(tool, events.PY_START, entering)
sys.monitoring.register_callback(tool, events.LINE, line)
sys.monitoring.set_local_events(tool, processes._owner_main.__code__, events.LINE)
sys.monitoring.set_local_events(tool, processes.ProcessEvents.select.__code__, events.PY_START)
sys.monitoring.set_local_events(tool, processes._report.__code__, events.PY_START)
sys.argv = ["processes.py", "--timeout", "1", "--", "sleep", "60"]
try:
    status = processes.main(restore_signal_mask=False)
finally:
    for code in (processes._owner_main.__code__, processes.ProcessEvents.select.__code__, processes._report.__code__):
        sys.monitoring.set_local_events(tool, code, 0)
    sys.monitoring.free_tool_id(tool)
assert second, "second signal was not injected in the chosen outcome path"
if outcome == "signal":
    assert first, "first signal was not injected"
raise SystemExit(status)
'''
        for outcome, window, status, message in (
                ("signal", "catch", 143, b"received SIGTERM"),
                ("signal", "classify", 143, b"received SIGTERM"),
                ("signal", "report", 143, b"received SIGTERM"),
                ("error", "catch", 125, b"command owner closed stdin"),
                ("error", "report", 125, b"command owner closed stdin")):
            with self.subTest(outcome=outcome, window=window):
                result = run_owned_process([sys.executable, "-B", "-c", source, outcome, window],
                                        cwd=ROOT, input=b"", capture_output=True, timeout=10)
                self.assertEqual(status, result.returncode, result.stderr)
                self.assertEqual(b"", result.stdout)
                self.assertEqual(b"requestseal-owner: " + message + b"\n", result.stderr)

    def test_owner_unwatchable_stdin_is_eof_and_stops_its_child(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty"
            empty.touch()
            partial = Path(directory) / "partial"
            partial.write_bytes(b"stop")  # No newline or EOF event may be required.
            for channel in (Path(os.devnull), empty, partial):
                with self.subTest(channel=channel.name), channel.open("rb") as incoming:
                    pid_file = Path(directory) / "pid"
                    result = run_owned_process(
                        [sys.executable, "-B", "scripts/processes.py", "--pid-file", str(pid_file),
                         "--timeout", "1", "--", "sleep", "60"], cwd=ROOT,
                        stdin=incoming, capture_output=True, timeout=10)
                    self.assertEqual(125, result.returncode, result.stderr)
                    self.assertEqual(b"", result.stdout)
                    self.assertEqual(b"requestseal-owner: command owner closed stdin\n", result.stderr)
                    pid = int(pid_file.read_text())
                    status = subprocess.run(["ps", "-p", str(pid), "-o", "pid="],
                                            capture_output=True, timeout=5)
                    self.assertEqual(1, status.returncode, "owner left its child running")
                    pid_file.unlink()

    def test_owner_closed_fd_zero_is_eof_and_stops_its_child(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            result = run_owned_process(
                ["sh", "-c", 'exec 0<&-; exec "$@"', "owner", sys.executable, "-B",
                 "scripts/processes.py", "--timeout", "1", "--pid-file", str(pid_file),
                 "--", "sleep", "60"], cwd=ROOT, capture_output=True, timeout=10)
            self.assertEqual(125, result.returncode, result.stderr)
            self.assertEqual(b"", result.stdout)
            self.assertEqual(b"requestseal-owner: command owner closed stdin\n", result.stderr)
            pid = int(pid_file.read_text())
            status = subprocess.run(["ps", "-p", str(pid), "-o", "pid="],
                                    capture_output=True, timeout=5)
            self.assertEqual(1, status.returncode, "owner left its child running")

    def test_owner_chosen_stop_survives_signals_after_main_and_during_shutdown(self):
        source = '''import os, runpy, sys, threading
window, release = sys.argv[1], int(sys.argv[2])
paused = False
def observe(frame, event, arg):
    global paused
    after_main = (window == "exit" and event == "exception"
                  and frame.f_code.co_filename.endswith("scripts/processes.py")
                  and frame.f_code.co_name == "<module>" and arg[0] is SystemExit)
    shutdown = (window == "shutdown" and event == "call"
                and frame.f_code is threading._shutdown.__code__)
    if not paused and (after_main or shutdown):
        paused = True
        print("paused", flush=True)
        os.read(release, 1)
        os.close(release)
    return observe
sys.settrace(observe)
sys.argv = ["scripts/processes.py", "--timeout", "1", "--", "sleep", "60"]
runpy.run_path("scripts/processes.py", run_name="__main__")
'''
        for window in ("exit", "shutdown"):
            with self.subTest(window=window):
                reader, writer = os.pipe()
                try:
                    owner = subprocess.Popen(
                        [sys.executable, "-B", "-c", source, window, str(reader)], cwd=ROOT,
                        pass_fds=(reader,), stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                except BaseException:
                    os.close(writer)
                    raise
                finally:
                    os.close(reader)
                try:
                    owner.stdin.write(b"stop\n")
                    owner.stdin.flush()
                    self.assertTrue(select.select([owner.stdout], [], [], 5)[0], "owner never paused")
                    self.assertEqual(b"paused\n", owner.stdout.readline())
                    os.kill(owner.pid, signal.SIGTERM)
                    os.kill(owner.pid, signal.SIGINT)
                    try:
                        os.write(writer, b"+")
                    except BrokenPipeError:
                        pass  # Still collect the status if a signal broke the pause.
                    stdout, stderr = owner.communicate(timeout=10)
                    self.assertEqual(0, owner.returncode, stderr)
                    self.assertEqual(b"", stdout)
                    self.assertEqual(b"requestseal-owner: command stopped\n", stderr)
                finally:
                    os.close(writer)  # Release the hook even when an assertion fails.
                    cleanup_process(owner)
                    owner.stdin.close()
                    owner.stdout.close()
                    owner.stderr.close()

    def test_in_process_owner_restores_the_neutral_reporter_on_return_and_raise(self):
        source = '''import signal, sys
sys.path.insert(0, "scripts")
import processes
mode = sys.argv[1]
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGHUP})
previous = signal.pthread_sigmask(signal.SIG_BLOCK, set())
sys.argv = ["processes.py"] if mode == "raise" else ["processes.py", "--timeout", "1", "--", "sleep", "60"]
try:
    assert processes.main() == 0
    assert mode == "return"
except SystemExit as error:
    assert mode == "raise" and error.code == 2
assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == previous
processes._report("neutral reporter")
'''
        for mode in ("return", "raise"):
            with self.subTest(mode=mode):
                result = run_owned_process([sys.executable, "-B", "-c", source, mode],
                                        cwd=ROOT, input=b"stop\n", capture_output=True, timeout=10)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(b"neutral reporter", result.stderr.splitlines()[-1])
                self.assertEqual(1, result.stderr.count(b"requestseal-owner:"))

    def test_in_process_owner_delivers_reporting_signals_to_its_caller_after_the_status_line(self):
        source = '''import os, signal, sys
sys.path.insert(0, "scripts")
import processes
signum = getattr(signal, sys.argv[1])
previous = signal.pthread_sigmask(signal.SIG_BLOCK, set())
injected = False
tool = sys.monitoring.DEBUGGER_ID
events = sys.monitoring.events
def reporting(code, offset):
    global injected
    if not injected:
        injected = True
        os.kill(os.getpid(), signum)
        assert signum in signal.sigpending(), "reporting signal was not blocked"
sys.monitoring.use_tool_id(tool, "caller-signals")
sys.monitoring.register_callback(tool, events.PY_START, reporting)
sys.monitoring.set_local_events(tool, processes._report.__code__, events.PY_START)
sys.argv = ["processes.py", "--timeout", "1", "--", "sleep", "60"]
try:
    try:
        processes.main()
    except (KeyboardInterrupt, SystemExit) as error:
        assert injected, "signal was not injected during reporting"
        if signum == signal.SIGINT:
            assert isinstance(error, KeyboardInterrupt), repr(error)
        else:
            assert isinstance(error, SystemExit) and error.code == 143, repr(error)
        traceback = error.__traceback__
        while traceback is not None:
            assert traceback.tb_frame.f_code is not processes._owner_main.__code__
            traceback = traceback.tb_next
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == previous
        processes._report("caller received " + type(error).__name__)
    else:
        raise AssertionError("main swallowed the caller's reporting signal")
finally:
    sys.monitoring.set_local_events(tool, processes._report.__code__, 0)
    sys.monitoring.free_tool_id(tool)
'''
        for name, exception in (("SIGINT", b"KeyboardInterrupt"), ("SIGTERM", b"SystemExit")):
            with self.subTest(signal=name):
                result = run_owned_process([sys.executable, "-B", "-c", source, name], cwd=ROOT,
                                        input=b"stop\n", capture_output=True, timeout=10)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(b"", result.stdout)
                self.assertEqual(b"requestseal-owner: command stopped\ncaller received "
                                 + exception + b"\n", result.stderr)

    def test_in_process_owner_redelivers_signals_suppressed_before_masking(self):
        source = '''import inspect, os, signal, sys
sys.path.insert(0, "scripts")
import processes
window = sys.argv[1]
choose_lines, choose_start = inspect.getsourcelines(processes._choose_owner_outcome)
blocking = next(choose_start + index for index, line in enumerate(choose_lines)
                if "signal.pthread_sigmask(" in line)
owner_lines, owner_start = inspect.getsourcelines(processes._owner_main)
catching = next(owner_start + index + 1 for index, line in enumerate(owner_lines)
                if line.strip() == "except Exception as error:")
target = processes._choose_owner_outcome.__code__ if window == "choose" else processes._owner_main.__code__
number = blocking if window == "choose" else catching
injected = False
previous = signal.pthread_sigmask(signal.SIG_BLOCK, set())
tool = sys.monitoring.DEBUGGER_ID
events = sys.monitoring.events
def inject(code, line):
    global injected
    if not injected and line == number:
        injected = True
        assert signal.SIGINT not in signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if window == "catch":
            frame = sys._getframe(1)
            assert "error" in frame.f_locals, "exception binding was not entered"
            assert not frame.f_locals["outcome"]["chosen"]
        os.kill(os.getpid(), signal.SIGINT)
sys.monitoring.use_tool_id(tool, "caller-unmasked-signals")
sys.monitoring.register_callback(tool, events.LINE, inject)
sys.monitoring.set_local_events(tool, target, events.LINE)
sys.argv = ["processes.py", "--timeout", "1", "--", "sleep", "60"]
try:
    try:
        processes.main(restore_signal_mask=True)
    except KeyboardInterrupt as error:
        assert injected, "signal was not injected in the unmasked window"
        traceback = error.__traceback__
        while traceback is not None:
            assert traceback.tb_frame.f_code is not processes._owner_main.__code__
            traceback = traceback.tb_next
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == previous
        processes._report("caller received KeyboardInterrupt")
    else:
        raise AssertionError("main swallowed the signal suppressed before masking")
finally:
    sys.monitoring.set_local_events(tool, target, 0)
    sys.monitoring.free_tool_id(tool)
'''
        for window, request, message in (
                ("choose", b"stop\n", b"command stopped"),
                ("catch", b"invalid\n", b"invalid owner command")):
            with self.subTest(window=window):
                result = run_owned_process([sys.executable, "-B", "-c", source, window], cwd=ROOT,
                                           input=request, capture_output=True, timeout=10)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(b"", result.stdout)
                self.assertEqual(b"requestseal-owner: " + message
                                 + b"\ncaller received KeyboardInterrupt\n", result.stderr)

    def test_in_process_owner_redelivers_each_distinct_suppressed_signal_once(self):
        source = '''import inspect, os, signal, sys
sys.path.insert(0, "scripts")
import processes
lines, start = inspect.getsourcelines(processes._choose_owner_outcome)
blocking = next(start + index for index, line in enumerate(lines) if "signal.pthread_sigmask(" in line)
received = []
injected = False
tool = sys.monitoring.DEBUGGER_ID
events = sys.monitoring.events
def inject(code, number):
    global injected
    if not injected and number == blocking:
        injected = True
        for signum in processes.SIGNALS:
            signal.signal(signum, lambda number, frame: received.append(number))
        processes._install_cleanup_handlers()
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGINT):
            os.kill(os.getpid(), signum)
        assert received == [], received
sys.monitoring.use_tool_id(tool, "caller-distinct-signals")
sys.monitoring.register_callback(tool, events.LINE, inject)
sys.monitoring.set_local_events(tool, processes._choose_owner_outcome.__code__, events.LINE)
sys.argv = ["processes.py", "--timeout", "1", "--", "sleep", "60"]
try:
    assert processes.main() == 0
finally:
    sys.monitoring.set_local_events(tool, processes._choose_owner_outcome.__code__, 0)
    sys.monitoring.free_tool_id(tool)
assert injected
assert received == [signal.SIGHUP, signal.SIGINT, signal.SIGTERM], received
'''
        result = run_owned_process([sys.executable, "-B", "-c", source], cwd=ROOT,
                                   input=b"stop\n", capture_output=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(b"", result.stdout)
        self.assertEqual(b"requestseal-owner: command stopped\n", result.stderr)

    def test_timeout_cleanup_stops_the_owner_group_and_separate_child_session(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready"
            lock = Path(directory) / "lock"
            source = ('import fcntl,os,signal,sys,time; from pathlib import Path; '
                      'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                      'handle=open(sys.argv[2],"w"); fcntl.flock(handle,fcntl.LOCK_EX); '
                      'Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)')
            owner = None
            pid = group = session = pidfd = None
            tool = sys.monitoring.DEBUGGER_ID
            events = sys.monitoring.events

            def before_communicate(code, offset):
                nonlocal owner, pid, group, session, pidfd
                if owner is not None:
                    return
                owner = sys._getframe(1).f_locals["self"]
                deadline = time.monotonic() + 30
                while not ready.exists() or not ready.read_text():
                    self.assertIsNone(owner.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                pid = int(ready.read_text())
                group, session, pidfd = self.runtime_identity(pid, owner.pid)

            sys.monitoring.use_tool_id(tool, "owner-timeout-cleanup")
            sys.monitoring.register_callback(tool, events.PY_START, before_communicate)
            sys.monitoring.set_local_events(tool, subprocess.Popen.communicate.__code__, events.PY_START)
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    # Monitoring waits for real readiness, then communicate's
                    # actual zero deadline expires. No startup timer can race it.
                    run_owned_process(
                        [sys.executable, "-B", "scripts/processes.py", "--", sys.executable,
                         "-B", "-c", source, str(ready), str(lock)], cwd=ROOT,
                        stdin=subprocess.PIPE, capture_output=True, timeout=0)
                self.assertIsNotNone(owner)
                self.assertNotEqual(owner.pid, session)
                self.assertIsNotNone(owner.returncode)
                with lock.open() as handle:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(handle, fcntl.LOCK_UN)
                if pidfd is not None:
                    self.assertTrue(select.select([pidfd], [], [], 0)[0])
            finally:
                sys.monitoring.set_local_events(tool, subprocess.Popen.communicate.__code__, 0)
                sys.monitoring.free_tool_id(tool)
                try:
                    if owner is not None:
                        cleanup_process(owner)
                finally:
                    if pid is not None:
                        try:
                            if pidfd is not None:
                                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                            elif (os.getpgid(pid), os.getsid(pid)) == (group, session):
                                os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        finally:
                            if pidfd is not None:
                                os.close(pidfd)

    def test_child_stdin_is_eof_while_the_owner_command_channel_still_works(self):
        source = 'import sys,time; assert sys.stdin.buffer.read() == b""; print("EOF",flush=True); time.sleep(60)'
        child = subprocess.Popen(
            [sys.executable, "-B", "scripts/processes.py", "--", sys.executable, "-B", "-c", source],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "child blocked on owner stdin")
            self.assertEqual(b"EOF\n", child.stdout.readline())
            child.stdin.write(b"stop\n")
            child.stdin.flush()
            status = child.wait(timeout=10)
            stderr = child.stderr.read()
            self.assertEqual(0, status, stderr)
            self.assertEqual(b"requestseal-owner: command stopped\n", stderr)
        finally:
            cleanup_process(child)
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()

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
                                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      start_new_session=True)
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
                cleanup_process(parent)
                if not parent.stdin.closed:
                    parent.stdin.close()
                if pidfd is not None:
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
                                      preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_IGN),
                                      start_new_session=True)
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
                cleanup_process(parent)


if __name__ == "__main__":
    unittest.main()
