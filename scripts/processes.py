"""Own command sessions and wait for exit without releasing their process identity.

Entry points must call install_signal_handlers() before acquiring resources.
Importing this module does not change signal handlers.
Protected calls also wrap current handlers on entry from the main thread.
Signals arriving before that installation run the previous handler; entry
points avoid that window by calling install_signal_handlers() first.
For standalone cleanup, a KeyboardInterrupt or SystemExit visible through
sys.exc_info() keeps precedence, including in a finally block. An ordinary
handled exception does not suppress signals; Python supplies implicit chaining.
Context managers use their own __exit__ exception arguments instead.
If an enclosing except KeyboardInterrupt or SystemExit block swallows its
exception, signals pending during a protected call there have already been
dropped under that precedence rule.

CLI outcome                              Status
Child exit                               The child's status
Child killed by signal N                 128 + N
Deadline                                 124
Owner failure or command-channel EOF      125
Usage error                              2 (with usage text)
Owner signaled (TERM, HUP, INT)           128 + N, after group cleanup
Explicit stop or help                    0
Exception interrupted by owner signal    128 + N, plus original-exception report

Every owner outcome emits one stderr line beginning ``requestseal-owner:``.
An interrupted ordinary exception adds one prefixed type-and-message report.
Exceptions from later pending handlers also get type-and-message reports while
the first handler's exception keeps precedence.
Child outcomes emit no such line. Signals name the signal, without a traceback.
Once main() chooses an outcome, further owner signals cannot change its status
or interrupt its report, including through CLI exit and interpreter shutdown.
In-process callers regain their previous signal mask when main() returns.
As with shell commands, a child can itself choose a reserved status; the prefix
distinguishes an owner outcome in merged output. Child stdin is /dev/null;
owner stdin carries only owner commands.
"""
import argparse
from contextlib import contextmanager
import errno
from functools import wraps
import math
import os
from pathlib import Path
import select
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
CLEANUP_SECONDS = 5


# A mask alone cannot protect its own entry: CPython can run an already
# scheduled handler from pthread_sigmask. Dispatchers recognize the entire
# protected call frame, including its first bytecode and context exit, and hold
# distinct signals until cleanup and mask restoration finish. Termination and
# hangup precede interrupt; an in-flight KeyboardInterrupt or SystemExit wins.
# These command-line owners are single-threaded.
_pending_signals = {}
_report_prefix = ""


def _report(message, *, file=None, flush=False):
    print(_report_prefix + " ".join(str(message).splitlines()),
          file=sys.stderr if file is None else file, flush=flush)


def _deliver_pending(pending, original, delivery):
    if isinstance(original, (KeyboardInterrupt, SystemExit)):
        pending.clear()
        return
    while pending:
        # Keep new signals queued until a handler's raised exception has been
        # recorded. The queue remains live while handlers themselves execute.
        delivery["active"] = True
        pending.sort(key=lambda item: item[1] == signal.SIGINT)
        handler, signum, frame = pending.pop(0)
        delivery["seen"].add(signum)
        try:
            handler(signum, frame)
        except BaseException as error:
            if original is not None:
                error.__context__ = original
            if delivery["failure"] is None:
                delivery["failure"] = error
            else:
                _report(f"{type(error).__name__}: {error}")
        delivery["active"] = False
    failure = delivery["failure"]
    if failure is not None:
        if original is not None and isinstance(failure, SystemExit):
            _report(f"{type(original).__name__}: {original}")
        raise failure


def _cleanup_call(function):
    @wraps(function)
    def protected(*args, **kwargs):
        original = sys.exc_info()[1]
        if function.__name__ == "__exit__":
            original = args[2]
        elif function.__name__ == "__enter__" or not isinstance(original, (KeyboardInterrupt, SystemExit)):
            original = None
        finished = False
        delivery = {"active": False, "failure": None, "seen": set()}
        try:
            _install_cleanup_handlers()
            try:
                result = function(*args, **kwargs)
                if function.__name__ == "__exit__" and result:
                    original = None  # The manager suppressed the body exception.
                pending = _pending_signals.setdefault(id(sys._getframe()), [])
                finished = True
                _deliver_pending(pending, original, delivery)
                return result
            except BaseException as error:
                original = error
                finished = False
                try:
                    # Python does not call __exit__ when __enter__ raises after yield.
                    if function.__name__ == "__enter__" and args[0].entered:
                        args[0].manager.__exit__(*sys.exc_info())
                except BaseException as cleanup_error:
                    original = cleanup_error
                    raise
                finally:
                    pending = _pending_signals.setdefault(id(sys._getframe()), [])
                    finished = True
                    _deliver_pending(pending, original, delivery)
                raise
        finally:
            _pending_signals.pop(id(sys._getframe()), None)
    return protected


def _install_cleanup_handlers():
    if threading.current_thread() is not threading.main_thread():
        return
    for signum in SIGNALS:
        handler = signal.getsignal(signum)
        if not callable(handler) or getattr(handler, "_cleanup_dispatcher", False):
            continue

        def dispatch(signum, frame, handler=handler):
            protected = None
            terminating = False
            current = frame
            while current is not None:
                # The owner has already finished resource cleanup. Protect its
                # selected outcome through reporting and main's final return,
                # including signals already scheduled before a mask could act.
                # An except binding selects failure before its first statement.
                if (current.f_code is main.__code__
                        and (current.f_locals.get("outcome", {}).get("chosen", False)
                             or "error" in current.f_locals)):
                    return
                if current.f_code is _CleanupContext.__exit__.__code__:
                    delivery = current.f_locals.get("delivery", {})
                    terminating |= isinstance(current.f_locals.get("original"),
                                              (KeyboardInterrupt, SystemExit))
                    terminating |= isinstance(delivery.get("failure"), (KeyboardInterrupt, SystemExit))
                    if (not current.f_locals.get("finished", False) or delivery.get("active")
                            or _pending_signals.get(id(current))):
                        protected = current
                current = current.f_back
            if protected is not None:
                pending = _pending_signals.setdefault(id(protected), [])
                seen = protected.f_locals.get("delivery", {}).get("seen", ())
                if signum not in seen and all(item[1] != signum for item in pending):
                    pending.append((handler, signum, frame))
            elif not terminating:
                handler(signum, frame)

        dispatch._cleanup_dispatcher = True
        signal.signal(signum, dispatch)


class _CleanupContext:
    def __init__(self, manager):
        self.manager = manager
        self.entered = False

    @_cleanup_call
    def __enter__(self):
        result = self.manager.__enter__()
        self.entered = True
        return result

    @_cleanup_call
    def __exit__(self, *exception):
        return self.manager.__exit__(*exception)


def cleanup_contextmanager(function):
    factory = contextmanager(function)

    @wraps(function)
    def create(*args, **kwargs):
        _install_cleanup_handlers()
        return _CleanupContext(factory(*args, **kwargs))
    return create


@cleanup_contextmanager
def cleanup_on_exit(function, *args, **kwargs):
    """Finish a cleanup callback before delivering a handled signal."""
    try:
        yield
    finally:
        function(*args, **kwargs)


@cleanup_contextmanager
def blocked_signals():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        yield previous
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@cleanup_contextmanager
def temporary_directory(**options):
    """Remove owned scratch before delivering any repeated termination signal."""
    directory = tempfile.TemporaryDirectory(**options)
    try:
        yield directory.name
    finally:
        with blocked_signals():
            directory.cleanup()


def install_signal_handlers():
    """Route terminal loss and termination through normal exception cleanup."""
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    for signum in (signal.SIGHUP, signal.SIGTERM):
        if signal.getsignal(signum) != signal.SIG_IGN:
            signal.signal(signum, terminate)
    _install_cleanup_handlers()


class ProcessEvents:
    """One kernel queue for exit, cleanup messages, and captured output."""

    def __init__(self, process, *, exit_only=False):
        self.process = process
        self.exited = False
        self.files = {}
        self.pidfd = None
        self.queue = None
        self.selector = None
        try:
            if sys.platform.startswith("linux") and hasattr(os, "pidfd_open"):
                self.selector = selectors.DefaultSelector()
                self.pidfd = os.pidfd_open(process.pid)
                self.selector.register(self.pidfd, selectors.EVENT_READ, "exit")
            elif hasattr(select, "kqueue"):
                self.queue = select.kqueue()
                try:
                    self.queue.control([select.kevent(
                        process.pid, filter=select.KQ_FILTER_PROC,
                        flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                        fflags=select.KQ_NOTE_EXIT)], 0, 0)
                except ProcessLookupError:
                    # Darwin's EVFILT_PROC is edge-triggered and proc_find()
                    # excludes zombies. ESRCH for our unreaped child proves it
                    # exited before registration; its PID still cannot be reused.
                    self.exited = True
            else:
                raise RuntimeError("Process exit events require Linux with pidfds, macOS, or BSD with kqueue")
            if not exit_only and hasattr(process, "cleanup_reader"):
                self.register(process.cleanup_reader, "cleanup")
        except BaseException:
            self.close()
            raise

    def register(self, fileobj, data):
        fd = fileobj if isinstance(fileobj, int) else fileobj.fileno()
        self.files[fd] = data
        try:
            if self.selector is not None:
                self.selector.register(fd, selectors.EVENT_READ, data)
            else:
                self.queue.control([select.kevent(fd, filter=select.KQ_FILTER_READ,
                                                  flags=select.KQ_EV_ADD)], 0, 0)
        except OSError:
            del self.files[fd]
            raise

    def unregister(self, fileobj):
        fd = fileobj if isinstance(fileobj, int) else fileobj.fileno()
        del self.files[fd]
        if self.selector is not None:
            self.selector.unregister(fd)
        else:
            try:
                self.queue.control([select.kevent(fd, filter=select.KQ_FILTER_READ,
                                                  flags=select.KQ_EV_DELETE)], 0, 0)
            except OSError as error:
                # Closing a descriptor also removes its kqueue registration.
                if error.errno not in (errno.EBADF, errno.ENOENT):
                    raise

    def select(self, timeout=None):
        if timeout is not None:
            # Absolute deadline arithmetic can round a boundary value upward.
            timeout = min(timeout, maximum_timeout())
        if self.selector is not None:
            events = [(key.fd, key.data) for key, _ in self.selector.select(timeout)]
        else:
            events = [(event.ident, "exit" if event.filter == select.KQ_FILTER_PROC
                       else self.files[event.ident])
                      for event in self.queue.control(None, len(self.files) + 1, timeout)]
        ready = []
        for fd, data in events:
            if data == "exit":
                self.exited = True
                if self.selector is not None:
                    self.selector.unregister(self.pidfd)
            elif data == "cleanup":
                nested_cleanup_pending(self.process)
                if self.process.cleanup_closed:
                    self.unregister(fd)
            else:
                ready.append((fd, data))
        return ready

    @_cleanup_call
    def close(self):
        if self.selector is not None:
            self.selector.close()
        if self.queue is not None:
            self.queue.close()
        if self.pidfd is not None:
            os.close(self.pidfd)


@cleanup_contextmanager
def process_events(process, *, exit_only=False):
    events = None if exit_only else getattr(process, "events", None)
    owned = events is None
    if owned:
        events = ProcessEvents(process, exit_only=exit_only)
    try:
        yield events
    finally:
        if owned:
            events.close()


def exited(process, timeout=None):
    """Block for an owned child's exit without releasing its PID or group ID."""
    if process.returncode is not None:
        return True
    if timeout == 0 and hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    # A separate exit queue leaves caller registrations intact and cannot wake
    # on their output or EOF, including a continuously readable cleanup pipe.
    with process_events(process, exit_only=True) as events:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not events.exited:
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            events.select(remaining)
            if deadline is not None and time.monotonic() >= deadline:
                break
        return events.exited


@cleanup_contextmanager
def command(argv, **options):
    """Own a command's session and the cleanup of cooperating nested runners."""
    parent = os.environ.get("REQUESTSEAL_CLEANUP_FD")
    parent = int(parent) if parent else None
    depth = 0
    if parent is not None:
        try:
            identity = os.fstat(parent)
            if (not stat.S_ISFIFO(identity.st_mode) or
                    os.environ.get("REQUESTSEAL_CLEANUP_ID") != f"{identity.st_dev}:{identity.st_ino}"):
                parent = None
            else:
                depth = int(os.environ.get("REQUESTSEAL_CLEANUP_DEPTH", "0"))
        except (OSError, ValueError):
            parent = None  # An intermediate exec may close inherited descriptors.
    reader, writer = os.pipe()
    os.set_blocking(reader, False)
    process = None
    registered = False
    try:
        # Registration and its flag must be indivisible to the handled signals.
        # Also finish Popen ownership before a pending signal can start cleanup;
        # restore the child's mask before exec (these scripts are single-threaded).
        with blocked_signals() as previous:
            if parent is not None:
                try:
                    os.write(parent, b"+")
                    registered = True
                except BrokenPipeError:
                    parent = None
            identity = os.fstat(writer)
            environment = dict(options.pop("env", os.environ), REQUESTSEAL_CLEANUP_FD=str(writer),
                               REQUESTSEAL_CLEANUP_ID=f"{identity.st_dev}:{identity.st_ino}",
                               REQUESTSEAL_CLEANUP_DEPTH=str(depth + 1))
            process = subprocess.Popen(
                argv, env=environment, start_new_session=True, pass_fds=(writer,),
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous), **options)
            process.cleanup_reader = reader
            process.cleanup_pending = 0
            process.cleanup_closed = False
            process.cleanup_depth = depth
            process.events = ProcessEvents(process)
            os.close(writer)
            writer = None
        yield process
    finally:
        with blocked_signals():
            try:
                if process is not None:
                    if hasattr(process, "events"):
                        stop_group(process)
                    else:
                        # Event registration can fail after spawn (for example,
                        # at the descriptor limit). Still discharge ownership.
                        signal_group(process, signal.SIGKILL)
                        process.wait()
            finally:
                if process is not None:
                    if hasattr(process, "events"):
                        process.events.close()
                    for stream in (process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
                os.close(reader)
                if writer is not None:
                    os.close(writer)
                if registered:
                    try:
                        os.write(parent, b"-")
                    except BrokenPipeError:
                        pass  # A vanished owner must not replace the original error.


def nested_cleanup_pending(process):
    if not hasattr(process, "cleanup_reader"):
        return False
    # Bound each drain too: a continuously writing child cannot starve a deadline.
    for _ in range(16):
        if process.cleanup_closed:
            break
        try:
            events = os.read(process.cleanup_reader, 4096)
        except BlockingIOError:
            break
        if not events:
            process.cleanup_closed = True
            break
        process.cleanup_pending += events.count(b"+") - events.count(b"-")
    return not process.cleanup_closed and process.cleanup_pending > 0


def signal_group(process, signum):
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    except PermissionError as error:
        # Darwin can deny signaling an exited, unreaped leader. Never wait on
        # a live leader after EPERM, or disguise that denial as a zero timeout.
        if sys.platform != "darwin" or not exited(process, timeout=0):
            raise PermissionError(f"Cannot signal process group {process.pid}: permission denied") from error


@_cleanup_call
def stop_group(process):
    """Terminate descendants before reaping the leader, keeping its pgid owned."""
    with blocked_signals():
        if process.returncode is not None:
            return  # A reaped leader's process group ID can already have been reused.
        events = getattr(process, "events", None)
        owned = events is None
        if owned:
            events = ProcessEvents(process)
        try:
            signal_group(process, signal.SIGTERM)
            signal_group(process, signal.SIGCONT)
            # Caller output and EOF descriptors must never wake cleanup waits.
            for fd in list(events.files):
                if fd != getattr(process, "cleanup_reader", None):
                    events.unregister(fd)
            # Each nesting level gets half its parent's five-second budget,
            # reserving the other half for propagation, reaping and acknowledgment.
            # Thus inner deadlines precede outer ones at every depth. A runner
            # itself SIGKILLed cannot clean its separate session; stale '+' must
            # still never extend this group's hard deadline.
            deadline = time.monotonic() + CLEANUP_SECONDS * 2.0 ** -getattr(process, "cleanup_depth", 0)
            while True:
                events.select(0)
                pending = nested_cleanup_pending(process)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or (events.exited and not pending):
                    break
                events.select(remaining)
            signal_group(process, signal.SIGKILL)
            process.wait()
        finally:
            if owned:
                events.close()


def run(argv, cwd=Path(__file__).resolve().parents[1], timeout=900, extra_env=None,
        *, env=None, capture_output=False, text=False, check=True, stdout=None, stderr=None):
    argv = list(map(str, argv))
    print("RUN " + " ".join(argv), flush=True)
    environment = dict(os.environ if env is None else env)
    if extra_env:
        environment.update(extra_env)
    if capture_output:
        stdout, stderr = subprocess.PIPE, subprocess.PIPE
    buffers = {}
    with command(argv, cwd=cwd, env=environment, stdout=stdout, stderr=stderr) as process:
        streams = [stream for stream in (process.stdout, process.stderr) if stream is not None]
        for stream in streams:
            buffers[stream.fileno()] = bytearray()
            process.events.register(stream, stream)
        deadline = time.monotonic() + timeout
        while not process.events.exited or any(stream.fileno() in process.events.files for stream in streams):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            for fd, stream in process.events.select(remaining):
                chunk = os.read(fd, 65536)
                if chunk:
                    buffers[fd].extend(chunk)
                else:
                    process.events.unregister(stream)
        output = [bytes(buffers[stream.fileno()]) for stream in streams]
    status = process.returncode
    result = subprocess.CompletedProcess(argv, status,
        output[0] if process.stdout is not None else None,
        output[-1] if process.stderr is not None else None)
    if text:
        for name in ("stdout", "stderr"):
            value = getattr(result, name)
            if value is not None:
                setattr(result, name, value.decode())
    if check:
        result.check_returncode()
    return result


@_cleanup_call
def write_pid_file(path, pid):
    # A same-directory rename publishes only the complete numeric identity.
    with tempfile.NamedTemporaryFile(mode="w", prefix=f".{path.name}-", dir=path.parent,
                                     delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(str(pid))
            output.flush()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def maximum_timeout():
    """Largest seconds value representable by the native event timeout ABI."""
    if sys.platform.startswith("linux"):
        # epoll_wait takes a signed C int in milliseconds (rounded upward).
        maximum = (1 << (struct.calcsize("i") * 8 - 1)) - 1
        scale = 1000
    else:
        # CPython converts kqueue's timespec through signed 64-bit nanoseconds;
        # its seconds field must also fit the platform's signed C long.
        scale = 1_000_000_000
        maximum = min((1 << (struct.calcsize("q") * 8 - 1)) - 1,
                      ((1 << (struct.calcsize("l") * 8 - 1)) - 1) * scale)
        # XNU's kevent_legacy_get_deadline calls timespec_is_valid, which
        # rejects tv_sec > INT32_MAX (bsd/kern/kern_time.c):
        # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_event.c
        # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_time.c
        maximum = min(maximum, ((1 << 31) - 1) * scale)
    seconds = maximum / scale
    numerator, denominator = seconds.as_integer_ratio()
    if numerator * scale > maximum * denominator:
        seconds = math.nextafter(seconds, 0)
    return seconds


def command_timeout(value):
    seconds = float(value)
    maximum = maximum_timeout()
    if not math.isfinite(seconds) or not 0 < seconds <= maximum:
        raise argparse.ArgumentTypeError(f"timeout must be finite, greater than 0 and at most {maximum}s")
    return seconds


def _choose_owner_outcome(outcome):
    # Mark first so dispatchers also drop handlers already scheduled by Python,
    # including one run while pthread_sigmask is entering the blocked state.
    outcome["chosen"] = True
    signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)


class _OwnerParser(argparse.ArgumentParser):
    def error(self, message):
        _choose_owner_outcome(self.outcome)
        self.print_usage(sys.stderr)
        _report(message)
        self.exit(2)

    def exit(self, status=0, message=None):
        _choose_owner_outcome(self.outcome)
        if status == 0:
            _report("help requested")
        super().exit(status, message)


def main(*, restore_signal_mask=True):
    global _report_prefix
    previous_prefix = _report_prefix
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    outcome = {"chosen": False}
    try:
        _report_prefix = "requestseal-owner: "
        install_signal_handlers()
        parser = _OwnerParser(description=__doc__)
        parser.outcome = outcome
        parser.add_argument("--timeout", type=command_timeout, default=900)
        parser.add_argument("--pid-file", type=Path)
        parser.add_argument("argv", nargs=argparse.REMAINDER)
        args = parser.parse_args()
        argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        if not argv:
            parser.error("a command is required")
        # Port or VM death closes stdin; EOF ends the separately owned session.
        with command(argv, stdin=subprocess.DEVNULL) as process:
            if args.pid_file:
                write_pid_file(args.pid_file, process.pid)
            try:
                # kqueue accepts regular files but need not report their EOF.
                # Decide command-channel eligibility independently of backend.
                if sys.stdin is None:
                    raise EOFError("command owner closed stdin")
                mode = os.fstat(0).st_mode
                if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISCHR(mode)):
                    raise EOFError("command owner closed stdin")
                process.events.register(0, "owner")
            except (OSError, ValueError):
                raise EOFError("command owner closed stdin") from None
            deadline = time.monotonic() + args.timeout
            incoming = bytearray()
            stopping = False
            while not process.events.exited and not stopping:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, args.timeout)
                for fd, _ in process.events.select(remaining):
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        raise EOFError("command owner closed stdin")
                    incoming.extend(chunk)
                    while b"\n" in incoming:
                        line, _, rest = incoming.partition(b"\n")
                        incoming[:] = rest
                        if line == b"stop":
                            stopping = True
                        elif line.startswith(b"signal "):
                            signum = getattr(signal, line[7:].decode(), None)
                            if signum not in (signal.SIGSTOP, signal.SIGCONT, signal.SIGTERM):
                                raise ValueError("unsupported agent signal")
                            # The leader is unreaped here, so its PID is still ours.
                            if signum == signal.SIGTERM:
                                signal_group(process, signum)
                                signal_group(process, signal.SIGCONT)
                            else:
                                os.kill(process.pid, signum)
                            _report(f"signal {signal.Signals(signum).name}", file=sys.stdout, flush=True)
                        else:
                            raise ValueError("invalid owner command")
                    if len(incoming) > 128:
                        raise ValueError("owner command too long")
        if stopping:
            _choose_owner_outcome(outcome)
            _report("command stopped")
            return 0
        _choose_owner_outcome(outcome)
        return 128 - process.returncode if process.returncode < 0 else process.returncode
    except subprocess.TimeoutExpired as error:
        _choose_owner_outcome(outcome)
        _report(f"command deadline exceeded after {error.timeout}s")
        return 124
    except Exception as error:
        _choose_owner_outcome(outcome)
        _report(error)
        return 125
    except (KeyboardInterrupt, SystemExit) as error:
        _choose_owner_outcome(outcome)
        if isinstance(error, KeyboardInterrupt):
            signum = signal.SIGINT
        else:
            signum = error.code - 128 if isinstance(error.code, int) else None
        if signum not in SIGNALS:
            raise
        _report(f"received {signal.Signals(signum).name}")
        return 128 + signum
    finally:
        _report_prefix = previous_prefix
        if restore_signal_mask:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


if __name__ == "__main__":
    raise SystemExit(main(restore_signal_mask=False))
