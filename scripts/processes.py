"""Own command sessions and wait for exit without releasing their process identity.

CLI statuses: the child's exit status, or 128 + N when killed by signal N;
124 for an owner deadline; 125 for owner EOF or an owner-side failure. Owner
failures emit one stderr line beginning ``requestseal-owner:``. As with shell
commands, a child can itself choose a reserved status; the prefix identifies
an owner failure in merged output.
"""
import argparse
from contextlib import contextmanager
from functools import wraps
import os
from pathlib import Path
import select
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
CLEANUP_SECONDS = 5


# A mask alone cannot protect its own entry: CPython can run an already
# scheduled handler from pthread_sigmask. Dispatchers recognize the entire
# protected call frame, including its first bytecode and context exit, and hold
# the first signal until cleanup and mask restoration finish. An in-flight
# exception wins. These command-line owners are single-threaded.
_pending_signals = {}


def _cleanup_call(function):
    @wraps(function)
    def protected(*args, **kwargs):
        original = sys.exc_info()[1]
        try:
            result = function(*args, **kwargs)
            finished = True
            pending = _pending_signals.pop(id(sys._getframe()), None)
            if pending is not None and original is None:
                handler, signum, frame = pending
                handler(signum, frame)
            return result
        except BaseException:
            # A deferred signal at context entry must also discharge everything
            # acquired before yield, since Python will not call __exit__ then.
            finished = False
            if function.__name__ == "__enter__" and args[0].entered:
                args[0].manager.__exit__(*sys.exc_info())
            finished = True
            _pending_signals.pop(id(sys._getframe()), None)
            raise
    return protected


def _install_cleanup_handlers():
    for signum in SIGNALS:
        handler = signal.getsignal(signum)
        if not callable(handler) or getattr(handler, "_cleanup_dispatcher", False):
            continue

        def dispatch(signum, frame, handler=handler):
            protected = None
            guarded = False
            current = frame
            while current is not None:
                if current.f_code is _CleanupContext.__exit__.__code__:
                    guarded = True
                    if not current.f_locals.get("finished", False):
                        protected = current
                current = current.f_back
            if protected is not None:
                _pending_signals.setdefault(id(protected), (handler, signum, frame))
            elif not guarded or sys.exc_info()[1] is None:
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


class ProcessEvents:
    """One kernel queue for exit, cleanup messages, and captured output."""

    def __init__(self, process):
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
            if hasattr(process, "cleanup_reader"):
                self.register(process.cleanup_reader, "cleanup")
        except BaseException:
            self.close()
            raise

    def register(self, fileobj, data):
        fd = fileobj if isinstance(fileobj, int) else fileobj.fileno()
        self.files[fd] = data
        if self.selector is not None:
            self.selector.register(fd, selectors.EVENT_READ, data)
        else:
            self.queue.control([select.kevent(fd, filter=select.KQ_FILTER_READ,
                                              flags=select.KQ_EV_ADD)], 0, 0)

    def unregister(self, fileobj):
        fd = fileobj if isinstance(fileobj, int) else fileobj.fileno()
        del self.files[fd]
        if self.selector is not None:
            self.selector.unregister(fd)
        else:
            self.queue.control([select.kevent(fd, filter=select.KQ_FILTER_READ,
                                              flags=select.KQ_EV_DELETE)], 0, 0)

    def select(self, timeout=None):
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
def process_events(process):
    events = getattr(process, "events", None)
    owned = events is None
    if owned:
        events = ProcessEvents(process)
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
    with process_events(process) as events:
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
            # Caller output and EOF descriptors must never wake cleanup waits.
            for fd, data in list(events.files.items()):
                if data != "cleanup":
                    events.unregister(fd)
            signal_group(process, signal.SIGTERM)
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


def main():
    install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--pid-file", type=Path)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv:
        parser.error("a command is required")
    try:
        # Port or VM death closes stdin; EOF ends the separately owned session.
        with command(argv) as process:
            if args.pid_file:
                write_pid_file(args.pid_file, process.pid)
            process.events.register(sys.stdin, "owner")
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
                            os.kill(process.pid, signum)
                            print(f"requestseal-owner: signal {signal.Signals(signum).name}", flush=True)
                        else:
                            raise ValueError("invalid owner command")
                    if len(incoming) > 128:
                        raise ValueError("owner command too long")
        if stopping:
            return 0
        return 128 - process.returncode if process.returncode < 0 else process.returncode
    except subprocess.TimeoutExpired as error:
        print(f"requestseal-owner: command deadline exceeded after {error.timeout}s", file=sys.stderr)
        return 124
    except (OSError, RuntimeError, EOFError, ValueError) as error:
        print("requestseal-owner: " + " ".join(str(error).splitlines()), file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
