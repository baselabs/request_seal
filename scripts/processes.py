"""Own command sessions and wait for their exit without reaping their leaders."""
import argparse
from contextlib import contextmanager
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


@contextmanager
def blocked_signals():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        yield previous
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextmanager
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

    def close(self):
        if self.selector is not None:
            self.selector.close()
        if self.queue is not None:
            self.queue.close()
        if self.pidfd is not None:
            os.close(self.pidfd)


def exited(process, timeout=None):
    """Block for an owned child's exit without releasing its PID or group ID."""
    if process.returncode is not None:
        return True
    if timeout == 0 and hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    events = getattr(process, "events", None)
    owned = events is None
    if owned:
        events = ProcessEvents(process)
    try:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not events.exited:
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            events.select(remaining)
            if deadline is not None and time.monotonic() >= deadline:
                break
        return events.exited
    finally:
        if owned:
            events.close()


@contextmanager
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
                    stop_group(process)
            finally:
                if process is not None and hasattr(process, "events"):
                    process.events.close()
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
        try:
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
        finally:
            for stream in streams:
                if stream.fileno() in process.events.files:
                    process.events.unregister(stream)
                stream.close()
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


if __name__ == "__main__":
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
        # A BEAM port closes stdin when its VM goes away. Wait for that EOF in
        # the same queue as exit/cleanup/output, and terminate our owned session.
        with command(argv) as process:
            if args.pid_file:
                args.pid_file.write_text(str(process.pid))
            process.events.register(sys.stdin, "owner")
            deadline = time.monotonic() + args.timeout
            while not process.events.exited:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, args.timeout)
                for fd, _ in process.events.select(remaining):
                    if not os.read(fd, 4096):
                        raise SystemExit("Command owner closed stdin")
        raise SystemExit(process.returncode)
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"Command deadline exceeded after {error.timeout}s")
