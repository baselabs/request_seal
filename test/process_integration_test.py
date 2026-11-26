"""Process ownership at the check, SBOM, notebook, and BEAM boundaries."""
import ast
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check
import processes
import sbom
from processes_test import cleanup_process, runtime_identity


def signal_installation_errors(source):
    """Check the CLI's direct local call path, including call order and multiplicity."""
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    entry = next((node for node in tree.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) in ("__name__ == '__main__'", "'__main__' == __name__")), None)
    if entry is None:
        return ["missing command entry point"]
    errors = []
    installations = 0

    def visit(node, active=(), conditional=False):
        nonlocal installations
        # Definitions do not execute their bodies until the entry point calls
        # them. Revisit a called function at every call site, including repeats.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(node, ast.Call):
            for argument in [node.func, *node.args, *(keyword.value for keyword in node.keywords)]:
                visit(argument, active, conditional)
            name = ast.unparse(node.func)
            if name == "install_signal_handlers":
                installations += 1
                if conditional:
                    errors.append("handler installation must be unconditional")
            elif isinstance(node.func, ast.Name) and name in functions:
                if name in active:
                    errors.append(f"recursive entry path cannot prove installation: {name}")
                else:
                    for statement in functions[name].body:
                        visit(statement, (*active, name), conditional)
                        if isinstance(statement, (ast.Return, ast.Raise)):
                            break
            elif not installations and not (name == "signal.pthread_sigmask"
                                             or (name == "set" and not node.args and not node.keywords)):
                # Reading the mask is the one pre-installation operation in
                # main's frame. Any other external call may acquire a resource.
                errors.append(f"call before handler installation: {name}")
            return
        conditional |= isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                         ast.ExceptHandler, ast.IfExp, ast.BoolOp, ast.Match, ast.comprehension))
        for child in ast.iter_child_nodes(node):
            visit(child, active, conditional)

    for statement in entry.body:
        visit(statement)
    if installations != 1:
        errors.append(f"handlers must be installed exactly once on the entry path, found {installations}")
    return errors


class ProcessIntegrationTest(unittest.TestCase):
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

    def test_every_command_entry_point_installs_handlers_explicitly(self):
        for script in ("check.py", "release.py", "check_docs.py", "sbom.py",
                       "check_jose_libraries.py", "check_optional_clients.py", "processes.py"):
            with self.subTest(script=script):
                self.assertEqual([], signal_installation_errors((ROOT / "scripts" / script).read_text()))

    def test_handler_installation_check_follows_transitive_calls_in_execution_order(self):
        source = '''def unused():
    acquire_resource()
def main():
    signal.pthread_sigmask(signal.SIG_BLOCK, set())
    return prepare()
def prepare():
    own()
def own():
    install_signal_handlers()
    acquire_resource()
if __name__ == "__main__":
    main()
'''
        self.assertEqual([], signal_installation_errors(source))
        self.assertEqual([], signal_installation_errors('''def main():
    acquire_resource()
if __name__ == "__main__":
    install_signal_handlers()
    main()
'''))

    def test_handler_installation_check_rejects_missing_duplicate_and_unreachable_calls(self):
        source = '''def main():
    prepare()
def prepare():
    install_signal_handlers()
    acquire_resource()
if __name__ == "__main__":
    main()
'''
        variants = {
            "removed": source.replace('    install_signal_handlers()\n', ''),
            "duplicated": source.replace('    install_signal_handlers()\n',
                                          '    install_signal_handlers()\n    install_signal_handlers()\n'),
            "unreachable helper": source.replace('    install_signal_handlers()\n', '')
                                  + '\ndef unused():\n    install_signal_handlers()\n',
            "repeated helper": source.replace('    prepare()\n', '    prepare()\n    prepare()\n'),
            "after return": source.replace('    prepare()\n', '    return\n    prepare()\n'),
        }
        for variant, changed in variants.items():
            with self.subTest(variant=variant):
                errors = signal_installation_errors(changed)
                self.assertTrue(any("exactly once" in error for error in errors), errors)

    def test_handler_installation_check_rejects_acquisition_before_or_without_installation(self):
        for body in (
                '    acquire_resource()\n    install_signal_handlers()\n',
                '    acquire()\n    install_signal_handlers()\n',
                '    install_signal_handlers(acquire_resource())\n',
                '    if enabled:\n        install_signal_handlers()\n    acquire_resource()\n'):
            with self.subTest(body=body):
                source = ('def main():\n' + body + 'def acquire():\n    acquire_resource()\n'
                          + 'if __name__ == "__main__":\n    main()\n')
                self.assertTrue(signal_installation_errors(source))

    def test_cleanup_pipe_is_drained_during_notebook_read(self):
        writer = ('import os; fd=int(os.environ["REQUESTSEAL_CLEANUP_FD"]); '
                  '[os.write(fd,b"+-") for _ in range(70000)]; print("DONE")')
        with processes.command([sys.executable, "-B", "-c", writer], stdout=subprocess.PIPE) as child:
            try:
                self.assertEqual("DONE\n", check.read_notebook(child, 10, 1024))
            finally:
                child.stdout.close()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux pidfds bind the runtime after BEAM death")
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
                pidfd = None
                try:
                    deadline = time.monotonic() + 20
                    while not ready.exists():
                        self.assertFalse(processes.exited(parent, timeout=0))
                        self.assertLess(time.monotonic(), deadline, "BEAM port did not start its real runtime")
                        time.sleep(0.01)
                    pid = int(ready.read_text())
                    _, _, pidfd = runtime_identity(pid, parent.pid)
                    os.kill(parent.pid, signal.SIGKILL)
                    self.assertTrue(select.select([pidfd], [], [], 10)[0],
                                    "runtime survived the death of its BEAM port owner")
                finally:
                    try:
                        cleanup_process(parent)
                    finally:
                        if pidfd is not None:
                            try:
                                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            os.close(pidfd)


if __name__ == "__main__":
    unittest.main()
