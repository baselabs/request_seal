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
from processes_test import runtime_identity


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
            tree = ast.parse((ROOT / "scripts" / script).read_text())
            entry = next((node for node in tree.body if isinstance(node, ast.FunctionDef)
                          and node.name == "main"), tree.body[-1])
            calls = [node for node in ast.walk(entry) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == "install_signal_handlers"]
            if not calls:
                calls = [node for node in ast.walk(tree.body[-1]) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Name) and node.func.id == "install_signal_handlers"]
            self.assertEqual(1, len(calls), script)

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
                deadline = time.monotonic() + 20
                while not ready.exists():
                    self.assertFalse(processes.exited(parent, timeout=0))
                    self.assertLess(time.monotonic(), deadline, "BEAM port did not start its real runtime")
                    time.sleep(0.01)
                pid = int(ready.read_text())
                _, _, pidfd = runtime_identity(pid, parent.pid)
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


if __name__ == "__main__":
    unittest.main()
