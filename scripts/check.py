#!/usr/bin/env python3
"""Run the checked-in scaffold contract on macOS and Linux; no service startup."""
import argparse
import json
import os
import math
import re
import time
from pathlib import Path
import subprocess
import sys

# Support the isolated, source-only invocations allowed by the local contract.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from release import development_snapshot, package_version, release_notes
from processes import cleanup_on_exit, command, install_signal_handlers, run, temporary_directory
from workflow_yaml import load as load_workflow

ROOT = Path(__file__).resolve().parents[1]

DIALYZER_SUPPRESSION_CHECK = r'''
unless File.lstat(".dialyzer_ignore.exs") == {:error, :enoent} do
  Mix.raise("Dialyzer suppression is forbidden: .dialyzer_ignore.exs")
end

if Keyword.has_key?(Mix.Project.config()[:dialyzer] || [], :ignore_warnings) do
  Mix.raise("Dialyzer suppression is forbidden: ignore_warnings in mix.exs")
end

for path <- ["mix.exs" | Path.wildcard("lib/**/*.{ex,exs}", match_dot: true)] do
  path
  |> File.read!()
  |> Code.string_to_quoted!(file: path)
  |> Macro.prewalk(fn
    {:ignore_warnings, _} when path == "mix.exs" ->
      Mix.raise("Dialyzer suppression is forbidden: ignore_warnings in mix.exs")

    {:@, _, [{:dialyzer, _, _}]} ->
      Mix.raise("Dialyzer suppression is forbidden: @dialyzer in #{path}")

    node ->
      node
  end)
end
'''


def check_dialyzer():
    """Analyze every warning with no source or file suppression path."""
    run(["mix", "run", "--no-start", "-e", DIALYZER_SUPPRESSION_CHECK])
    run(["mix", "dialyzer"])


def execute_notebook(script, completion, timeout=300, maximum_output=1_048_576):
    """Execute a real exported notebook with bounded bytes, time, and descendants."""
    if not math.isfinite(timeout) or timeout <= 0 or maximum_output <= 0:
        raise ValueError("Notebook execution limits must be positive and finite")
    if not completion or "\n" in completion or "\r" in completion:
        raise ValueError("Notebook completion must be one nonempty line")
    script = Path(script).resolve(strict=True)
    # Run from the script's own directory with a private Mix.install cache: a
    # path dependency must not land inside this repository's Mix project, and
    # an inherited MIX_HOME (version-manager shims export one) would otherwise
    # gate the notebook on a shared install cache it never declared.
    environment = dict(os.environ)
    environment["MIX_INSTALL_DIR"] = str(script.parent / "mix_install")
    # Select the project's runtime before leaving its version-manager scope.
    # Notebook code still runs outside the project, with the usual empty argv.
    bootstrap = ("[script] = System.argv(); System.argv([]); "
                 "File.cd!(Path.dirname(script)); Code.require_file(script)")
    with command(["elixir", "-e", bootstrap, "--", str(script)], cwd=ROOT, env=environment,
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
        output = read_notebook(process, timeout, maximum_output)
    if process.returncode:
        raise ValueError(f"Notebook failed ({process.returncode}):\n{output}")
    if output.splitlines().count(completion) != 1:
        raise ValueError(f"Notebook did not complete exactly once:\n{output}")
    return output, process.returncode


def read_notebook(process, timeout, maximum_output):
    deadline = time.monotonic() + timeout
    output = bytearray()
    events = process.events
    def unregister_output():
        if process.stdout.fileno() in events.files:
            events.unregister(process.stdout)

    with cleanup_on_exit(unregister_output):
        events.register(process.stdout, "output")
        while process.stdout.fileno() in events.files or not events.exited:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Notebook execution deadline exceeded:\n" + output.decode("utf-8", errors="replace"))
            for fd, _ in events.select(remaining):
                chunk = os.read(fd, 65536)
                if not chunk:
                    events.unregister(fd)
                    continue
                if len(output) + len(chunk) > maximum_output:
                    raise ValueError("Notebook output limit exceeded:\n" + output.decode("utf-8", errors="replace"))
                output.extend(chunk)
    return output.decode("utf-8")


def ci_action_errors(workflow, required_actions=None):
    """Require the build's essential actions and immutable commit identities.

    A reference to a workflow in this repository (./.github/workflows/...) is fixed by the
    commit being run, so it is the one reference that carries no commit identity."""
    errors = []
    try:
        workflow = load_workflow(workflow)
    except ValueError as error:
        return [f"CI workflow YAML: {error}"]
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict) or any(not isinstance(job, dict) for job in jobs.values()):
        return ["CI workflow jobs must be mappings"]
    calls, actions = [], []
    for job in jobs.values():
        if "uses" in job:
            calls.append(job["uses"])
        steps = job.get("steps", [])
        if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
            return ["CI workflow steps must be mappings"]
        actions.extend(step["uses"] for step in steps if "uses" in step)
    if required_actions is None:
        required_actions = {"actions/checkout", "erlef/setup-beam", "actions/setup-python", "actions/setup-node"}
    local = re.compile(r"\./\.github/workflows/[A-Za-z0-9_.-]+\.yml")
    pinned = re.compile(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}")
    if (not required_actions.issubset({ref.split("@", 1)[0] for ref in [*calls, *actions] if isinstance(ref, str)})
            or any(not isinstance(call, str) or not local.fullmatch(call) or ".." in call for call in calls)
            or any(not isinstance(action, str) or not pinned.fullmatch(action) for action in actions)):
        errors.append("CI actions must use immutable commit identities")
    return errors


def check_ci_actions():
    workflows = ROOT / ".github/workflows"
    errors = ci_action_errors((workflows / "ci.yml").read_text(), {
        "actions/checkout", "erlef/setup-beam", "actions/setup-python", "actions/setup-node",
        "actions/attest", "baselabs/.github/.github/actions/hex-publish",
    })
    errors += ci_action_errors((workflows / "publish.yml").read_text(), {
        "actions/checkout", "erlef/setup-beam", "actions/setup-python",
        "actions/upload-artifact", "actions/download-artifact",
        "baselabs/.github/.github/actions/hex-publish",
    })
    for workflow in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        errors += [f"{workflow.name}: {error}" for error in ci_action_errors(workflow.read_text(), set())]
    if errors:
        raise ValueError("\n".join(errors))
    print("PASS: CI actions use immutable commits")


def corpus_release_errors(sources):
    """Publication refuses mismatched package, corpus, or release-note identities."""
    import json
    try:
        version = package_version(sources["mix.exs"])
    except ValueError as error:
        return [str(error)]
    try:
        release = json.loads(sources["corpus/index.json"]).get("elixir_release")
    except (ValueError, AttributeError):
        release = None
    if release != "v" + version:
        return [f"corpus/index.json: elixir_release must be v{version} to match mix.exs"]
    if not development_snapshot(version):
        try:
            release_notes(sources.get("CHANGELOG.md", ""), version)
        except ValueError as error:
            return [str(error)]
    return []


def check_corpus_release():
    errors = corpus_release_errors({path: (ROOT / path).read_text() for path in ("mix.exs", "corpus/index.json", "CHANGELOG.md")})
    if errors:
        raise ValueError("\n".join(errors))
    print("PASS: corpus/index.json elixir_release matches the package version")


def check_sbom():
    from sbom import generate
    with temporary_directory(prefix="sbom-check-") as directory:
        generate(Path(directory) / "sbom.cdx.json")


def normalize_exdoc_inventory(output, project_root=ROOT):
    # ExDoc 0.40 emits absolute paths for copied Livebooks in its cleanup inventory.
    # Keep cleanup functional without including developer paths in served artifacts.
    output = output.resolve()
    project_root = project_root.resolve()
    for inventory in sorted(output.glob(".build*")):
        if not inventory.is_file() or inventory.is_symlink():
            raise ValueError("ExDoc inventory must be a regular generated file")
        entries = []
        for value in inventory.read_text().splitlines():
            item = Path(value)
            target = (item if item.is_absolute() else output / item).resolve()
            # EPUB uses paths relative to the invoking project; HTML/Markdown
            # inventories use paths relative to their output directory.
            if not item.is_absolute() and not target.is_file() and inventory.name == ".build.epub":
                target = (project_root / item).resolve()
            if not target.is_relative_to(output) or not target.is_file():
                raise ValueError("ExDoc inventory targets a missing or outside file")
            entries.append(target.relative_to(output).as_posix())
        inventory.write_text("".join(entry + "\n" for entry in entries))


def doc_link_errors(output):
    # Every relative link in generated HTML must reach an existing file and,
    # when it names a fragment, an element id in that file. A summary copied
    # onto another page keeps its module-local links, which break there.
    from html import unescape
    from html.parser import HTMLParser
    from urllib.parse import unquote, urlsplit

    class Collector(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids, self.hrefs = set(), []

        def handle_starttag(self, tag, attrs):
            for name, value in attrs:
                if name == "id" and value is not None:
                    self.ids.add(unescape(value))
                elif name == "href" and tag == "a" and value is not None:
                    self.hrefs.append(value)

    pages = {}
    for page in sorted(output.rglob("*.html")):
        collector = Collector()
        collector.feed(page.read_text())
        pages[page.resolve()] = collector
    errors = []
    version = package_version((ROOT / "mix.exs").read_text())
    current_hexdocs = {"hexdocs.pm": "/request_seal/" + version + "/", "request-seal.hexdocs.pm": "/" + version + "/"}
    for page, collector in pages.items():
        for href in collector.hrefs:
            parts = urlsplit(href)
            prefix = current_hexdocs.get(parts.netloc)
            if parts.scheme == "https" and prefix and parts.path.startswith(prefix):
                # Absolute authored links to this version must retain the same
                # generated-page and fragment checks as local ExDoc links.
                parts = parts._replace(scheme="", netloc="", path=parts.path[len(prefix):])
            if parts.scheme or parts.netloc or href.startswith("//"):
                continue
            target = (page.parent / unquote(parts.path)).resolve() if parts.path else page
            if not target.is_relative_to(output.resolve()) or not target.is_file():
                errors.append(f"{page.relative_to(output.resolve()).as_posix()}: {href} has no target")
                continue
            fragment = unquote(parts.fragment)
            if fragment and target.suffix == ".html" and fragment not in pages[target].ids:
                errors.append(f"{page.relative_to(output.resolve()).as_posix()}: {href} has no target")
    return errors


def check_doc_links(output):
    errors = doc_link_errors(output)
    if errors:
        raise ValueError("Generated documentation has broken links:\n" + "\n".join(errors))


def check_documentation():
    with temporary_directory(prefix="requestseal-docs-") as scratch:
        output = Path(scratch) / "current"
        run(["mix", "docs", "--warnings-as-errors", "--output", output], extra_env={"MIX_ENV": "dev"})
        run([sys.executable, "scripts/check_docs.py", "--docs-output", output])
        normalize_exdoc_inventory(output)
        check_doc_links(output)


def notebooks():
    from check_optional_clients import packed_source, running_toolchain
    tooling = ROOT / "tools/notebooks"
    run(["mix", "deps.get", "--check-locked"], tooling)
    run(["mix", "hex.audit"], tooling)
    run(["mix", "deps.audit"], tooling)
    run(["mix", "format", "--check-formatted"], tooling)
    run(["mix", "run", "--no-start", "check.exs", "--self-test"], tooling)
    _, runtime_path = running_toolchain()
    with packed_source(runtime_path) as source, temporary_directory(prefix="requestseal-notebooks-") as temporary:
        scratch = Path(temporary)
        run(["mix", "run", "--no-start", "check.exs", str(scratch)], tooling,
            extra_env={"REQUESTSEAL_PYTHON": sys.executable, "REQUESTSEAL_PACKED_SOURCE": str(source)})
        execute_notebooks(scratch)


def execute_notebooks(scratch):
    manifest = json.loads((scratch / "manifest.json").read_text())
    for entry in manifest:
        output, _ = execute_notebook(scratch / entry["script"], entry["completion"])
        print("\n".join(line for line in output.splitlines() if line != entry["completion"]))
        print(f'PASS {entry["notebook"]}: {entry["cells"]} nonempty Elixir cells exported; completion receipt verified')
    print(f"PASS {len(manifest)} notebooks; no external peer or UI acceptance claimed")

if __name__ == "__main__":
    install_signal_handlers()
    class SelectCheck(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            selected = getattr(namespace, self.dest) or []
            setattr(namespace, self.dest, [*selected, option_string])

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notebooks-only", action="store_true",
                        help="Run only notebooks; cannot combine with focused check flags")
    for flag in ("--ci-actions-only", "--corpus-release-only", "--sbom-only"):
        parser.add_argument(flag, dest="focused_checks", action=SelectCheck, nargs=0,
                            help="Run only this check; can combine with other focused checks, but not with --notebooks-only")
    args = parser.parse_args()
    if args.notebooks_only and args.focused_checks:
        parser.error("argument --notebooks-only: not allowed with argument " + args.focused_checks[0])
    try:
        focused = [
            ("--ci-actions-only", check_ci_actions),
            ("--corpus-release-only", check_corpus_release),
            ("--sbom-only", check_sbom),
        ]
        if args.focused_checks:
            for flag, operation in focused:
                if flag in args.focused_checks:
                    operation()
            raise SystemExit(0)
        check_ci_actions()
        if not args.notebooks_only:
            check_corpus_release()
            run(["mix", "format", "--check-formatted"])
            run(["mix", "compile", "--warnings-as-errors"])
            check_dialyzer()
            run(["mix", "test", "--warnings-as-errors"])
            run([sys.executable, "-B", "scripts/check_jose_libraries.py"])
            run(["mix", "run", "scripts/check_corpus_mutations.exs"], extra_env={"MIX_ENV": "test"})
            run([sys.executable, "scripts/check_optional_clients.py"])
            run([sys.executable, "-m", "unittest", "discover", "-s", "test", "-p", "*_test.py"])
            check_documentation()
            run(["mix", "hex.audit"])
            run(["mix", "deps.audit"])
        notebooks()
    except subprocess.TimeoutExpired as error:
        raise SystemExit(f"Command deadline exceeded after {error.timeout}s: {error.cmd}")
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
    except (ValueError, TimeoutError) as error:
        raise SystemExit(str(error))
    print("PASS: library contract and all shipped notebooks")
