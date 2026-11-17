#!/usr/bin/env python3
"""Run the checked-in scaffold contract on macOS and Linux; no service startup."""
import argparse
import os
import math
import re
import selectors
import time
import signal
import tempfile
from pathlib import Path
import subprocess
import sys
from release import package_version

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


def run(argv, cwd=ROOT, timeout=900, extra_env=None):
    print("RUN " + " ".join(argv), flush=True)
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True)
        status = process.wait(timeout=timeout)
        if status:
            raise subprocess.CalledProcessError(status, argv)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # Kill any descendants still in the group even if the direct child exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise SystemExit(f"Deadline exceeded after {timeout}s: {argv}")

def stop_group(process):
    # Keep an unreaped leader until all signals finish; never target a reused pgid.
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        # macOS denies signaling a group whose leader exited unreaped; the
        # SIGKILL step below proves the exit before discharging the error.
        pass
    time.sleep(0.2)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Some hosts deny signaling an exited, unreaped group leader. Only
        # discharge that error when wait proves this owned child already exited.
        process.wait(timeout=0)
    process.wait()


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
    process = subprocess.Popen(["elixir", "-e", bootstrap, "--", str(script)], cwd=ROOT, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Notebook execution deadline exceeded:\n" + output.decode("utf-8", errors="replace"))
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(output) + len(chunk) > maximum_output:
                        raise ValueError("Notebook output limit exceeded:\n" + output.decode("utf-8", errors="replace"))
                    output.extend(chunk)
        try:
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Notebook execution deadline exceeded:\n" + output.decode("utf-8", errors="replace")) from error
        text = output.decode("utf-8")
        if status:
            raise ValueError(f"Notebook failed ({status}):\n{text}")
        if text.splitlines().count(completion) != 1:
            raise ValueError(f"Notebook did not complete exactly once:\n{text}")
        return text, status
    finally:
        try:
            stop_group(process)
        finally:
            process.stdout.close()


def ci_action_errors(workflow, required_actions=None):
    """Require the build's essential actions and immutable commit identities."""
    errors = []
    actions = re.findall(r"uses:\s*(\S+)", workflow)
    if required_actions is None:
        required_actions = {"actions/checkout", "erlef/setup-beam", "actions/setup-python", "actions/setup-node"}
    if not required_actions.issubset({action.split("@", 1)[0] for action in actions}) or any(not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action) for action in actions):
        errors.append("CI actions must use immutable commit identities")
    return errors


def check_ci_actions():
    errors = ci_action_errors((ROOT / ".github/workflows/ci.yml").read_text())
    errors += ci_action_errors((ROOT / ".github/workflows/release.yml").read_text(), {
        "actions/checkout", "erlef/setup-beam", "actions/setup-python",
        "actions/upload-artifact", "actions/download-artifact", "actions/attest",
    })
    if errors:
        raise ValueError("\n".join(errors))
    print("PASS: CI actions use immutable commits")


def corpus_release_errors(sources):
    """The corpus release workflow refuses a tag unless these agree; fail before tagging."""
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
    return []


def check_corpus_release():
    errors = corpus_release_errors({path: (ROOT / path).read_text() for path in ("mix.exs", "corpus/index.json")})
    if errors:
        raise ValueError("\n".join(errors))
    print("PASS: corpus/index.json elixir_release matches the package version")


RELEASE_RUNTIME_CHECK = r'''
check = Mix.Project.config()[:aliases][:"hex.publish"] |> hd()
development? =
  case Version.parse!(Mix.Project.config()[:version]).pre do
    [first | _] when is_binary(first) -> String.starts_with?(first, "dev")
    _ -> false
  end
if development? do
  try do
    check.([])
  rescue
    error in Mix.Error ->
      unless String.contains?(Exception.message(error), "development versions cannot publish"),
        do: reraise(error, __STACKTRACE__)
      IO.puts("PASS: development version refuses to publish")
  else
    _ -> Mix.raise("development version must refuse to publish")
  end
else
  check.([])
end
'''


def check_package_metadata(path):
    """Consult the built Hex artifact, not the development dependency list."""
    run(["elixir", "-e", r"""
{:ok, metadata} = :file.consult(System.argv() |> hd() |> String.to_charlist())
{"requirements", requirements} = List.keyfind(metadata, "requirements", 0)
for name <- ["ash_onetime", "ash_hooks"] do
  matches = Enum.filter(requirements, &(List.keyfind(&1, "name", 0) == {"name", name}))
  unless length(matches) == 1 and List.keyfind(hd(matches), "optional", 0) == {"optional", true} do
    raise "Hex metadata must contain exactly one optional requirement for #{name}"
  end
end
IO.puts("PASS: built Hex metadata lists ash_onetime and ash_hooks as optional requirements")
""", str(path)])


def check_package():
    run(["mix", "run", "--no-start", "-e", RELEASE_RUNTIME_CHECK])
    (ROOT / "_build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="package-check-", dir=ROOT / "_build") as temporary:
        artifact = Path(temporary) / "unpacked"
        run(["mix", "hex.build", "--unpack", "--output", str(artifact)])
        check_package_metadata(artifact / "hex_metadata.config")
    print("PASS: release runtime guard and optional package requirements; unpacked artifact deleted")


def check_sbom():
    from sbom import generate
    with tempfile.TemporaryDirectory(prefix="sbom-check-") as directory:
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
    for page, collector in pages.items():
        for href in collector.hrefs:
            parts = urlsplit(href)
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

def notebooks():
    tooling = ROOT / "tools/notebooks"
    run(["mix", "deps.get", "--check-locked"], tooling)
    run(["mix", "hex.audit"], tooling)
    run(["mix", "format", "--check-formatted"], tooling)
    run(["mix", "run", "--no-start", "check.exs", "--self-test"], tooling)
    run(["mix", "run", "--no-start", "check.exs"], tooling,
        extra_env={"REQUESTSEAL_PYTHON": sys.executable})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notebooks-only", action="store_true")
    parser.add_argument("--ci-actions-only", action="store_true")
    parser.add_argument("--corpus-release-only", action="store_true")
    parser.add_argument("--package-only", action="store_true")
    parser.add_argument("--sbom-only", action="store_true")
    parser.add_argument("--execute-notebook", nargs=2, metavar=("SCRIPT", "COMPLETION"))
    parser.add_argument("--notebook-timeout", type=float, default=300)
    args = parser.parse_args()
    try:
        if args.execute_notebook:
            output, _ = execute_notebook(*args.execute_notebook, timeout=args.notebook_timeout)
            print(output, end="")
            raise SystemExit(0)
        focused = [
            (args.ci_actions_only, check_ci_actions),
            (args.corpus_release_only, check_corpus_release),
            (args.package_only, check_package),
            (args.sbom_only, check_sbom),
        ]
        if any(selected for selected, _ in focused):
            for selected, operation in focused:
                if selected:
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
            run([sys.executable, "scripts/check_docs.py"])
            run(["mix", "docs", "--warnings-as-errors"])
            normalize_exdoc_inventory(ROOT / "doc")
            check_doc_links(ROOT / "doc")
            run(["mix", "hex.audit"])
            check_package()
            check_sbom()
        notebooks()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
    except (ValueError, TimeoutError) as error:
        raise SystemExit(str(error))
    print("PASS: library contract and all shipped notebooks")
