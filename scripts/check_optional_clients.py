#!/usr/bin/env python3
"""Prove core isolation and exact optional-client floors in fresh consumers."""
import os
import json
import shutil
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def check():
    with tempfile.TemporaryDirectory(prefix="requestseal-consumer-") as name:
        project = Path(name)
        versions = (ROOT / ".tool-versions").read_text()
        (project / ".tool-versions").write_text(versions)
        elixir = next(line.split()[1].split("-otp-")[0]
                      for line in versions.splitlines() if line.startswith("elixir "))
        (project / "config").mkdir()
        (project / "config/config.exs").write_text((ROOT / "config/config.exs").read_text())
        (project / "mix.exs").write_text(
            "defmodule CoreConsumer.MixProject do\n"
            "  use Mix.Project\n"
            f"  def project, do: [app: :core_consumer, version: \"0.0.0\", elixir: {json.dumps(elixir)}, "
            "deps: [{:request_seal, path: System.fetch_env!(\"REQUESTSEAL_CONSUMER_PATH\")}]]\n"
            "  def application, do: [extra_applications: [:request_seal]]\n"
            "end\n"
        )
        env = os.environ.copy()
        # Do not inherit a build/dependency path that could contain the clients.
        for key in ("MIX_BUILD_PATH", "MIX_BUILD_ROOT", "MIX_DEPS_PATH", "ERL_LIBS"):
            env.pop(key, None)
        env["MIX_ENV"] = "prod"
        env["REQUESTSEAL_CONSUMER_PATH"] = str(ROOT)
        commands = [
            ["mix", "deps.get"],
            ["mix", "compile", "--warnings-as-errors"],
            ["mix", "run", "--no-compile", "-e", """
false = Code.ensure_loaded?(Req)
false = Code.ensure_loaded?(Finch)
false = Code.ensure_loaded?(Plug.Conn)
false = Code.ensure_loaded?(Bandit)
false = Code.ensure_loaded?(Phoenix)
false = Code.ensure_loaded?(RequestSeal.Plug)
false = Code.ensure_loaded?(RequestSeal.Plug.Capture)
false = Code.ensure_loaded?(RequestSeal.Plug.Verify)
false = Code.ensure_loaded?(RequestSeal.Plug.SignResponse)
false = Code.ensure_loaded?(RequestSeal.Plug.State)
false = Code.ensure_loaded?(RequestSeal.Plug.Origin)
false = Code.ensure_loaded?(RequestSeal.Plug.Delivery)
false = Code.ensure_loaded?(RequestSeal.Req)
false = Code.ensure_loaded?(RequestSeal.Finch)
true = Code.ensure_loaded?(RequestSeal)
false = Enum.any?(Application.started_applications(), fn {app, _, _} -> app in [:req, :finch, :plug, :bandit, :phoenix] end)
{:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ""})
{:ok, digest} = RequestSeal.Digest.compute(body, ["sha-256"])
{:ok, _} = RequestSeal.Digest.serialize(digest)
IO.puts("PASS: fresh consumer compiles and runs core without Req/Finch/Plug/Bandit/Phoenix")
"""],
        ]
        for command in commands:
            subprocess.run(command, cwd=project, env=env, check=True, timeout=180)


def check_client_floors():
    with tempfile.TemporaryDirectory(prefix="requestseal-client-consumer-") as name:
        project = Path(name)
        versions = (ROOT / ".tool-versions").read_text()
        (project / ".tool-versions").write_text(versions)
        elixir = next(line.split()[1].split("-otp-")[0]
                      for line in versions.splitlines() if line.startswith("elixir "))
        (project / "mix.exs").write_text(
            "defmodule ClientConsumer.MixProject do\n"
            "  use Mix.Project\n"
            f"  def project, do: [app: :client_consumer, version: \"0.0.0\", elixir: {json.dumps(elixir)}, "
            "deps: [{:request_seal, path: System.fetch_env!(\"REQUESTSEAL_CONSUMER_PATH\")}, "
            "{:finch, \"0.23.0\", runtime: false}, {:req, \"0.7.4\", runtime: false}]]\n"
            "  def application, do: [extra_applications: [:request_seal]]\n"
            "end\n"
        )
        for relative in ("test/client_adapters_test.exs", "test/support/http_signature_peer_helper.exs"):
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        for directory in ("crypto", "signature_base", "verification"):
            relative = Path("test/fixtures") / directory
            shutil.copytree(ROOT / relative, project / relative)
        (project / "test/test_helper.exs").write_text("ExUnit.start()\n")
        env = os.environ.copy()
        for key in ("MIX_BUILD_PATH", "MIX_BUILD_ROOT", "MIX_DEPS_PATH", "ERL_LIBS"):
            env.pop(key, None)
        env["MIX_ENV"] = "test"
        env["REQUESTSEAL_CONSUMER_PATH"] = str(ROOT)
        commands = [
            ["mix", "deps.get"],
            ["mix", "compile", "--warnings-as-errors"],
            ["mix", "run", "--no-start", "--no-compile", "-e", """
lock = Mix.Dep.Lock.read()
{:hex, :finch, "0.23.0", _, _, _, _, _} = lock.finch
{:hex, :req, "0.7.4", _, _, _, _, _} = lock.req
IO.puts("PASS: consumer lock contains finch 0.23.0 and req 0.7.4")
"""],
            ["mix", "test", "--warnings-as-errors"],
        ]
        for command in commands:
            print("RUN " + " ".join(command[:3]), flush=True)
            subprocess.run(command, cwd=project, env=env, check=True, timeout=300)
        print("PASS: fresh consumer compiles and passes client tests at finch 0.23.0 / req 0.7.4", flush=True)


if __name__ == "__main__":
    check()
    check_client_floors()
