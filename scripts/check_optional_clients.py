#!/usr/bin/env python3
"""Compile and run a fresh core consumer without optional HTTP frameworks."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def check():
    with tempfile.TemporaryDirectory(prefix="requestseal-consumer-") as name:
        project = Path(name)
        import json
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
        for key in ("MIX_BUILD_PATH", "MIX_DEPS_PATH", "ERL_LIBS"):
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


if __name__ == "__main__":
    check()
