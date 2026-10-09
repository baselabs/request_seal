#!/usr/bin/env python3
"""Prove core isolation and exact optional-client floors in fresh consumers."""
import os
import json
import re
import shutil
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def running_toolchain():
    result = subprocess.run(
        ["elixir", "-e", """
IO.puts(System.version())
IO.puts(System.otp_release())
IO.puts(Path.expand("../../bin", to_string(:code.lib_dir(:elixir))))
IO.puts(Path.join(to_string(:code.root_dir()), "bin"))
"""],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=30,
    )
    elixir, otp, elixir_bin, erlang_bin = result.stdout.splitlines()
    print(f"CONSUMER TOOLCHAIN: Elixir {elixir} / OTP {otp}", flush=True)
    return elixir, os.pathsep.join([elixir_bin, erlang_bin, os.environ["PATH"]])


def client_floors(source):
    finch = re.findall(r'\{:finch, ">= (\d+\.\d+\.\d+) and < \d+\.\d+\.\d+"', source)
    req = re.findall(r'\{:req, "~> (\d+\.\d+\.\d+)"', source)
    if len(finch) != 1 or len(req) != 1:
        raise ValueError("Optional client requirements must declare one Finch and Req floor")
    return finch[0], req[0]


def check(elixir, runtime_path):
    with tempfile.TemporaryDirectory(prefix="requestseal-consumer-") as name:
        project = Path(name)
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
        env["PATH"] = runtime_path
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
{:ok, request} = RequestSeal.Message.request("POST", "https://example.com/a%2Fb?x=1", [{"x", "one"}, {"x", "two"}], <<0, 255>>, digest: ["sha-256"])
{_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
components = ~s[("@method" "@authority" "@path" "content-digest")]
spec = %{label: "sig", algorithm: "ed25519", components: components,
  parameters: %{created: true, expires_in: 60, nonce: :random, alg: true, keyid: "consumer-key", tag: nil},
  digest: ["sha-256"], field_schemas: %{}}
{:ok, signed} = RequestSeal.sign(request, spec, handle)
{:ok, policy} = RequestSeal.Policy.new(%{algorithms: ["ed25519"], components: components,
  key_resolver: fn %{keyid: "consumer-key"} -> {:ok, %{algorithm: "ed25519", key: key}}; _ -> :error end,
  freshness: %{clock: fn -> System.system_time(:second) end, max_age: 60, skew: 5, require_expires: true},
  content: %{kind: :content, algorithms: ["sha-256"], section: :headers}, replay: :not_required})
{:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
:valid = verification.signature.crypto
{:ok, response} = RequestSeal.Message.response(204, [], nil, request: request)
true = response.related_request == request
:ok = RequestSeal.Custody.Local.release(handle)
IO.puts("PASS: fresh consumer builds, signs, and verifies core without Req/Finch/Plug/Bandit/Phoenix")
"""],
        ]
        for command in commands:
            subprocess.run(command, cwd=project, env=env, check=True, timeout=180)


def check_client_floors(elixir, runtime_path):
    finch, req = client_floors((ROOT / "mix.exs").read_text())
    with tempfile.TemporaryDirectory(prefix="requestseal-client-consumer-") as name:
        project = Path(name)
        (project / "mix.exs").write_text(
            "defmodule ClientConsumer.MixProject do\n"
            "  use Mix.Project\n"
            f"  def project, do: [app: :client_consumer, version: \"0.0.0\", elixir: {json.dumps(elixir)}, "
            "deps: [{:request_seal, path: System.fetch_env!(\"REQUESTSEAL_CONSUMER_PATH\")}, "
            f"{{:finch, {json.dumps(finch)}, runtime: false}}, {{:req, {json.dumps(req)}, runtime: false}}]]\n"
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
        env["PATH"] = runtime_path
        for key in ("MIX_BUILD_PATH", "MIX_BUILD_ROOT", "MIX_DEPS_PATH", "ERL_LIBS"):
            env.pop(key, None)
        env["MIX_ENV"] = "test"
        env["REQUESTSEAL_CONSUMER_PATH"] = str(ROOT)
        commands = [
            ["mix", "deps.get"],
            ["mix", "compile", "--warnings-as-errors"],
            ["mix", "run", "--no-start", "--no-compile", "-e", f"""
lock = Mix.Dep.Lock.read()
{{:hex, :finch, {json.dumps(finch)}, _, _, _, _, _}} = lock.finch
{{:hex, :req, {json.dumps(req)}, _, _, _, _, _}} = lock.req
IO.puts("PASS: consumer lock contains finch {finch} and req {req}")
"""],
            ["mix", "test", "--warnings-as-errors"],
        ]
        for command in commands:
            print("RUN " + " ".join(command[:3]), flush=True)
            subprocess.run(command, cwd=project, env=env, check=True, timeout=300)
        print(f"PASS: fresh consumer compiles and passes client tests at finch {finch} / req {req}", flush=True)


if __name__ == "__main__":
    elixir, runtime_path = running_toolchain()
    check(elixir, runtime_path)
    check_client_floors(elixir, runtime_path)
