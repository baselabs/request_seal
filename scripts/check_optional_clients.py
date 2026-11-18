#!/usr/bin/env python3
"""Prove core isolation and exact published dependency floors in fresh consumers."""
from contextlib import contextmanager
import io
import os
import tarfile
import json
import shutil
from pathlib import Path
from processes import install_signal_handlers, run, temporary_directory

ROOT = Path(__file__).resolve().parents[1]

FLOOR_COVERAGE = {
    "telemetry": ("test/telemetry_test.exs",),
    "ash": ("test/ash_test.exs", "test/support/ash"),
    "req": ("test/client_adapters_test.exs", "test/support/http_signature_peer_helper.exs"),
    "finch": ("test/client_adapters_test.exs", "test/support/http_signature_peer_helper.exs"),
    "plug": (
        "test/plug_transport_test.exs", "test/plug_phoenix_test.exs", "test/plug_target_fidelity_test.exs",
        "test/support/plug_transport_helper.exs", "test/support/plug_phoenix_helper.exs",
    ),
    "postgrex": ("test/replay_postgres_test.exs",),
    "ash_onetime": ("test/replay_ash_onetime_test.exs", "test/support/owned_database.ex"),
    "ash_hooks": (
        "test/ash_hooks_test.exs", "test/support/owned_database.ex", "test/support/owned_hooks.ex",
    ),
}

# These test tools exercise real Ash policies and HTTP servers, not consumer floors.
FLOOR_TEST_TOOLS = {"ash": ("simple_sat",), "plug": ("bandit", "phoenix"), "ash_hooks": ("bandit",)}

DEPENDENCY_METADATA = r'''
Mix.start()
Mix.env(:test)
Code.require_file("mix.exs")
dependencies = Enum.map(Mix.Project.config()[:deps], fn dependency ->
  {name, requirement, options} = case dependency do
    {name, requirement} -> {name, requirement, []}
    dependency -> dependency
  end
  published = not Keyword.has_key?(options, :only)
  floor = if published do
    # The supported range shapes name their inclusive lower boundaries. Ask
    # Version which boundary satisfies the complete requirement (including ~>).
    requirement
    |> then(&Regex.scan(~r/\d+\.\d+(?:\.\d+)?/, &1))
    |> List.flatten()
    |> Enum.map(fn version ->
      if length(String.split(version, ".")) == 2, do: version <> ".0", else: version
    end)
    |> Enum.filter(&Version.match?(&1, requirement))
    |> Enum.min_by(&Version.parse!/1, Version)
  end
  %{name: name, requirement: requirement, published: published,
    floor: floor, runtime: Keyword.get(options, :runtime, true)}
end)
IO.puts(["REQUESTSEAL_DEPENDENCIES\t", :json.encode(dependencies)])
'''


def running_toolchain():
    result = run(
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


def dependency_metadata(runtime_path):
    env = os.environ.copy()
    env["PATH"] = runtime_path
    result = run(
        ["elixir", "-e", DEPENDENCY_METADATA], cwd=ROOT, env=env,
        check=True, capture_output=True, text=True, timeout=30,
    )
    marker = "REQUESTSEAL_DEPENDENCIES\t"
    data = [json.loads(line[len(marker):]) for line in result.stdout.splitlines() if line.startswith(marker)]
    if len(data) != 1 or not data[0]:
        raise ValueError("Mix must report a nonempty dependency inventory")
    return {dependency["name"]: dependency for dependency in data[0]}


@contextmanager
def packed_source(runtime_path):
    """Both fresh consumers install the inspected packed archive, with no seed lock."""
    from check_docs import public_configuration
    from publication import inspect_package, members
    from release import package_version
    with temporary_directory(prefix="requestseal-consumer-package-") as name:
        directory = Path(name)
        tarball = directory / "package.tar"
        env = dict(os.environ, PATH=runtime_path, MIX_ENV="dev")
        run(["mix", "deps.get", "--check-locked"], cwd=ROOT, env=env, check=True, timeout=300)
        run(["mix", "hex.build", "--output", tarball], cwd=ROOT, env=env, check=True, timeout=300)
        version = package_version((ROOT / "mix.exs").read_text())
        inspect_package(tarball, version, public_configuration(ROOT)["files"])
        source = directory / "source"
        source.mkdir()
        with tarfile.open(tarball) as outer:
            contents = outer.extractfile("contents.tar.gz").read()
        with tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as archive:
            for relative, member in members(archive).items():
                target = source / relative
                if member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
        yield source


def floor_files(dependencies):
    unknown = set(dependencies) - FLOOR_COVERAGE.keys()
    if unknown:
        raise ValueError("Published dependencies need floor coverage: " + ", ".join(sorted(unknown)))
    return sorted({relative for name in dependencies for relative in FLOOR_COVERAGE[name]})


def check(elixir, runtime_path, source):
    with temporary_directory(prefix="requestseal-consumer-") as name:
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
        env["REQUESTSEAL_CONSUMER_PATH"] = str(source)
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
false = Code.ensure_loaded?(AshOnetime.Transaction)
false = Code.ensure_loaded?(AshHooks.Provider)
false = Code.ensure_loaded?(RequestSeal.Replay.AshOnetime)
false = Code.ensure_loaded?(RequestSeal.AshHooks)
false = Code.ensure_loaded?(RequestSeal.AshHooks.Http)
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
            run(command, cwd=project, env=env, check=True, timeout=180)


def check_client_floors(elixir, runtime_path, source):
    metadata = dependency_metadata(runtime_path)
    published = {name: dependency for name, dependency in metadata.items() if dependency["published"]}
    files = floor_files(published)
    test_tools = sorted({tool for name in published for tool in FLOOR_TEST_TOOLS.get(name, ())})
    dependencies = []
    for name in list(published) + test_tools:
        dependency = metadata[name]
        requirement = dependency["floor"] if dependency["published"] else dependency["requirement"]
        runtime = "" if dependency["runtime"] else ", runtime: false"
        dependencies.append(f"{{:{name}, {json.dumps(requirement)}{runtime}}}")
    floors = {name: dependency["floor"] for name, dependency in published.items()}
    print("PUBLISHED DEPENDENCY FLOORS: " + json.dumps(floors, sort_keys=True), flush=True)
    if not os.environ.get("REQUESTSEAL_REPLAY_PG_URL"):
        print("NOT VERIFIED: REQUESTSEAL_REPLAY_PG_URL is not set; PostgreSQL floor tests need a real database", flush=True)

    with temporary_directory(prefix="requestseal-floor-consumer-") as name:
        project = Path(name)
        (project / "config").mkdir()
        shutil.copyfile(ROOT / "config/config.exs", project / "config/config.exs")
        (project / "mix.exs").write_text(
            "defmodule FloorConsumer.MixProject do\n"
            "  use Mix.Project\n"
            f"  def project, do: [app: :floor_consumer, version: \"0.0.0\", elixir: {json.dumps(elixir)}, "
            "elixirc_paths: [\"test/support\"], "
            "deps: [{:request_seal, path: System.fetch_env!(\"REQUESTSEAL_CONSUMER_PATH\")}, "
            + ", ".join(dependencies) + "]]\n"
            "  def application, do: [extra_applications: [:request_seal]]\n"
            "end\n"
        )
        # A fresh packed-archive installation has no committed or copied lock.
        for relative in files + ["test/test_helper.exs", "test/support/multi_signature_helper.exs",
                                 "test/support/system_command.ex", "scripts/processes.py"]:
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if (ROOT / relative).is_dir():
                shutil.copytree(ROOT / relative, target)
            else:
                shutil.copyfile(ROOT / relative, target)
        for directory in ("crypto", "signature_base", "verification", "http", "multi_signature"):
            relative = Path("test/fixtures") / directory
            shutil.copytree(ROOT / relative, project / relative)
        env = os.environ.copy()
        env["PATH"] = runtime_path
        for key in ("MIX_BUILD_PATH", "MIX_BUILD_ROOT", "MIX_DEPS_PATH", "ERL_LIBS"):
            env.pop(key, None)
        env["MIX_ENV"] = "test"
        env["REQUESTSEAL_CONSUMER_PATH"] = str(source)
        env["REQUESTSEAL_DEPENDENCY_FLOORS"] = json.dumps(floors)
        test_files = [relative for relative in files if relative.endswith("_test.exs")]
        commands = [
            ["mix", "deps.get"],
            ["mix", "run", "--no-start", "--no-compile", "--no-deps-check", "-e", """
lock = Mix.Dep.Lock.read()
for {name, floor} <- :json.decode(System.fetch_env!("REQUESTSEAL_DEPENDENCY_FLOORS")) do
  {:hex, _, ^floor, _, _, _, _, _} = Map.fetch!(lock, String.to_existing_atom(name))
  IO.puts("PASS: consumer lock contains #{name} #{floor}")
end
"""],
            ["mix", "compile", "--warnings-as-errors"],
            ["mix", "test", "--warnings-as-errors", *test_files],
        ]
        for command in commands:
            print("RUN " + " ".join(command[:3]), flush=True)
            # A cold floor consumer compiles the whole Ash, Phoenix and Bandit graph.
            run(command, cwd=project, env=env, check=True, timeout=1200)
        if not env.get("REQUESTSEAL_REPLAY_PG_URL"):
            raise ValueError("REQUESTSEAL_REPLAY_PG_URL is not set; PostgreSQL dependency floors were not verified")
        print("PASS: fresh consumer compiles and passes covering tests at every published dependency floor", flush=True)


if __name__ == "__main__":
    install_signal_handlers()
    elixir, runtime_path = running_toolchain()
    with packed_source(runtime_path) as source:
        check(elixir, runtime_path, source)
        check_client_floors(elixir, runtime_path, source)
