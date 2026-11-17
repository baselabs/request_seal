defmodule RequestSeal.ReleaseSBOMTest do
  use ExUnit.Case, async: true

  # Load the script's actual functions without executing its command-line entry point.
  {:__block__, _, [module | _]} =
    "scripts/release_sbom.exs" |> File.read!() |> Code.string_to_quoted!()

  Code.eval_quoted(module)

  test "the lockfile is read as literal data through public APIs" do
    lock = RequestSeal.ReleaseSBOM.lock!()
    assert {:hex, :telemetry, version, _, _, _, _, _} = lock.telemetry
    assert Version.parse(version) != :error
  end

  test "public package identifiers and URLs are allowed" do
    for value <- [
          "A fast, parallel test runner\n",
          "Client / server toolkit",
          "Writes caches under tmp/ by default",
          "Parse a .env file: KEY=value",
          "ratio 3 / 4",
          "about ~2x/day",
          "Lightweight HTTP/2 client",
          "Erlang/OTP 27",
          "https://example.com/home/source",
          "http://example.com/tmp/package",
          "ssh://example.com/home/source",
          "git://example.com/home/source",
          "git+https://example.com/home/source",
          "git+ssh://example.com/home/source",
          "mailto:team@example.com",
          "urn:example:/tmp/package",
          "data:text/plain,/tmp/package"
        ] do
      assert :ok ==
               RequestSeal.ReleaseSBOM.reject_paths!(%{
                 "components" => [%{"properties" => [%{"value" => value}]}]
               })
    end

    assert :ok ==
             RequestSeal.ReleaseSBOM.reject_paths!(%{
               "metadata" => %{"name" => "request_seal", "version" => "2.0.0-dev"},
               "components" => [
                 %{
                   "purl" => "pkg:hex/telemetry@1.4.3",
                   "url" => "https://github.com/beam-telemetry/telemetry",
                   "description" =>
                     "docs/reference/compatibility.md; tmp/package; runner/work/package; home/account/package; temp/package; _work/package",
                   "links" => [
                     "ftp://example.com/tmp/package",
                     "ssh://example.com/home/source",
                     "mailto:team@example.com",
                     "urn:example:/tmp/package",
                     "data:text/plain,/tmp/package"
                   ]
                 }
               ],
               "serialNumber" => "urn:uuid:3ca6fa60-6e3b-510e-8de9-939c220532ca"
             })
  end

  test "filesystem paths are rejected in every nested string value" do
    for path <- [
          "/" <> "home/rp/project",
          "path:/" <> "home/rp/project",
          "dir:/" <> "Users/rp/x",
          "/tmp/x",
          "/var/folders/x",
          "/private/var/x",
          "/root/x",
          "/opt/x",
          "/github/workspace",
          "/__w/x",
          "/runner/work",
          "/mnt/data/x",
          "C:\\Users\\x",
          "\\\\server\\share",
          "file:///etc/x",
          "git+file:///home/rp/x",
          "GIT+FILE:///tmp/x/",
          "svn+file:///opt/x/",
          "~/x",
          "$HOME/x",
          "${HOME}/x",
          "$TMPDIR/x",
          "%USERPROFILE%\\x",
          Path.join(["/", "var", "cache", "package"]),
          Path.join(["/", "tmp", "package"]),
          "C:" <> "\\" <> "build" <> "\\" <> "package",
          "\\\\" <> "server" <> "\\" <> "share",
          "~/package",
          "~account/package",
          "$HOME/package",
          "${TMPDIR}/package",
          "file:" <> "///" <> "package",
          "$TMPDIR/package",
          "${HOME}/package",
          "%USERPROFILE%/package",
          "source=" <> Path.join(["/", "opt", "package"])
        ],
        path <- [path, "Source location: #{path} (unavailable)"] do
      error =
        assert_raise Mix.Error, ~r/filesystem path/, fn ->
          RequestSeal.ReleaseSBOM.reject_paths!(%{
            "components" => [%{"properties" => [%{"value" => path}]}]
          })
        end

      assert Exception.message(error) =~ "components[0].properties[0].value"
      assert Exception.message(error) =~ inspect(path)
    end
  end

  test "unsupported lock shapes name the dependency and entry" do
    for entry <- [
          {:hex, :dependency, "1.0.0", "checksum", [:mix], [], "hexpm"},
          {:hex, :dependency, "1.0.0", "checksum", [:mix], :invalid, "hexpm", "outer"},
          {:git, "https://example.com/library.git", "revision", []},
          :invalid
        ] do
      error =
        assert_raise Mix.Error, ~r/unsupported lock shape for dependency/, fn ->
          RequestSeal.ReleaseSBOM.scopes([{:dependency, "~> 1.0"}], %{dependency: entry})
        end

      assert Exception.message(error) =~ inspect(entry)
      assert Exception.message(error) =~ "8-tuple :hex"
    end
  end

  test "prod scope follows required paths, optional roots and environment filters" do
    edge = fn app, optional -> {app, "~> 1.0", [hex: app, repo: "hexpm", optional: optional]} end
    entry = fn app, edges -> {:hex, app, "1.0.0", "checksum", [:mix], edges, "hexpm", "outer"} end

    lock = %{
      required_root:
        entry.(:required_root, [edge.(:required_child, false), edge.(:optional_edge, true)]),
      required_child: entry.(:required_child, [edge.(:shared, false)]),
      optional_root:
        entry.(:optional_root, [edge.(:optional_child, false), edge.(:shared, false)]),
      optional_child: entry.(:optional_child, []),
      optional_edge: entry.(:optional_edge, []),
      shared: entry.(:shared, [edge.(:required_root, false)]),
      development: entry.(:development, []),
      tests: entry.(:tests, [])
    }

    scopes =
      RequestSeal.ReleaseSBOM.scopes(
        [
          {:required_root, "~> 1.0"},
          {:optional_root, "~> 1.0", optional: true},
          {:optional_edge, optional: true, only: [:prod, :test]},
          {:development, "~> 1.0", only: [:dev, :test]},
          {:tests, "~> 1.0", only: :test}
        ],
        lock
      )

    assert scopes == %{
             required_root: "required",
             required_child: "required",
             shared: "required",
             optional_root: "optional",
             optional_child: "optional",
             optional_edge: "optional"
           }

    bom = %{
      "components" =>
        Enum.map(scopes, fn {app, _} ->
          %{"name" => Atom.to_string(app), "scope" => "required"}
        end)
    }

    rewritten = RequestSeal.ReleaseSBOM.rewrite_scopes!(bom, scopes)
    assert :ok == RequestSeal.ReleaseSBOM.verify_scopes!(rewritten, scopes)

    for {app, scope} <- scopes do
      tampered =
        Map.update!(rewritten, "components", fn components ->
          Enum.map(components, fn component ->
            if component["name"] == Atom.to_string(app),
              do:
                Map.put(
                  component,
                  "scope",
                  if(scope == "required", do: "optional", else: "required")
                ),
              else: component
          end)
        end)

      assert_raise Mix.Error, ~r/scope mismatch for #{app}/, fn ->
        RequestSeal.ReleaseSBOM.verify_scopes!(tampered, scopes)
      end
    end

    without_optional_root = RequestSeal.ReleaseSBOM.scopes([{:required_root, "~> 1.0"}], lock)
    refute Map.has_key?(without_optional_root, :optional_edge)
  end
end
