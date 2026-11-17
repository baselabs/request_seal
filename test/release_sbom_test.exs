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
    assert :ok ==
             RequestSeal.ReleaseSBOM.reject_paths!(%{
               "metadata" => %{"name" => "request_seal", "version" => "2.0.0-dev"},
               "components" => [
                 %{
                   "purl" => "pkg:hex/telemetry@1.4.3",
                   "url" => "https://github.com/beam-telemetry/telemetry"
                 }
               ],
               "serialNumber" => "urn:uuid:3ca6fa60-6e3b-510e-8de9-939c220532ca"
             })
  end

  test "filesystem paths are rejected in every nested string value" do
    for path <- [
          Path.join(["/", "var", "cache", "package"]),
          Path.join(["/", "tmp", "package"]),
          "C:" <> "\\" <> "build" <> "\\" <> "package",
          "\\\\" <> "server" <> "\\" <> "share",
          "~/package",
          "~account/package",
          "$HOME/package",
          "${TMPDIR}/package",
          "file:" <> "///" <> "package",
          "runner/work/package",
          "tmp/package",
          "home/account/package",
          "temp/package",
          "_work/package",
          "source=" <> Path.join(["/", "opt", "package"])
        ] do
      assert_raise Mix.Error, ~r/filesystem path/, fn ->
        RequestSeal.ReleaseSBOM.reject_paths!(%{
          "components" => [%{"properties" => [%{"value" => path}]}]
        })
      end
    end
  end
end
