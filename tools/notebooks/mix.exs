defmodule RequestSealNotebooks.MixProject do
  use Mix.Project

  def project do
    [
      app: :request_seal_notebooks,
      version: "0.1.0",
      # The notebook tooling runs on the latest Elixir pinned in .tool-versions.
      elixir: latest_elixir(),
      # The Livebook Hex release pins earmark_parser; isolate it from ExDoc.
      # Exact Livebook identity binds the internal importer/exporter we execute.
      deps: [
        {:livebook, "== 0.19.10", runtime: false},
        {:aws_credentials, "~> 1.1.1", override: true, runtime: false},
        # Override upstream application pins with advisory-fixed releases.
        # This tooling executes importer/exporter only; every override is lockfile-audited.
        {:bandit, "~> 1.15", override: true, runtime: false},
        # Livebook 0.19.10 pins ecto 3.13.6 (EEF-CVE-2026-118391); 3.14.3 is the fixed release.
        {:ecto, "~> 3.14.3", override: true, runtime: false},
        {:phoenix, "~> 1.8.15", override: true, runtime: false},
        {:phoenix_html, "~> 4.4", override: true, runtime: false},
        {:phoenix_live_view, "~> 1.2.12", override: true, runtime: false},
        {:plug, "~> 1.20.3", override: true, runtime: false},
        # Phoenix security updates require the matching newer crypto API.
        {:plug_crypto, "~> 2.2.0", override: true, runtime: false},
        {:protobuf, "~> 0.17.0", override: true, runtime: false},
        {:req, "~> 0.7.5", override: true, runtime: false}
      ]
    ]
  end

  def application, do: [extra_applications: [:crypto]]

  defp latest_elixir do
    ~r/^elixir\s+(.+)$/m
    |> Regex.run(File.read!(Path.expand("../../.tool-versions", __DIR__)),
      capture: :all_but_first
    )
    |> hd()
    |> String.split()
    |> Enum.map(&(&1 |> String.split("-otp-") |> hd() |> Version.parse!()))
    |> Enum.max(Version)
    |> to_string()
  end
end
