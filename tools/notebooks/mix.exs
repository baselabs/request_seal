defmodule RequestSealNotebooks.MixProject do
  use Mix.Project

  def project do
    [
      app: :request_seal_notebooks,
      version: "0.1.0",
      elixir: "1.20.4",
      # The Livebook Hex release pins earmark_parser; isolate it from ExDoc.
      # Exact Livebook identity binds the internal importer/exporter we execute.
      deps: [
        {:livebook, "== 0.19.10", runtime: false},
        # OBSERVED: 0.3.2 fails on OTP 29's deprecated format_status/2 callback.
        # The current stable release implements format_status/1.
        {:aws_credentials, "~> 1.1.1", override: true, runtime: false},
        # Override upstream application pins with advisory-fixed releases.
        # This tooling executes importer/exporter only; every override is lockfile-audited.
        {:bandit, "~> 1.12.5", override: true, runtime: false},
        {:phoenix, "~> 1.8.15", override: true, runtime: false},
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
end
