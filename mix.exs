defmodule RequestSeal.MixProject do
  use Mix.Project

  # Reviewed public guides: one inventory for Hex and ExDoc. No directory exports.
  @public_documents [
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    "test/fixtures/web_bot_auth/PROVENANCE.md",
    "docs/adr/0001-library-boundary.md",
    "docs/adr/0002-lossless-http-and-structured-fields.md",
    "docs/adr/0003-source-bound-profiles.md",
    "docs/adr/0004-key-custody-and-discovery.md",
    "docs/adr/0005-atomic-replay-envelope.md",
    "docs/adr/0006-verification-results-and-observability.md",
    "docs/adr/0007-framework-and-proxy-adapters.md",
    "docs/adr/0008-toolchain-and-compatibility.md",
    "docs/adr/0009-cross-language-corpus.md",
    "docs/adr/0010-dx-and-livebooks.md",
    "docs/adr/0011-public-contract-provenance.md",
    "docs/adr/0013-extension-profile-boundary.md",
    "docs/design/architecture.md",
    "docs/design/threat-model.md",
    "docs/guides/getting-started.md",
    "docs/guides/testing.md",
    "docs/operations/releases.md",
    "docs/reference/glossary.md",
    "docs/reference/standards.md",
    "livebooks/README.md",
    "livebooks/environment.livemd",
    "livebooks/rfc-ed25519.livemd"
  ]

  def project do
    # Dependency consumers do not load this library's config/config.exs.
    unless Code.ensure_loaded?(:json) do
      raise "RequestSeal requires Erlang/OTP 27 or newer for :json."
    end

    [
      app: :request_seal,
      version: "0.1.0-dev",
      # Libraries declare a consumer range; development and notebook tools stay pinned.
      # OTP 27 supplies :json; both supported CI lanes are recorded in ADR 0008.
      elixir: "~> 1.18",
      name: "RequestSeal",
      source_url: "https://github.com/baselabs/request_seal",
      description: "HTTP message signatures and agent authentication for Elixir.",
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: dependencies(),
      package: [
        licenses: ["Apache-2.0", "BSD-3-Clause"],
        files: ["lib/**/*.ex", "mix.exs" | @public_documents],
        links: %{"GitHub" => "https://github.com/baselabs/request_seal"}
      ],
      docs: [
        main: "readme",
        extras:
          Enum.map(@public_documents, fn
            "livebooks/README.md" -> {"livebooks/README.md", filename: "livebooks"}
            path -> path
          end),
        groups_for_extras: [
          "Start here": ["README.md", ~r/docs\/guides\//],
          Reference: ~r/docs\/reference\//,
          Design: ~r/docs\/design\//,
          Decisions: ~r/docs\/adr\//,
          Livebooks: ~r/livebooks\//,
          Maintenance: ["CONTRIBUTING.md", "SECURITY.md", ~r/docs\/operations\//]
        ]
      ]
    ]
  end

  defp dependencies do
    # Ash needs StreamData in dev/prod; scope the test override here to keep it out of Hex requirements.
    test_dependencies =
      if Mix.env() == :test,
        do: [{:stream_data, "~> 1.1", only: :test, override: true}],
        else: []

    [
      {:ex_doc, "~> 0.40.4", only: [:dev, :test], runtime: false},
      # Floor is the Ash minor series the real-action tests ran against (lock: 3.34.5); Ash.Scope itself dates from 3.5.13.
      {:ash, "~> 3.34", optional: true},
      {:simple_sat, "~> 0.1", only: :test},
      # Use stable Req; 0.8.0-rc.0 is a release candidate.
      # Consumers own client startup; importing this library starts no pool.
      {:req, "~> 0.7.4", optional: true, runtime: false},
      {:finch, ">= 0.23.0 and < 0.25.0", optional: true, runtime: false},
      {:plug, "~> 1.20.3", optional: true, runtime: false},
      {:bandit, "~> 1.12.5", only: :test},
      {:phoenix, "~> 1.8.15", only: :test},
      {:postgrex, "~> 0.22.4", optional: true, runtime: false}
    ] ++ test_dependencies
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application, do: [extra_applications: [:crypto, :public_key]]
end
