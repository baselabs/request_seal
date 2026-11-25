defmodule RequestSeal.MixProject do
  use Mix.Project

  @version "2.0.0-dev"

  # Reviewed public guides: one inventory for Hex and ExDoc. No directory exports.
  @public_documents [
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    "IPR.md",
    "TRADEMARKS.md",
    "docs/design/architecture.md",
    "docs/design/threat-model.md",
    "docs/guides/getting-started.md",
    "docs/guides/signing-and-verifying.md",
    "docs/guides/errors.md",
    "docs/guides/phoenix-and-plug.md",
    "docs/guides/req-and-finch.md",
    "docs/guides/ash.md",
    "docs/guides/ash-hooks.md",
    "docs/guides/decision-hook.md",
    "docs/guides/credential-proxy.md",
    "docs/guides/web-bot-auth.md",
    "docs/guides/replay-protection.md",
    "docs/guides/idempotency.md",
    "docs/guides/key-discovery.md",
    "docs/guides/jose.md",
    "docs/guides/key-custody.md",
    "docs/guides/key-generation-and-derivation.md",
    "docs/guides/json-object-content.md",
    "docs/guides/upgrading-to-2.0.md",
    "docs/guides/key-rotation.md",
    "docs/guides/testing-your-integration.md",
    "docs/guides/testing.md",
    "docs/guides/verifying-releases.md",
    "docs/reference/compatibility.md",
    "docs/reference/corpus-format.md",
    "docs/reference/glossary.md",
    "docs/reference/standards.md",
    "livebooks/overview.md",
    "livebooks/environment.livemd",
    "livebooks/rfc-ed25519.livemd",
    "livebooks/sign-and-verify.livemd",
    "livebooks/plug-webhook.livemd",
    "livebooks/web-bot-auth.livemd",
    "livebooks/jose.livemd",
    "livebooks/ecdh-es.livemd",
    "livebooks/jwe-batch.livemd"
  ]

  def project do
    # Dependency consumers do not load this library's config/config.exs.
    unless Code.ensure_loaded?(:json) do
      raise "RequestSeal requires Erlang/OTP 27 or newer for :json."
    end

    [
      app: :request_seal,
      version: @version,
      # Libraries declare a consumer range; development and notebook tools stay pinned.
      # OTP 27 supplies :json; CI tests the floor, a middle and the latest toolchain.
      elixir: "~> 1.18",
      name: "RequestSeal",
      source_url: "https://github.com/baselabs/request_seal",
      description:
        "Sign and verify HTTP requests and responses in Elixir: RFC 9421 HTTP Message Signatures, Web Bot Auth for AI agents, JWS/JWE, digests and replay protection, with Plug (including Phoenix), Req, Finch and Ash integrations.",
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: dependencies(),
      dialyzer: [
        # Optional integration adapters compile in dev; their apps belong in
        # the PLT so their calls resolve instead of reporting unknowns.
        plt_add_apps: [:req, :finch, :mint, :plug, :postgrex, :telemetry]
      ],
      package: [
        licenses: ["Apache-2.0", "BSD-3-Clause"],
        files: ["lib/**/*.ex", "mix.exs" | @public_documents],
        links: %{
          "GitHub" => "https://github.com/baselabs/request_seal",
          "Changelog" => "https://request-seal.hexdocs.pm/changelog.html"
        }
      ],
      docs: [
        main: "readme",
        formatters: ["html"],
        before_closing_footer_tag: %{html: "<p>© 2026 BaseLabs Holdings LLC · Apache-2.0</p>"},
        source_ref: source_ref(),
        # Historical entries retain references to removed APIs.
        skip_undefined_reference_warnings_on: ["CHANGELOG.md"],
        extras:
          Enum.map(@public_documents, fn
            "livebooks/overview.md" -> {"livebooks/overview.md", filename: "livebooks"}
            "livebooks/" <> name = path -> {path, filename: "livebook-" <> Path.rootname(name)}
            path -> path
          end),
        groups_for_extras: [
          "Start here": ["README.md"],
          Guides: ~r/docs\/guides\/(?!getting-started\.md|testing\.md)/,
          Reference: ~r/docs\/reference\//,
          "Design and decisions": ~r/docs\/design\//,
          Livebooks: ~r/livebooks\//,
          Contributing: [
            "CONTRIBUTING.md",
            "SECURITY.md",
            "IPR.md",
            "TRADEMARKS.md",
            "docs/guides/getting-started.md",
            "docs/guides/testing.md"
          ]
        ],
        groups_for_modules: [
          Core: [
            RequestSeal,
            RequestSeal.Message,
            RequestSeal.Message.Error,
            RequestSeal.Body,
            RequestSeal.FieldOccurrence,
            RequestSeal.TransportFacts,
            RequestSeal.Policy,
            RequestSeal.Verification,
            RequestSeal.Error,
            RequestSeal.SignatureBase,
            RequestSeal.SignatureBase.Error,
            RequestSeal.Telemetry,
            ~r/^RequestSeal\.(StructuredFields|Digest|Crypto|AcceptSignature)(\.|$)/
          ],
          "Keys and custody": [
            RequestSeal.PublicKey,
            RequestSeal.KeyHandle,
            RequestSeal.KeyIdentity,
            ~r/^RequestSeal\.Custody(\.|$)/
          ],
          Discovery: ~r/^RequestSeal\.Discovery(\.|$)/,
          Replay: ~r/^RequestSeal\.(Replay|Idempotency|Journal)(\.|$)/,
          JOSE: ~r/^RequestSeal\.JOSE(\.|$)/,
          "Web Bot Auth": ~r/^RequestSeal\.WebBotAuth(\.|$)/,
          Integrations: ~r/^RequestSeal\.(Req|Finch|Plug|Ash|AshHooks|Adapter)(\.|$)/,
          Profiles: [RequestSeal.Profile]
        ]
      ]
    ]
  end

  defp source_ref do
    if development_snapshot?(), do: "main", else: "baselabs_request_seal-v#{@version}"
  end

  defp development_snapshot? do
    case Version.parse!(@version).pre do
      [first | _] when is_binary(first) -> String.starts_with?(first, "dev")
      _ -> false
    end
  end

  defp dependencies do
    # Ash needs StreamData in dev/prod; scope the test override here to keep it out of Hex requirements.
    test_dependencies =
      if Mix.env() == :test,
        do: [{:stream_data, ">= 1.4.0 and < 2.0.0", only: :test, override: true}],
        else: []

    [
      {:ex_doc, "~> 0.40.4", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1.5", only: [:dev, :test], runtime: false},
      # Static analysis in the declared gate; PLT is cached in CI.
      {:dialyxir, ">= 1.4.8 and < 2.0.0", only: [:dev, :test], runtime: false},
      # The only required dependency: the versioned telemetry contract emits
      # through it (ADR 0006). No transitive dependencies.
      {:telemetry, ">= 1.4.2 and < 2.0.0"},
      # Require the Ash security patch line used by the optional integrations.
      {:ash, ">= 3.38.1 and < 4.0.0", optional: true},
      {:simple_sat, "~> 0.1", only: :test},
      # Use stable Req; 0.8.0-rc.0 is a release candidate.
      # Consumers own client startup; importing this library starts no pool.
      {:req, "~> 0.7.4", optional: true, runtime: false},
      {:finch, ">= 0.25.0 and < 0.26.0", optional: true, runtime: false},
      {:plug, ">= 1.20.4 and < 2.0.0", optional: true, runtime: false},
      {:bandit, ">= 1.15.0 and < 2.0.0", only: :test},
      {:phoenix, ">= 1.8.17 and < 2.0.0", only: :test},
      {:postgrex, ">= 0.22.4 and < 0.24.0", optional: true, runtime: false}
    ] ++ test_dependencies ++ owned_integrations()
  end

  # These optional packages require Elixir 1.20. Floor/mid developer and CI
  # toolchains omit them; the latest lane executes their real integrations.
  defp owned_integrations do
    if Version.match?(System.version(), ">= 1.20.0") do
      [
        {:ash_onetime, "~> 1.9 and >= 1.9.2", optional: true},
        {:ash_hooks, ">= 3.0.0 and < 4.0.0", optional: true}
      ]
    else
      []
    end
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application, do: [extra_applications: [:crypto, :public_key | test_applications(Mix.env())]]

  # The JWE oracles count sensitive worker calls with :cover, which ships in :tools.
  defp test_applications(:test), do: [:tools]
  defp test_applications(_), do: []
end
