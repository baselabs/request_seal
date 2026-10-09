defmodule RequestSeal.GuideWebBotAuthTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        {:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
        signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
        ''',
        binding,
        "docs/guides/web-bot-auth.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, message} =
          RequestSeal.Message.request(
            "POST",
            "https://api.example.com/webhooks",
            [],
            ~s({"event":"created"}),
            digest: ["sha-256"]
          )
        ''',
        binding,
        "docs/guides/web-bot-auth.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        now = System.system_time(:second)

        {:ok, agent_request} =
          RequestSeal.WebBotAuth.sign(
            message,
            %{
              label: "agent",
              agent: %{location: "https://agent.example", type: :directory},
              key: key,
              algorithm: "ed25519",
              created: now,
              expires: now + 60,
              nonce: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
            },
            signer
          )
        ''',
        binding,
        "docs/guides/web-bot-auth.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        {:ok, agent_policy} =
          RequestSeal.WebBotAuth.Policy.new(%{
            algorithms: ["ed25519"],
            agents: fn _ -> :error end,
            cache: nil,
            unresolved:
              {:held_keys,
               fn
                 %{keyid: ^thumbprint} -> {:ok, %{algorithm: "ed25519", key: key}}
                 _ -> :error
               end},
            freshness: %{clock: fn -> System.system_time(:second) end, max_age: 60, skew: 5},
            content: :not_required,
            replay: :not_required
          })

        {:ok, envelope} = RequestSeal.WebBotAuth.verify(agent_request, agent_policy)
        verification = envelope.signatures["agent"]
        ''',
        binding,
        "docs/guides/web-bot-auth.md",
        4
      )

    assert Keyword.fetch!(binding, :verification).principal == %{
             kind: :key,
             thumbprint: Keyword.fetch!(binding, :thumbprint)
           }

    binding = E.publisher(binding)
    E.configure(:my_app, :agent_jwks_url, Keyword.fetch!(binding, :jwks_url))
    E.configure(:my_app, :agent_ca_roots, Keyword.fetch!(binding, :trust_roots))

    E.configure(
      :my_app,
      :agent_permitted_addresses,
      Keyword.fetch!(binding, :permitted_addresses)
    )

    binding =
      E.eval(
        ~S'''
        jwks_url = Application.fetch_env!(:my_app, :agent_jwks_url)
        trust_roots = Application.fetch_env!(:my_app, :agent_ca_roots)
        permitted_addresses = Application.fetch_env!(:my_app, :agent_permitted_addresses)
        {:ok, _apps} = Application.ensure_all_started(:ssl)

        {:ok, source} =
          RequestSeal.Discovery.Source.new(%{
            type: :jwks_uri,
            location: jwks_url,
            cacerts: trust_roots,
            permitted_addresses: permitted_addresses,
            timeout: 5_000
          })

        {:ok, key_set} = RequestSeal.Discovery.fetch(source)
        ''',
        binding,
        "docs/guides/web-bot-auth.md",
        5
      )

    binding =
      E.eval(
        ~S'''
        {:ok, discovered_agent_policy} =
          RequestSeal.WebBotAuth.Policy.new(%{
            algorithms: ["ed25519"],
            cache: nil,
            agents: fn
              %{location: location, type: :jwks_uri} when location == key_set.source.location ->
                {:ok, key_set}

              _ ->
                :error
            end,
            freshness: %{clock: fn -> System.system_time(:second) end, max_age: 60, skew: 5},
            content: :not_required,
            replay: :not_required
          })
        ''',
        binding,
        "docs/guides/web-bot-auth.md",
        6
      )

    binding =
      E.eval(
        ~S'''
        now = System.system_time(:second)

        {:ok, discovered_request} =
          RequestSeal.WebBotAuth.sign(
            message,
            %{
              label: "agent",
              agent: %{location: key_set.source.location, type: :jwks_uri},
              key: key,
              algorithm: "ed25519",
              created: now,
              expires: now + 60,
              nonce: nil
            },
            signer
          )

        {:ok, discovered_envelope} =
          RequestSeal.WebBotAuth.verify(
            discovered_request,
            discovered_agent_policy
          )

        discovered_envelope.signatures["agent"].principal.kind
        # => :agent
        ''',
        binding,
        "docs/guides/web-bot-auth.md",
        7
      )

    principal = Keyword.fetch!(binding, :discovered_envelope).signatures["agent"].principal
    assert principal.kind == :agent
    assert principal.identifier == Keyword.fetch!(binding, :jwks_url)

    assert {:error, %RequestSeal.Error{reason: :invalid_signature}} =
             RequestSeal.WebBotAuth.verify(
               %{Keyword.fetch!(binding, :agent_request) | authority: "other.example"},
               Keyword.fetch!(binding, :agent_policy)
             )

    E.assert_fences("docs/guides/web-bot-auth.md", 7)
    assert is_list(binding)
  end
end
