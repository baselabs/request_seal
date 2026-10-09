defmodule RequestSeal.GuideAshTest do
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
        "docs/guides/ash.md",
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
        "docs/guides/ash.md",
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
        "docs/guides/ash.md",
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
        "docs/guides/ash.md",
        4
      )

    assert Keyword.fetch!(binding, :verification).principal == %{
             kind: :key,
             thumbprint: Keyword.fetch!(binding, :thumbprint)
           }

    binding =
      E.eval(
        ~S'''
        defmodule AshApp.Document do
          use Ash.Resource,
            domain: AshApp.Documents,
            data_layer: Ash.DataLayer.Ets,
            authorizers: [Ash.Policy.Authorizer]

          ets do
            private?(false)
          end

          multitenancy do
            strategy(:attribute)
            attribute(:tenant_id)
          end

          attributes do
            uuid_primary_key(:id)
            attribute(:tenant_id, :string, allow_nil?: false)
          end

          actions do
            defaults([:read])
          end

          policies do
            policy action_type(:read) do
              authorize_if(actor_attribute_equals(:role, :reader))
            end
          end
        end
        ''',
        binding,
        "docs/guides/ash.md",
        5
      )

    binding =
      E.eval(
        ~S'''
        defmodule AshApp.Documents do
          use Ash.Domain, validate_config_inclusion?: false

          resources do
            resource(AshApp.Document)
          end
        end
        ''',
        binding,
        "docs/guides/ash.md",
        6
      )

    record = E.seed_documents(AshApp.Document)

    binding =
      E.eval(
        ~S'''
        {:ok, scope} =
          RequestSeal.Ash.scope(verification, %{
            actor: fn
              %{kind: :key, thumbprint: ^thumbprint} -> {:ok, %{role: :reader}}
              _ -> :error
            end,
            tenant: {:value, "demo"},
            unattributed: :reject
          })

        documents = Ash.read!(AshApp.Document, scope: scope, authorize?: true)
        ''',
        binding,
        "docs/guides/ash.md",
        7
      )

    E.assert_ash_read(binding, record)
    E.assert_ash_denial(binding, AshApp.Document)
    assert Protocol.consolidated?(Ash.ToTenant)
    assert Protocol.consolidated?(Ash.Scope.ToOpts)

    assert {:error, %RequestSeal.Error{reason: :invalid_signature}} =
             RequestSeal.WebBotAuth.verify(
               %{Keyword.fetch!(binding, :agent_request) | authority: "other.example"},
               Keyword.fetch!(binding, :agent_policy)
             )

    E.assert_fences("docs/guides/ash.md", 7)
    assert is_list(binding)
  end
end
