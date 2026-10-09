defmodule RequestSeal.ReadmeTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "README examples execute with real cryptography and HTTP" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        components = ~s[("@method" "@authority" "@path")]
        {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
        spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60}
        {:ok, signed} = RequestSeal.sign(message, spec, handle)
        resolve = fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end
        clock = fn -> System.system_time(:second) end

        {:ok, policy} =
          RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: components,
            key_resolver: resolve,
            freshness: %{clock: clock, max_age: 60, skew: 5, require_expires: true},
            content: :not_required,
            replay: :not_required
          })

        {:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
        # :valid
        IO.inspect(verification.signature.crypto)
        ''',
        binding,
        "README.md",
        1
      )

    assert Keyword.fetch!(binding, :verification).signature.crypto == :valid

    binding =
      E.eval(
        ~S'''
        {:request_seal, git: "https://github.com/baselabs/request_seal.git"}
        ''',
        binding,
        "README.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        [
          {:req, "~> 0.7.4"},
          {:finch, ">= 0.23.0 and < 0.25.0"},
          {:plug, "~> 1.20.3"},
          {:bandit, "~> 1.12.5"},
          {:jason, "~> 1.0"}
        ]
        ''',
        binding,
        "README.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        defmodule WebhookReceiver do
          use Plug.Router

          plug(RequestSeal.Plug.Capture,
            origin: :connection,
            max_body_bytes: 1_048_576,
            read_timeout: 5_000
          )

          plug(Plug.Parsers,
            parsers: [:json],
            pass: ["*/*"],
            json_decoder: Jason,
            body_reader: {RequestSeal.Plug.Capture, :read_body, []}
          )

          plug(RequestSeal.Plug.Verify,
            policy: {Application, :fetch_env!, [:webhook_demo, :signature_policy]},
            label: "sig",
            on_reject: {:halt, 401}
          )

          plug(:match)
          plug(:dispatch)

          post "/webhooks" do
            {:ok, verified} = RequestSeal.Plug.verification(conn)
            send_resp(conn, 200, "#{verified.signature.crypto}: #{conn.body_params["event"]}")
          end

          match _ do
            send_resp(conn, 404, "not found")
          end
        end

        # The sender owns the private key; the receiver gets only its public key.
        {_public, webhook_seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, webhook_handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, webhook_seed})
        {:ok, webhook_key} = RequestSeal.Custody.public_key(webhook_handle)
        webhook_components = ~s[("@method" "@authority" "@path" "content-digest")]

        {:ok, webhook_policy} =
          RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: webhook_components,
            key_resolver: fn
              %{keyid: "sender-key"} -> {:ok, %{algorithm: "ed25519", key: webhook_key}}
              _ -> :error
            end,
            freshness: %{
              clock: fn -> System.system_time(:second) end,
              max_age: 60,
              skew: 5,
              require_expires: true
            },
            content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
            replay: :not_required
          })

        webhook_signing = %{
          label: "sig",
          algorithm: "ed25519",
          components: webhook_components,
          expires_in: 60,
          keyid: "sender-key",
          digest: ["sha-256"]
        }

        Application.put_env(:webhook_demo, :signature_policy, webhook_policy)
        {:ok, webhook_apps} = Application.ensure_all_started(:req)
        {:ok, webhook_pool} = Finch.start_link(name: WebhookFinch)

        {:ok, receiver} =
          Bandit.start_link(
            plug: WebhookReceiver,
            ip: {127, 0, 0, 1},
            port: 0,
            http_options: [compress: false]
          )

        {:ok, {_, port}} = ThousandIsland.listener_info(receiver)

        try do
          request =
            Req.new(
              url: "http://127.0.0.1:#{port}/webhooks",
              method: :post,
              json: %{"event" => "created"},
              finch: [name: WebhookFinch],
              retry: false
            )

          {:ok, request} =
            RequestSeal.Req.attach(request, sign: webhook_signing, signer: webhook_handle, verify: :none)

          {:ok, response} = Req.request(request)
          # {200, "valid: created"}
          IO.inspect({response.status, response.body})

          unsigned =
            Req.post!("http://127.0.0.1:#{port}/webhooks", json: %{"event" => "created"}, retry: false)

          # 401
          IO.inspect(unsigned.status)

          unless response.status == 200 and response.body == "valid: created" and unsigned.status == 401,
            do: raise("webhook verification failed")
        after
          Supervisor.stop(receiver)
          Application.delete_env(:webhook_demo, :signature_policy)
          Supervisor.stop(webhook_pool)
          RequestSeal.Custody.Local.release(webhook_handle)
          Enum.each(Enum.reverse(webhook_apps), &Application.stop/1)
        end
        ''',
        binding,
        "README.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        defmodule MyAppWeb.SignedWebhookPipeline do
          use Plug.Builder

          plug(RequestSeal.Plug.Capture,
            origin: :connection,
            max_body_bytes: 1_048_576,
            read_timeout: 5_000
          )

          plug(Plug.Parsers,
            parsers: [:json],
            pass: ["*/*"],
            json_decoder: Jason,
            body_reader: {RequestSeal.Plug.Capture, :read_body, []}
          )

          plug(RequestSeal.Plug.Verify,
            policy: {Application, :fetch_env!, [:my_app, :http_signature_policy]},
            label: "sig",
            on_reject: {:halt, 401}
          )
        end

        defmodule MyAppWeb.WebhookController do
          use Phoenix.Controller, formats: [:json]

          def create(conn, params) do
            {:ok, verified} = RequestSeal.Plug.verification(conn)
            json(conn, %{signature_label: verified.label, event: params["event"]})
          end
        end
        ''',
        binding,
        "README.md",
        5
      )

    phoenix_binding =
      Keyword.merge(binding,
        policy: Keyword.fetch!(binding, :webhook_policy),
        handle: Keyword.fetch!(binding, :handle),
        signing: Keyword.fetch!(binding, :webhook_signing)
      )

    # The script released its separate sender; use the hello-world key for this endpoint.
    key = Keyword.fetch!(binding, :key)

    {:ok, policy} =
      RequestSeal.Policy.new(%{
        Map.from_struct(Keyword.fetch!(binding, :webhook_policy))
        | key_resolver: fn
            %{keyid: "sender-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
            _ -> :error
          end
      })

    phoenix_binding = Keyword.put(phoenix_binding, :policy, policy)

    phoenix_binding =
      E.endpoint(phoenix_binding, MyAppWeb.SignedWebhookPipeline, MyAppWeb.WebhookController)

    {:ok, pool} = Finch.start_link(name: ReadmePhoenixFinch)

    request =
      Req.new(
        url: Keyword.fetch!(phoenix_binding, :url),
        method: :post,
        json: %{"event" => "created"},
        finch: [name: ReadmePhoenixFinch],
        retry: false
      )

    {:ok, request} =
      RequestSeal.Req.attach(request,
        sign: Keyword.fetch!(binding, :webhook_signing),
        signer: Keyword.fetch!(binding, :handle),
        verify: :none
      )

    {:ok, response} = Req.request(request)
    assert response.status == 200
    E.assert_received_request()

    assert Req.post!(Keyword.fetch!(phoenix_binding, :url),
             finch: [name: ReadmePhoenixFinch],
             json: %{"event" => "created"},
             retry: false
           ).status == 401

    Supervisor.stop(pool)

    binding =
      E.eval(
        ~S'''
        {:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
        signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
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
        "README.md",
        6
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
        "README.md",
        7
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
        "README.md",
        8
      )

    E.assert_ash_read(binding, record)
    E.assert_ash_denial(binding, AshApp.Document)

    binding =
      E.eval(
        ~S'''
        {:ok, replay_pid} = RequestSeal.Replay.ETS.start_link(max_entries: 10_000)

        replay = %{
          identifier: :nonce,
          namespace: "demo-api",
          commitment: fn facts -> {:ok, facts.identifier} end,
          store: RequestSeal.Replay.ETS.store(replay_pid),
          timeout: 5_000
        }

        {:ok, replay_policy} = RequestSeal.Policy.new(%{Map.from_struct(policy) | replay: replay})
        {:ok, accepted} = RequestSeal.verify(signed, replay_policy, label: "sig")
        ''',
        binding,
        "README.md",
        9
      )

    binding =
      E.eval(
        ~S'''
        RequestSeal.verify(signed, replay_policy, label: "sig")
        # => {:error, %RequestSeal.Error{reason: :replayed, ...}}
        ''',
        binding,
        "README.md",
        10
      )

    assert {:error, %{reason: :replayed}} = Keyword.fetch!(binding, :example_result)
    E.assert_fences("README.md", 10)
    RequestSeal.Custody.Local.release(Keyword.fetch!(binding, :handle))
  end
end
