Code.require_file("support/plug_transport_helper.exs", __DIR__)

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
        components = ~s[("@method" "@scheme" "@authority" "@path")]
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
        {:request_seal, "~> 0.3.1"}
        ''',
        binding,
        "README.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        [
          {:request_seal, "~> 0.3.1"},
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

          # Capture keeps the signed body bytes before Parsers consumes them.
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
        webhook_components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]

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

          # verify: :none skips response verification; the receiver verifies this request.
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

    original_binding = binding

    {outgoing_url, _} = RequestSeal.PlugTransport.start(owner: self())
    E.configure(:my_app, :outgoing_url, outgoing_url <> "/")

    binding =
      E.eval(
        ~S'''
        {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, apps} = Application.ensure_all_started(:req)
        {:ok, pool} = Finch.start_link(name: OutgoingFinch)
        try do
          request = Req.new(url: Application.fetch_env!(:my_app, :outgoing_url), finch: [name: OutgoingFinch], retry: false)
          spec = %{label: "sig", algorithm: "ed25519", components: ~s[("@method" "@scheme" "@authority" "@path")], expires_in: 60}
          # verify: :none skips verification of this unsigned response.
          {:ok, request} = RequestSeal.Req.attach(request, sign: spec, signer: handle, verify: :none)
          {:ok, response} = Req.request(request)
          IO.inspect(response.status)
        after
          Supervisor.stop(pool)
          RequestSeal.Custody.Local.release(handle)
          Enum.each(Enum.reverse(apps), &Application.stop/1)
        end
        ''',
        binding,
        "README.md",
        5
      )

    assert Keyword.fetch!(binding, :example_result) == 200
    assert_receive {:observed, _, {:ok, captured}, _}, 5_000

    {:ok, outgoing_key} =
      RequestSeal.PublicKey.import({:ed25519, Keyword.fetch!(binding, :_public)}, :raw)

    {:ok, outgoing_policy} =
      RequestSeal.Policy.new(%{
        algorithms: ["ed25519"],
        components: Keyword.fetch!(binding, :spec).components,
        key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: outgoing_key}} end,
        freshness: :not_evaluated,
        content: :not_required,
        replay: :not_required
      })

    assert {:ok, outgoing_verification} =
             RequestSeal.verify(captured.message, outgoing_policy, label: "sig")

    assert outgoing_verification.signature.crypto == :valid
    binding = original_binding

    # The webhook script released its sender. Use the live hello-world key here.
    key = Keyword.fetch!(binding, :key)

    {:ok, phoenix_policy} =
      RequestSeal.Policy.new(%{
        Map.from_struct(Keyword.fetch!(binding, :webhook_policy))
        | key_resolver: fn
            %{keyid: "sender-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
            _ -> :error
          end
      })

    E.configure(:my_app, :http_signature_policy, phoenix_policy)
    binding = Keyword.put(binding, :webhook_policy, phoenix_policy)

    binding =
      E.eval(
        ~S'''
        Application.put_env(:my_app, :http_signature_policy, webhook_policy)

        defmodule MyAppWeb.SignedWebhookPipeline do
          use Plug.Builder

          def signature_policy, do: Application.fetch_env!(:my_app, :http_signature_policy)

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
            policy: &__MODULE__.signature_policy/0,
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

        defmodule MyAppWeb.Router do
          use Phoenix.Router

          scope "/", MyAppWeb do
            post("/webhooks", WebhookController, :create)
          end
        end

        defmodule MyAppWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :my_app

          plug(MyAppWeb.SignedWebhookPipeline)

          plug(Plug.Parsers,
            parsers: [:urlencoded, :multipart, :json],
            pass: ["*/*"],
            json_decoder: Jason
          )

          plug(MyAppWeb.Router)
        end
        ''',
        binding,
        "README.md",
        6
      )

    E.configure(:my_app, MyAppWeb.Endpoint,
      server: true,
      adapter: Bandit.PhoenixAdapter,
      http: [ip: {127, 0, 0, 1}, port: 0, http_options: [compress: false]],
      secret_key_base: String.duplicate("a", 64),
      debug_errors: false,
      pubsub_server: RequestSeal.ReadmePubSub
    )

    start_supervised!({Phoenix.PubSub, name: RequestSeal.ReadmePubSub})
    start_supervised!(MyAppWeb.Endpoint)
    {:ok, {_, port}} = Bandit.PhoenixAdapter.server_info(MyAppWeb.Endpoint, :http)
    url = "http://127.0.0.1:#{port}/webhooks"

    {:ok, pool} = Finch.start_link(name: ReadmePhoenixFinch)

    request =
      Req.new(
        url: url,
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
    assert response.body == %{"event" => "created", "signature_label" => "sig"}

    assert Req.post!(url,
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

        IO.puts("signed agent request")
        ''',
        binding,
        "README.md",
        7
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
        IO.inspect(verification.signature.crypto)
        ''',
        binding,
        "README.md",
        8
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
        IO.inspect(scope.tenant)
        ''',
        binding,
        "README.md",
        9
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
        IO.inspect(accepted.signature.crypto)
        ''',
        binding,
        "README.md",
        10
      )

    binding =
      E.eval(
        ~S'''
        {:error, replay_error} = RequestSeal.verify(signed, replay_policy, label: "sig")
        IO.inspect(replay_error.reason)
        ''',
        binding,
        "README.md",
        11
      )

    assert Keyword.fetch!(binding, :replay_error).reason == :replayed
    E.assert_fences("README.md", 11)
    RequestSeal.Custody.Local.release(Keyword.fetch!(binding, :handle))
  end
end
