if Code.ensure_loaded?(AshHooks.Provider) do
  defmodule RequestSeal.GuideHooksReceiver do
    @behaviour Plug
    def init(opts), do: opts

    def call(conn, opts) do
      conn = apply(SignedWebhookIngress, :call, [conn, [policy: opts[:policy]]])

      send(
        opts[:owner],
        {:guide_hooks, RequestSeal.Plug.verification(conn), conn.assigns[:webhook_body],
         Map.new(conn.req_headers)}
      )

      if conn.halted, do: conn, else: Plug.Conn.send_resp(conn, 204, "")
    end
  end

  defmodule RequestSeal.GuideAshHooksTest do
    use ExUnit.Case, async: false
    @moduletag :postgres
    alias RequestSeal.DocsExamples, as: E

    test "every webhook fence executes with a real delivery ledger and HTTP receiver" do
      prefix = RequestSeal.OwnedDatabase.start()
      RequestSeal.HooksTestSupport.tables()

      on_exit(fn ->
        RequestSeal.HooksTestSupport.drop()
        RequestSeal.OwnedDatabase.drop(prefix)
      end)

      binding = []

      binding =
        E.eval(
          ~S'''
          {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
          {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
          {:ok, key} = RequestSeal.Custody.public_key(handle)
          components = ~s[("@method" "@authority" "@path" "content-digest" "content-type" "webhook-id")]
          spec = %{
            label: "sig",
            algorithm: "ed25519",
            components: components,
            expires_in: 60,
            keyid: "webhook-key",
            digest: ["sha-256"]
          }
          {:ok, policy} = RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: components,
            key_resolver: fn
              %{keyid: "webhook-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
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
          ''',
          binding,
          "docs/guides/ash-hooks.md",
          1
        )

      on_exit(fn -> RequestSeal.Custody.Local.release(Keyword.fetch!(binding, :handle)) end)

      binding =
        E.eval(
          ~S'''
          defmodule SignedWebhookIngress do
            @behaviour Plug
            def init(opts), do: opts

            def call(conn, opts) do
              conn = RequestSeal.Plug.Capture.call(conn,
                RequestSeal.Plug.Capture.init(
                  origin: :connection, max_body_bytes: 100_000, read_timeout: 5_000))
              conn = RequestSeal.Plug.Verify.call(conn,
                RequestSeal.Plug.Verify.init(
                  policy: opts[:policy], label: "sig", on_reject: {:halt, 401}, assign: :verified_webhook))

              if conn.halted do
                conn
              else
                {:ok, body, conn} = AshHooks.BodyReader.read_body(conn, [])
                Plug.Conn.assign(conn, :webhook_body, body)
              end
            end
          end
          ''',
          binding,
          "docs/guides/ash-hooks.md",
          2
        )

      policy = Keyword.fetch!(binding, :policy)

      server =
        start_supervised!(
          {Bandit,
           plug: {RequestSeal.GuideHooksReceiver, [policy: policy, owner: self()]},
           ip: {127, 0, 0, 1},
           port: 0,
           startup_log: false}
        )

      {:ok, {_, port}} = ThousandIsland.listener_info(server)
      destination = "http://localhost:#{port}/events"

      endpoint =
        Ash.create!(RequestSeal.HooksEndpoint, %{url: destination, secret_ref: "guide-key"},
          authorize?: false
        )

      {:ok, event} = AshHooks.Event.new(type: :order_paid, payload: ~s({"order":1}))

      delivery =
        Ash.create!(
          RequestSeal.HooksDelivery,
          %{
            event_uuid: event.id,
            event_type: "order_paid",
            payload: event.payload,
            endpoint_id: endpoint.id
          },
          action: :dispatch,
          authorize?: false
        )

      secret = "whsec_" <> Base.encode64(:crypto.strong_rand_bytes(32))

      binding =
        binding ++
          [
            deliveries: RequestSeal.HooksDelivery,
            endpoints: RequestSeal.HooksEndpoint,
            secret_resolver: fn "guide-key" -> {:ok, secret} end,
            delivery: delivery
          ]

      binding =
        E.eval(
          ~S'''
          config = [
            deliveries: deliveries,
            endpoints: endpoints,
            secret_resolver: secret_resolver,
            http: RequestSeal.AshHooks.Http,
            http_opts: [request_seal: [spec: spec, signer: handle]]
          ]
          ''',
          binding,
          "docs/guides/ash-hooks.md",
          3
        )

      # The real local receiver is explicitly authorized; production retains SSRF defaults.
      binding =
        Keyword.update!(binding, :config, fn config ->
          config
          |> Keyword.put(:ssrf_check, fn target -> target == destination end)
          |> Keyword.update!(:http_opts, &Keyword.put(&1, :validate_destination, false))
        end)

      binding =
        E.eval(
          ~S'''
          :ok = AshHooks.Delivery.run(%{
            "endpoint_id" => delivery.endpoint_id,
            "event_uuid" => delivery.event_uuid
          }, config)
          ''',
          binding,
          "docs/guides/ash-hooks.md",
          4
        )

      assert_receive {:guide_hooks, {:ok, result}, body, headers}, 5_000
      assert result.signature.crypto == :valid
      assert body == event.payload
      assert headers["webhook-id"] == event.id
      persisted = Ash.get!(RequestSeal.HooksDelivery, delivery.id, authorize?: false)
      assert persisted.status == :succeeded
      assert persisted.response_status == 204
      binding = binding ++ [body: body, headers: headers, destination: destination]

      binding =
        E.eval(
          ~S'''
          context = %{
            method: "POST",
            request_uri: destination,
            headers: headers,
            signature: headers["signature"],
            tenant: nil
          }
          :ok = RequestSeal.AshHooks.verify_signature(body, context, "webhook-key",
            policy: fn "webhook-key" -> policy end, label: "sig")
          ''',
          binding,
          "docs/guides/ash-hooks.md",
          5
        )

      assert Keyword.fetch!(binding, :example_result) == :ok
      E.assert_fences("docs/guides/ash-hooks.md", 5)
    end
  end
end
