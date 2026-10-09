if Code.ensure_loaded?(AshHooks.Provider) do
  defmodule RequestSeal.AshHooksTest do
    use ExUnit.Case, async: false
    @moduletag :postgres
    alias RequestSeal.{HooksTestSupport, OwnedDatabase, HooksEndpoint, HooksDelivery}
    alias RequestSeal.AshHooks.Http

    setup_all do
      prefix = OwnedDatabase.start()
      HooksTestSupport.tables()

      on_exit(fn ->
        HooksTestSupport.drop()
        OwnedDatabase.drop(prefix)
      end)

      :ok
    end

    setup do
      HooksTestSupport.clear()
      {handle, key} = HooksTestSupport.key()
      on_exit(fn -> RequestSeal.Custody.Local.release(handle) end)
      %{handle: handle, policy: HooksTestSupport.policy(key)}
    end

    test "real ash_hooks delivery records a Plug-verified HTTP round trip and inbound helper", %{
      handle: handle,
      policy: policy
    } do
      url = HooksTestSupport.start_receiver(policy, self())

      endpoint =
        Ash.create!(HooksEndpoint, %{url: url, secret_ref: "standard-key"}, authorize?: false)

      {:ok, event} = AshHooks.Event.new(type: :order_paid, payload: ~s({"order":1}))

      row =
        Ash.create!(
          HooksDelivery,
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

      assert :ok =
               AshHooks.Delivery.run(%{"endpoint_id" => endpoint.id, "event_uuid" => event.id},
                 deliveries: HooksDelivery,
                 endpoints: HooksEndpoint,
                 secret_resolver: fn "standard-key" -> {:ok, secret} end,
                 http: Http,
                 http_opts: [
                   request_seal: [spec: HooksTestSupport.spec(), signer: handle],
                   validate_destination: false
                 ],
                 ssrf_check: fn target -> target == url end
               )

      assert_receive {:hooks_received, {:ok, verification}, :ok, bytes, headers}, 5_000
      assert verification.signature.crypto == :valid
      assert bytes == event.payload
      assert Map.new(headers)["webhook-id"] == event.id
      persisted = Ash.get!(HooksDelivery, row.id, authorize?: false)
      assert persisted.status == :succeeded
      assert persisted.attempts == 1
      assert persisted.response_status == 204

      IO.puts(
        "DELIVERY: ash_hooks -> Bounded -> Bandit -> Plug.Verify + helper, 204, ledger succeeded"
      )
    end

    test "inbound helper rejects body, method, path, authority, headers and key mutations", %{
      handle: handle,
      policy: policy
    } do
      body = ~s({"order":1})
      url = "https://hooks.example.com/events"

      {:ok, message} =
        RequestSeal.Message.request(
          "POST",
          url,
          [{"content-type", "application/json"}, {"webhook-id", "event-1"}],
          body
        )

      {:ok, signed} = RequestSeal.sign(message, HooksTestSupport.spec(), handle)
      headers = Map.new(signed.fields, &{&1.name, &1.value})

      context = %{
        method: "POST",
        request_uri: url,
        headers: headers,
        signature: headers["signature"],
        tenant: nil
      }

      opts = [policy: fn "receiver-key" -> policy end, label: "sig"]
      assert :ok = RequestSeal.AshHooks.verify_signature(body, context, "receiver-key", opts)

      for {bytes, ctx, ref} <- [
            {body <> " ", context, "receiver-key"},
            {body, %{context | method: "GET"}, "receiver-key"},
            {body, %{context | request_uri: url <> "/other"}, "receiver-key"},
            {body, %{context | request_uri: "https://other.example.com/events"}, "receiver-key"},
            {body, %{context | headers: Map.put(headers, "content-type", "text/plain")},
             "receiver-key"},
            {body, %{context | headers: Map.put(headers, "webhook-id", "event-2")},
             "receiver-key"},
            {body, context, "unknown-key"}
          ] do
        assert {:error, :invalid_signature} =
                 RequestSeal.AshHooks.verify_signature(bytes, ctx, ref, opts)
      end

      assert {:error, :no_webhook_secret} =
               RequestSeal.AshHooks.verify_signature(body, context, "", opts)
    end

    test "adapter rejects insufficient coverage, digest conflicts, header collisions and expired deadlines",
         %{handle: handle, policy: policy} do
      url = HooksTestSupport.start_receiver(policy, self())
      headers = %{"content-type" => "application/json", "webhook-id" => "event-1"}

      opts = [
        request_seal: [spec: HooksTestSupport.spec(), signer: handle],
        validate_destination: false
      ]

      assert {:ok, %{status: 204}} = Http.request(:post, url, headers, "{}", opts)

      for unsafe <- [
            Map.put(headers, "Content-Type", "text/plain"),
            Map.put(headers, "host", "other"),
            Map.put(headers, "content-digest", "sha-256=:AAAA:"),
            Map.put(headers, "signature", "old=:AAAA:")
          ] do
        assert {:error, :request_seal_rejected} = Http.request(:post, url, unsafe, "{}", opts)
      end

      bad = put_in(opts[:request_seal][:spec][:components], ~s[("@method")])
      assert {:error, :request_seal_rejected} = Http.request(:post, url, headers, "{}", bad)

      assert {:error, :timeout} =
               Http.request(:post, url, headers, "{}", Keyword.put(opts, :timeout, 0))

      assert {:error, :unsafe_destination} =
               Http.request(
                 :post,
                 url,
                 headers,
                 "{}",
                 Keyword.delete(opts, :validate_destination)
               )
    end
  end
end
