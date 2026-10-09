if Code.ensure_loaded?(AshHooks.Provider) do
  defmodule RequestSeal.HooksEndpoint do
    @moduledoc false
    use Ash.Resource,
      domain: RequestSeal.HooksDomain,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshHooks.Endpoint]

    postgres do
      table("requestseal_hooks_endpoints")
      repo(RequestSeal.OwnedRepo)
    end

    actions do
      defaults([:read, :create, :update])
      default_accept(:*)
    end
  end

  defmodule RequestSeal.HooksDelivery do
    @moduledoc false
    use Ash.Resource,
      domain: RequestSeal.HooksDomain,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshHooks.OutboundDelivery]

    postgres do
      table("requestseal_hooks_deliveries")
      repo(RequestSeal.OwnedRepo)
    end

    actions do
      defaults([:read])
    end
  end

  defmodule RequestSeal.HooksDomain do
    @moduledoc false
    use Ash.Domain, otp_app: nil, validate_config_inclusion?: false

    resources do
      resource(RequestSeal.HooksEndpoint)
      resource(RequestSeal.HooksDelivery)
    end
  end

  defmodule RequestSeal.HooksReceiver do
    @moduledoc false
    @behaviour Plug
    def init(opts), do: opts

    def call(conn, opts) do
      conn =
        RequestSeal.Plug.Capture.call(
          conn,
          RequestSeal.Plug.Capture.init(
            origin: :connection,
            max_body_bytes: 100_000,
            read_timeout: 5_000
          )
        )

      {:ok, capture} = RequestSeal.Plug.capture(conn)
      # The real ash_hooks reader receives exactly the bytes replayed by Capture.
      {:ok, bytes, conn} = AshHooks.BodyReader.read_body(conn, [])

      context = %{
        headers: Map.new(conn.req_headers),
        method: conn.method,
        request_uri:
          "http://#{capture.message.authority}#{RequestSeal.Plug.Target.reconstruct(conn)}",
        signature: Map.new(conn.req_headers)["signature"],
        tenant: nil
      }

      result =
        RequestSeal.AshHooks.verify_signature(bytes, context, "receiver-key",
          policy: fn nil, "receiver-key" -> opts[:policy] end,
          label: "sig"
        )

      # This reference receiver owns the complete received target. Generic Plug
      # verification deliberately rejects target-dependent components.
      {:ok, message} =
        RequestSeal.Message.request(conn.method, context.request_uri, conn.req_headers, bytes)

      verification = RequestSeal.verify(message, opts[:policy], label: "sig")
      send(opts[:owner], {:hooks_received, verification, result, bytes, conn.req_headers})

      status = if match?({:ok, _}, verification) and result == :ok, do: 204, else: 401
      Plug.Conn.send_resp(conn, status, "")
    end
  end

  defmodule RequestSeal.HooksTestSupport do
    @moduledoc false
    alias RequestSeal.OwnedRepo, as: Repo

    def tables do
      Repo.query!("""
      CREATE TABLE requestseal_hooks_endpoints (
        id uuid PRIMARY KEY, url text NOT NULL, status text NOT NULL DEFAULT 'enabled',
        secret_ref text NOT NULL, previous_secret_ref text, legacy_secret_ref text, legacy_previous_secret_ref text)
      """)

      Repo.query!("""
      CREATE TABLE requestseal_hooks_deliveries (
        id uuid PRIMARY KEY, event_uuid text NOT NULL, event_type text NOT NULL, payload bytea NOT NULL,
        endpoint_id uuid NOT NULL, subscription_id uuid, signing_mode text, status text NOT NULL DEFAULT 'pending',
        attempts bigint NOT NULL DEFAULT 0, response_status bigint, response_snippet text, last_error text,
        next_attempt_at timestamptz, dispatch_source text NOT NULL DEFAULT 'v1:direct:unbound',
        dispatch_route text NOT NULL DEFAULT 'v1:route:unbound', attempt_token uuid,
        send_lease_expires_at timestamptz, enqueue_token uuid, enqueue_lease_expires_at timestamptz, endpoint_snapshot jsonb,
        UNIQUE (endpoint_id, event_uuid))
      """)
    end

    def clear do
      Repo.query!("DELETE FROM requestseal_hooks_deliveries")
      Repo.query!("DELETE FROM requestseal_hooks_endpoints")
    end

    def drop do
      {:ok, conn} =
        Postgrex.start_link(
          Ecto.Repo.Supervisor.parse_url(System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"))
        )

      try do
        Postgrex.query!(
          conn,
          "DROP TABLE requestseal_hooks_deliveries, requestseal_hooks_endpoints",
          []
        )
      after
        GenServer.stop(conn)
      end
    end

    def start_receiver(policy, owner) do
      server =
        ExUnit.Callbacks.start_supervised!(
          {Bandit,
           plug: {RequestSeal.HooksReceiver, [policy: policy, owner: owner]},
           ip: {127, 0, 0, 1},
           port: 0,
           startup_log: false}
        )

      {:ok, {_, port}} = ThousandIsland.listener_info(server)
      "http://localhost:#{port}/events"
    end

    # Relay actual TCP bytes, changing only one query value before the receiver.
    def query_relay(receiver) do
      target = URI.parse(receiver)

      {:ok, listener} =
        :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

      {:ok, {_, port}} = :inet.sockname(listener)
      ExUnit.Callbacks.on_exit(fn -> :gen_tcp.close(listener) end)

      task =
        Task.async(fn ->
          {:ok, incoming} = :gen_tcp.accept(listener, 5_000)

          {:ok, outgoing} =
            :gen_tcp.connect({127, 0, 0, 1}, target.port, [:binary, active: false], 5_000)

          try do
            request = read_request(incoming, "")

            :ok =
              :gen_tcp.send(
                outgoing,
                String.replace(request, "?account=one HTTP/1.1", "?account=two HTTP/1.1")
              )

            relay_response(outgoing, incoming)
          after
            :gen_tcp.close(incoming)
            :gen_tcp.close(outgoing)
            :gen_tcp.close(listener)
          end
        end)

      {"http://localhost:#{port}/events?account=one", task}
    end

    defp read_request(socket, bytes) do
      case String.split(bytes, "\r\n\r\n", parts: 2) do
        [head, body] ->
          [_, length] = Regex.run(~r/content-length: (\d+)/i, head)

          if byte_size(body) >= String.to_integer(length) do
            bytes
          else
            {:ok, chunk} = :gen_tcp.recv(socket, 0, 5_000)
            read_request(socket, bytes <> chunk)
          end

        _ ->
          {:ok, chunk} = :gen_tcp.recv(socket, 0, 5_000)
          read_request(socket, bytes <> chunk)
      end
    end

    defp relay_response(source, destination) do
      case :gen_tcp.recv(source, 0, 5_000) do
        {:ok, chunk} ->
          :ok = :gen_tcp.send(destination, chunk)
          relay_response(source, destination)

        {:error, :closed} ->
          :ok
      end
    end

    def key do
      {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
      {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      {:ok, key} = RequestSeal.Custody.public_key(handle)
      {handle, key}
    end

    def components,
      do: ~s[("@method" "@authority" "@path" "content-digest" "content-type" "webhook-id")]

    def spec,
      do: %{
        label: "sig",
        algorithm: "ed25519",
        components: components(),
        expires_in: 60,
        keyid: "receiver-key",
        digest: ["sha-256"]
      }

    def policy(key) do
      {:ok, policy} =
        RequestSeal.Policy.new(%{
          algorithms: ["ed25519"],
          components: components(),
          key_resolver: fn
            %{keyid: "receiver-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
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

      policy
    end
  end
end
