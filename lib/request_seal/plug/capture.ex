if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Capture do
    @moduledoc """
    Capture a bounded request before destructive parsing or origin/IP rewriting.

    All options are required: `:origin` is `:connection`,
    `{:declared, scheme, authority}`, or `{:forwarded, %{trusted_peers: CIDRs,
    field: :forwarded | :x_forwarded}}`; `:max_body_bytes` is nonnegative;
    `:read_timeout` is 1..300,000 milliseconds. A CIDR is `{ip_tuple, prefix}`.
    Forwarded reconstruction uses the last element only after checking the actual
    connection peer against the explicit ranges; connection mode ignores it.
    Original ingress facts remain separate. Transport facts stay declared and
    describe ingress, never the forwarded origin.

    Headers retain Plug's occurrence order and protocol provenance. Plug has
    already normalized header names; HTTP/2 servers can join cookie crumbs.
    Request trailers are `:unavailable`; policies requiring them reject.
    The target is origin-form reconstructed from `request_path` and `query_string`.
    It supports path derivation, not exact target evidence. Verify rejects required
    or covered `@request-target`, `@target-uri`, and `@query` with
    `:unsupported_component`; SignResponse also rejects those request components.
    See `RequestSeal.Plug` for the tested per-transport rule.
    OPTIONS `*` is retained.
    CONNECT and an empty host reject rather than invent an origin.

    One `Plug.Conn.read_body/2` call captures bytes. `:more` or a returned body
    exceeding the bound halts with 413, without a second read. Other capture
    failures halt with 400 and an empty body. Failure is stored as a bounded
    `RequestSeal.Adapter.Error`; invalid options raise that bounded error at init.
    Parsed `body_params` reject with `:parser_order` before any read or resolver.
    The Delivery adapter replays retained bytes to all readers, including
    multipart; `read_body/2` records invocation and delegates to Plug. Reads honor `:length` and return
    `:more` until drained, then empty bytes. Negative or non-integer replay
    `:length` returns a bounded `:invalid_options` adapter error without advancing
    the replay. Custom wrapper readers must return
    replayed bytes unchanged; their subsequent transformations cannot be observed
    by the adapter. Retention remains caller-owned. Only HTTP/1.0 and HTTP/1.1
    rejects carry `connection: close`; HTTP/2 rejects omit connection fields.
    """
    @behaviour Plug
    alias RequestSeal.{Body, FieldOccurrence, Message, TransportFacts}
    alias RequestSeal.Adapter.{Error, Signing}
    alias RequestSeal.Plug.{Delivery, Origin, State, Target}
    @derive {Inspect, only: []}
    defstruct [:message, :ingress, :origin]

    @type t :: %__MODULE__{
            message: Message.t(),
            ingress: %{
              scheme: atom(),
              host: binary(),
              port: non_neg_integer(),
              remote_ip: :inet.ip_address(),
              protocol: atom()
            },
            origin: %{
              scheme: binary(),
              authority: binary(),
              source: :connection | :declared | :forwarded
            }
          }

    @impl Plug
    def init(opts) do
      case Signing.protect(:plug, :attach, 0, fn ->
             Signing.options(opts, [:origin, :max_body_bytes, :read_timeout])

             Signing.ensure(
               is_integer(opts[:max_body_bytes]) and opts[:max_body_bytes] >= 0 and
                 is_integer(opts[:read_timeout]) and opts[:read_timeout] in 1..300_000,
               :invalid_options
             )

             Origin.validate!(opts[:origin])
             opts
           end) do
        {:error, error} -> raise %{error | stage: :capture}
        opts -> opts
      end
    end

    @impl Plug
    def call(conn, opts) do
      case prepare(conn, opts) do
        {:ok, ingress, origin} ->
          max_body_bytes = opts[:max_body_bytes]

          result =
            Signing.protect(:plug, :capture, 0, fn ->
              Plug.Conn.read_body(conn, length: max_body_bytes, read_timeout: opts[:read_timeout])
            end)

          case result do
            {:ok, bytes, read_conn} when byte_size(bytes) <= max_body_bytes ->
              finish(read_conn, bytes, opts, ingress, origin)

            {tag, _, read_conn} when tag in [:more, :ok] ->
              reject(read_conn, Error.new(:limit, :plug, :capture, 0))

            {:error, %Error{} = error} ->
              reject(conn, error)

            {:error, _} ->
              reject(conn, Error.new(:body_unavailable, :plug, :capture, 0))
          end

        {:error, error} ->
          reject(conn, error)
      end
    end

    defp prepare(conn, opts) do
      Signing.protect(:plug, :capture, 0, fn ->
        Signing.ensure(match?(%Plug.Conn.Unfetched{}, conn.body_params), :parser_order)

        Signing.ensure(
          conn.method != "CONNECT" and is_binary(conn.host) and conn.host != "",
          :invalid_request
        )

        Signing.ensure(State.get(conn).capture == nil, :invalid_request)
        protocol = Plug.Conn.get_http_protocol(conn)

        ingress =
          Map.take(conn, [:scheme, :host, :port, :remote_ip]) |> Map.put(:protocol, protocol)

        origin = Origin.select!(conn, opts[:origin])
        {:ok, ingress, origin}
      end)
    end

    defp finish(conn, bytes, opts, ingress, origin) do
      result =
        Signing.protect(:plug, :capture, 0, fn ->
          target = Target.reconstruct(conn)

          protocol = protocol(ingress.protocol)

          fields =
            Enum.map(conn.req_headers, fn {n, v} ->
              %FieldOccurrence{
                name: n,
                value: v,
                section: :headers,
                provenance: provenance(protocol)
              }
            end)

          case Message.new(%{
                 kind: :request,
                 method: conn.method,
                 raw_target: target,
                 target_form:
                   if(conn.method == "OPTIONS" and target == "*", do: :asterisk, else: :origin),
                 scheme: origin.scheme,
                 authority: origin.authority,
                 fields: fields,
                 trailers: :unavailable,
                 body: %Body{state: :retained, bytes: bytes, max_bytes: opts[:max_body_bytes]},
                 transport: %TransportFacts{
                   http_version: protocol,
                   tls: if(ingress.scheme == :https, do: :tls, else: :plain)
                 }
               }) do
            {:ok, message} ->
              {:ok, %__MODULE__{message: message, ingress: ingress, origin: origin}}

            {:error, source} ->
              Signing.fail(:invalid_request, source)
          end
        end)

      case result do
        {:ok, capture} ->
          conn = %{conn | adapter: Delivery.retain(conn.adapter, bytes)}
          {Delivery, delivery} = conn.adapter
          State.put(conn, %{State.get(conn) | capture: capture, replay_id: delivery.replay.id})

        {:error, error} ->
          reject(conn, error)
      end
    end

    defp reject(conn, error) do
      conn =
        if Plug.Conn.get_http_protocol(conn) in [:"HTTP/1.0", :"HTTP/1.1"],
          do: Plug.Conn.put_resp_header(conn, "connection", "close"),
          else: conn

      conn
      |> State.error(error)
      |> Plug.Conn.send_resp(if(error.reason == :limit, do: 413, else: 400), "")
      |> Plug.Conn.halt()
    end

    @doc "Record reader invocation and delegate to Plug; replay length-bounded bytes unchanged."
    @spec read_body(Plug.Conn.t(), keyword()) ::
            {:ok | :more, binary(), Plug.Conn.t()} | {:error, term()}
    def read_body(conn, opts) do
      state = State.get(conn)
      conn = if state.capture, do: State.put(conn, %{state | reader_called?: true}), else: conn
      Plug.Conn.read_body(conn, opts)
    end

    defp protocol(:"HTTP/1.0"), do: :http1_0
    defp protocol(:"HTTP/1.1"), do: :http1_1
    defp protocol(:"HTTP/2"), do: :http2
    defp protocol(:"HTTP/3"), do: :http3
    defp protocol(_), do: :unknown
    defp provenance(:http2), do: :http2
    defp provenance(:http3), do: :http3
    defp provenance(p) when p in [:http1_0, :http1_1], do: :http1
    defp provenance(_), do: :caller
  end
end
