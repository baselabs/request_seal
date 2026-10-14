if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Capture do
    @moduledoc """
    Capture a bounded request before destructive parsing or origin/IP rewriting.

    Original ingress facts remain separate from the selected origin. Transport
    facts stay declared and describe ingress, never the forwarded origin.

    Headers retain Plug's occurrence order and protocol provenance. Plug has
    already normalized header names; HTTP/2 servers can join cookie crumbs.
    Request trailers are `:unavailable`; policies requiring them reject.
    The target is origin-form reconstructed from `request_path` and `query_string`.
    It supports path derivation, not exact target evidence. Verify rejects required
    or covered `@request-target`, `@target-uri`, and `@query` with
    `:unsupported_component`; SignResponse also rejects those request components.
    See `RequestSeal.Plug` for the tested per-transport rule.
    OPTIONS `*` is retained.

    After a successful capture, the Delivery adapter replays retained bytes to
    all readers, including multipart. Custom wrapper readers must return
    replayed bytes unchanged; their subsequent transformations cannot be
    observed by the adapter. Retention remains caller-owned.
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

    @doc """
    Validates capture options once, at plug initialization.

    ## Parameters

      * `opts` - keyword list of the options below. All are required; unknown or
        duplicate options reject.

    ## Options

      * `:origin` - how the request origin (scheme and authority) is selected.
        Every selected origin lowercases scheme and host and omits the default
        port (80 for HTTP, 443 for HTTPS).
        * `:connection` - the connection's scheme, host, and port.
        * `{:declared, scheme, authority}` - a caller-trusted scheme and
          authority, validated and normalized at init.
        * `{:forwarded, %{trusted_peers: cidrs, field: field}}` - `cidrs` is a
          list of 1..1,024 `{ip_tuple, prefix}` ranges; `field` is `:forwarded`
          or `:x_forwarded`. The last forwarded element is used only after the
          actual socket peer is found in a trusted range.
      * `:max_body_bytes` - nonnegative integer bound on the captured body.
      * `:read_timeout` - 1..300,000 milliseconds for the single body read.

    ## Returns

      * keyword list - the validated options, with a declared origin normalized.

    Raises `RequestSeal.Adapter.Error` with reason `:invalid_options` and stage
    `:capture` on any invalid option.

    ## Examples

        iex> RequestSeal.Plug.Capture.init(
        ...>   origin: {:declared, "HTTPS", "Docs.Example.com:443"},
        ...>   max_body_bytes: 1_024,
        ...>   read_timeout: 5_000
        ...> )
        [origin: {:declared, "https", "docs.example.com"}, max_body_bytes: 1024, read_timeout: 5000]
        iex> try do
        ...>   RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: -1, read_timeout: 5_000)
        ...> rescue
        ...>   error in RequestSeal.Adapter.Error -> {error.reason, error.stage}
        ...> end
        {:invalid_options, :capture}
    """
    @impl Plug
    def init(opts) do
      case Signing.protect(:plug, :attach, 0, fn ->
             Signing.options(opts, [:origin, :max_body_bytes, :read_timeout])

             Signing.ensure(
               is_integer(opts[:max_body_bytes]) and opts[:max_body_bytes] >= 0 and
                 is_integer(opts[:read_timeout]) and opts[:read_timeout] in 1..300_000,
               :invalid_options
             )

             Keyword.put(opts, :origin, Origin.validate!(opts[:origin]))
           end) do
        {:error, error} -> raise %{error | stage: :capture}
        opts -> opts
      end
    end

    @doc """
    Reads the request body once and retains the request as an immutable message.

    One `Plug.Conn.read_body/2` call with `length: max_body_bytes` captures the
    bytes. On success the request-local Delivery adapter replaces the
    connection adapter so later readers receive the same bytes, and the capture
    is stored in private state for `RequestSeal.Plug.capture/1`.

    ## Parameters

      * `conn` - a `Plug.Conn` whose body has not been read or parsed.
      * `opts` - options returned by `init/1`.

    ## Returns

      * `Plug.Conn` - on success, the connection with the capture stored.
      * `Plug.Conn` - on rejection, halted with an empty body and status 413
        for `:limit` or 400 for every other reason. Only HTTP/1.0 and HTTP/1.1
        rejections carry `connection: close`; HTTP/2 rejections omit connection
        fields. Private state's `:error` holds a
        `%RequestSeal.Adapter.Error{stage: :capture, attempt: 0}` with reason:
        `:parser_order` (`body_params` already fetched; checked before any read),
        `:invalid_request` (CONNECT, an empty host, an existing capture, a
        malformed or oversized forwarded field, an invalid forwarded scheme or
        authority, a value `RequestSeal.Message.new/1` rejects, or an unexpected
        exception), `:untrusted_proxy` (the socket peer is outside
        `trusted_peers`), `:limit` (the read returned `:more` or more than
        `max_body_bytes`; no second read occurs), and `:body_unavailable` (the
        server returned a read error). Meanings: `RequestSeal.Adapter.Error`.

    ## Examples

        iex> opts =
        ...>   RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: 4, read_timeout: 5_000)
        iex> conn =
        ...>   RequestSeal.Plug.Capture.call(
        ...>     Plug.Test.conn(:post, "https://telemetry.example.com/ingest", "12345"),
        ...>     opts
        ...>   )
        iex> {conn.status, conn.halted, conn.private.request_seal.error.reason}
        {413, true, :limit}
        iex> Plug.Conn.get_resp_header(conn, "connection")
        ["close"]

    `RequestSeal.Plug.capture/1` shows a successful capture.
    """
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

    @doc """
    Records that the RequestSeal reader ran, then reads the body through Plug.

    Configure it as a parser reader with
    `body_reader: {RequestSeal.Plug.Capture, :read_body, []}`. After a capture,
    reads come from the retained replay: each returns at most `:length` bytes
    (default 8,000,000), `:more` until the replay is drained, then `:ok` with
    empty bytes. Without a capture the call is a plain `Plug.Conn.read_body/2`.
    `RequestSeal.Plug.Verify` uses the recorded invocation to require a fully
    drained, matching replay.

    ## Parameters

      * `conn` - a `Plug.Conn`.
      * `opts` - `Plug.Conn.read_body/2` options; the replay honors `:length`.

    ## Returns

      * `{:ok, binary, conn}` - the last bytes of the body, or empty bytes once
        drained.
      * `{:more, binary, conn}` - a chunk; more bytes remain.
      * `{:error, %RequestSeal.Adapter.Error{reason: :invalid_options}}` - a
        negative or non-integer replay `:length`; the replay does not advance.
      * `{:error, term}` - any other error from the underlying Plug adapter when
        no capture is installed.

    ## Examples

        iex> opts =
        ...>   RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: 1_024, read_timeout: 5_000)
        iex> conn =
        ...>   RequestSeal.Plug.Capture.call(
        ...>     Plug.Test.conn(:post, "https://docs.example.com/upload", "abcdef"),
        ...>     opts
        ...>   )
        iex> {:more, first, conn} = RequestSeal.Plug.Capture.read_body(conn, length: 4)
        iex> {:ok, rest, conn} = RequestSeal.Plug.Capture.read_body(conn, length: 4)
        iex> {first, rest}
        {"abcd", "ef"}
        iex> {:ok, "", conn} = RequestSeal.Plug.Capture.read_body(conn, [])
        iex> {:error, error} = RequestSeal.Plug.Capture.read_body(conn, length: -1)
        iex> error.reason
        :invalid_options
    """
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
