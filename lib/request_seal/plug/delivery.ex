if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Delivery do
    @moduledoc false
    @behaviour Plug.Conn.Adapter
    @derive {Inspect, only: []}
    defstruct [:adapter, :payload, :failure, :transport, :metrics, :upgrade, :replay]

    # Plug binds adapter/payload before before_send, and forbids changing delivery state.
    # This request-local flag lets the bound transport dispatch an empty failure instead.
    # No process or global state is created. Successful operations delegate unchanged.
    def wrap({__MODULE__, %__MODULE__{}} = adapter), do: adapter

    def wrap({adapter, payload}) do
      failure = :atomics.new(1, signed: false)
      {__MODULE__, sync(%__MODULE__{adapter: adapter, failure: failure}, payload)}
    end

    def retain(adapter, bytes) do
      {__MODULE__, s} = wrap(adapter)

      replay = %{
        id: make_ref(),
        bytes: bytes,
        offset: 0,
        read?: false,
        digest: :crypto.hash_init(:sha256)
      }

      {__MODULE__, %{s | replay: replay}}
    end

    def retained?({__MODULE__, %__MODULE__{replay: %{id: id}}}, id) when is_reference(id),
      do: true

    def retained?(_, _), do: false

    def replayed?({__MODULE__, %{replay: %{read?: read?}}}), do: read?
    def replayed?(_), do: false

    # This measures bytes handed to readers, not transformations a reader makes later.
    def replay_matches?({__MODULE__, %{replay: r}}, bytes) when is_map(r) do
      r.offset == byte_size(r.bytes) and byte_size(bytes) == byte_size(r.bytes) and
        :crypto.hash_final(r.digest) == :crypto.hash(:sha256, bytes)
    end

    def replay_matches?(_, _), do: false

    def fail(%__MODULE__{failure: flag}, status), do: :atomics.put(flag, 1, status)
    defp failed?(s), do: :atomics.get(s.failure, 1) != 0
    defp sent({:ok, body, payload}, s), do: {:ok, body, sync(s, payload)}
    defp sent(result, _s), do: result

    # Servers may read transport/metrics/upgrade from their payload after the plug.
    # Mirror those fields without depending on a particular server module.
    defp sync(s, payload) do
      facts =
        if is_map(payload), do: Map.take(payload, [:transport, :metrics, :upgrade]), else: %{}

      struct(%{s | payload: payload}, facts)
    end

    @impl true
    def send_resp(s, status, headers, body) do
      if failed?(s),
        do:
          s.adapter.send_resp(s.payload, :atomics.get(s.failure, 1), clean(headers), "")
          |> sent(s),
        else: s.adapter.send_resp(s.payload, status, headers, body) |> sent(s)
    end

    @impl true
    def send_chunked(s, status, headers) do
      if failed?(s),
        do: send_resp(s, status, headers, ""),
        else: s.adapter.send_chunked(s.payload, status, headers) |> sent(s)
    end

    @impl true
    def send_file(s, status, headers, file, offset, length) do
      if failed?(s),
        do: send_resp(s, status, headers, ""),
        else: s.adapter.send_file(s.payload, status, headers, file, offset, length) |> sent(s)
    end

    @impl true
    def chunk(s, body) do
      if failed?(s) do
        {:error, :closed}
      else
        s.adapter.chunk(s.payload, body) |> sent(s)
      end
    end

    defp clean(headers),
      do:
        Enum.reject(headers, fn {n, _} ->
          String.downcase(n) in [
            "signature",
            "signature-input",
            "content-length",
            "content-digest",
            "repr-digest",
            "content-encoding",
            "transfer-encoding",
            "trailer"
          ]
        end)

    @impl true
    def read_req_body(%__MODULE__{replay: r} = s, opts) when is_map(r) do
      requested = Keyword.get(opts, :length, 8_000_000)

      if is_integer(requested) and requested >= 0 do
        remaining = byte_size(r.bytes) - r.offset
        length = min(requested, remaining)
        bytes = binary_part(r.bytes, r.offset, length)

        r = %{
          r
          | offset: r.offset + length,
            read?: true,
            digest: :crypto.hash_update(r.digest, bytes)
        }

        {if(r.offset < byte_size(r.bytes), do: :more, else: :ok), bytes, %{s | replay: r}}
      else
        {:error, RequestSeal.Adapter.Error.new(:invalid_options, :plug, :capture, 0)}
      end
    end

    def read_req_body(s, opts) do
      case s.adapter.read_req_body(s.payload, opts) do
        {tag, body, payload} when tag in [:ok, :more] -> {tag, body, sync(s, payload)}
        result -> result
      end
    end

    @impl true
    def get_peer_data(s), do: s.adapter.get_peer_data(s.payload)
    @impl true
    def get_http_protocol(s), do: s.adapter.get_http_protocol(s.payload)
    @impl true
    def get_sock_data(s), do: optional(s, :get_sock_data, [])
    @impl true
    def get_ssl_data(s), do: optional(s, :get_ssl_data, [])
    @impl true
    def push(s, path, headers), do: optional(s, :push, [path, headers])
    @impl true
    def inform(s, status, headers) do
      case s.adapter.inform(s.payload, status, headers) do
        {:ok, payload} -> {:ok, sync(s, payload)}
        result -> result
      end
    end

    @impl true
    def upgrade(s, protocol, opts) do
      case s.adapter.upgrade(s.payload, protocol, opts) do
        {:ok, payload} -> {:ok, sync(s, payload)}
        result -> result
      end
    end

    defp optional(s, function, args) do
      if function_exported?(s.adapter, function, length(args) + 1),
        do: apply(s.adapter, function, [s.payload | args]),
        else: {:error, :not_supported}
    end
  end
end
