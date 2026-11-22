defmodule RequestSeal.Adapter.Delivery do
  @moduledoc false

  # Req 0.7.5 lib/req/finch.ex normalize_error/1:349-376 preserves reasons and
  # HTTP versions, but :370-371 drops Finch.TransportError.phase (also in 0.7.4).
  # Finch 0.25.0 lib/finch/error.ex Error.wrap/1:36-40 preserves its own errors
  # (including phase) and wraps Mint reasons without adding phase evidence.
  def classify(result, adapter, bodyless? \\ true)

  def classify({:ok, %{__struct__: response, status: status}}, adapter, _bodyless?)
      when is_integer(status) do
    expected = if adapter == :req, do: Req.Response, else: Finch.Response

    if response == expected and status not in [502, 504], do: :answered, else: :unknown
  end

  def classify(
        {:error, %RequestSeal.Adapter.Error{adapter: adapter, stage: :attach, attempt: 0}},
        adapter,
        _bodyless?
      ),
      do: :refused

  def classify(
        {:error, %RequestSeal.Adapter.Error{adapter: adapter, stage: :sign, attempt: 1}},
        adapter,
        _bodyless?
      ),
      do: :refused

  # Finch 0.25.0 lib/finch/http1/conn.ex Conn.connect/2:53-68 sets :connect
  # only after Mint.HTTP.connect/4 fails, before Pool.request/6 calls
  # Conn.request/8 (lib/finch/http1/pool.ex:63-65). No request byte was sent.
  def classify(
        {:error, %{__struct__: Finch.TransportError, reason: _, phase: :connect}},
        :finch,
        _bodyless?
      ),
      do: :refused

  def classify({:error, %{__struct__: type, reason: reason} = error}, adapter, bodyless?) do
    cond do
      transport?(type, adapter) -> transport(reason)
      bodyless? and http2?(error, adapter) -> http2(reason, adapter)
      bodyless? and adapter == :finch and type == Finch.Error -> pool(reason)
      true -> :unknown
    end
  end

  def classify(_, _, _), do: :unknown

  defp transport?(type, :req), do: type == Req.TransportError
  defp transport?(type, :finch), do: type in [Finch.TransportError, Mint.TransportError]

  defp http2?(%{__struct__: Req.HTTPError, protocol: :http2}, :req), do: true

  defp http2?(%{__struct__: type, module: Mint.HTTP2}, :finch),
    do: type in [Finch.HTTPError, Mint.HTTPError]

  defp http2?(_, _), do: false

  # Mint 1.11.0 lib/mint/core/transport/tcp.ex TCP.connect/3:15-45 resolves
  # names before any request byte. TCP.send/2:58-60 and recv/3:66-68 reuse the
  # same reason wrapper on an open socket, so socket reasons alone prove no
  # phase. Finch's :connect field above supplies the missing HTTP/1 evidence;
  # raw Mint and Req transport errors do not carry it.
  defp transport(:nxdomain), do: :refused

  # Mint 1.11.0 lib/mint/http2.ex HTTP2.negotiate/4:1369-1377 precedes requests.
  defp transport(:protocol_not_negotiated), do: :refused
  defp transport({:bad_alpn_protocol, protocol}) when is_binary(protocol), do: :refused
  defp transport(_), do: :unknown

  # Mint 1.11.0 lib/mint/http2.ex HTTP2.handle_rst_stream/3:2426 reports the
  # stream's code. handle_goaway/3:2844-2853 emits :unprocessed only above
  # last_stream_id. Finch 0.25.0 lib/finch/http2/pool.ex handle_response/3:866-885
  # forwards the wrapped error even while the stream is still uploading.
  # A connection-level GOAWAY code alone does not identify an unprocessed stream.
  defp http2({:server_closed_request, :refused_stream}, _), do: :refused
  defp http2(:unprocessed, _), do: :refused
  defp http2(reason, :req), do: pool(reason)
  defp http2(_, _), do: :unknown

  # Finch 0.25.0 lib/finch/http2/pool.ex HTTP2.Pool.disconnected/3:347-348 and
  # connecting/3:407-408 return before send_request/6:736. Req normalizes these
  # to HTTP/2 errors (Req 0.7.5 lib/req/finch.ex normalize_error/1:361-362).
  # For a non-nil body, any HTTP/2 refusal may follow a :read_only rerun of a
  # partially sent request (same pool file, connected_read_only/3:579-592;
  # lib/finch.ex Finch.__stream__/6:853-860). Only nil starts RequestStream in
  # :done (lib/finch/http2/request_stream.ex RequestStream.new/1:6-21).
  defp pool(reason) when reason in [:disconnected, :connection_not_ready], do: :refused
  defp pool(_), do: :unknown
end
