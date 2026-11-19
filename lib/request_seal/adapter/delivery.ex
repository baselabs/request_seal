defmodule RequestSeal.Adapter.Delivery do
  @moduledoc false

  # Req 0.7.5 Req.Finch.normalize_error/1 preserves reasons and HTTP versions.
  # Finch 0.24.0 Error.wrap/1 preserves Mint reasons in its own wrappers.
  def classify({:ok, %{__struct__: response, status: status}}, adapter)
      when is_integer(status) do
    expected = if adapter == :req, do: Req.Response, else: Finch.Response

    if response == expected and status not in [502, 504], do: :answered, else: :unknown
  end

  def classify({:error, %RequestSeal.Adapter.Error{adapter: adapter, stage: stage}}, adapter)
      when stage in [:attach, :sign],
      do: :refused

  def classify({:error, %{__struct__: type, reason: reason} = error}, adapter) do
    cond do
      transport?(type, adapter) -> transport(reason)
      http2?(error, adapter) -> http2(reason, adapter)
      adapter == :finch and type == Finch.Error -> pool(reason)
      true -> :unknown
    end
  end

  def classify(_, _), do: :unknown

  defp transport?(type, :req), do: type == Req.TransportError
  defp transport?(type, :finch), do: type in [Finch.TransportError, Mint.TransportError]

  defp http2?(%{__struct__: Req.HTTPError, protocol: :http2}, :req), do: true

  defp http2?(%{__struct__: type, module: Mint.HTTP2}, :finch),
    do: type in [Finch.HTTPError, Mint.HTTPError]

  defp http2?(_, _), do: false

  # Mint 1.11.0 Core.Transport.TCP.connect/3, lines 33-45: connect failures.
  # No generic :timeout, :closed or TLS alert proves the phase of an exchange.
  defp transport(reason)
       when reason in [:econnrefused, :nxdomain, :ehostunreach, :enetunreach],
       do: :refused

  # Mint 1.11.0 HTTP2.negotiate/4, lines 1369-1377, precedes any HTTP request.
  defp transport(:protocol_not_negotiated), do: :refused
  defp transport({:bad_alpn_protocol, protocol}) when is_binary(protocol), do: :refused
  defp transport(_), do: :unknown

  # Mint 1.11.0 HTTP2.handle_rst_stream/3, line 2426, reports the stream's code.
  # handle_goaway/3, lines 2844-2853, emits :unprocessed only above last_stream_id.
  # A connection-level GOAWAY code alone does not identify an unprocessed stream.
  defp http2({:server_closed_request, :refused_stream}, _), do: :refused
  defp http2(:unprocessed, _), do: :refused
  defp http2(reason, :req), do: pool(reason)
  defp http2(_, _), do: :unknown

  # Finch 0.24.0 HTTP2.Pool.disconnected/3:342 and connecting/3:397 return
  # immediately, before send_request/7. Req normalizes these to HTTP/2 errors.
  defp pool(reason) when reason in [:disconnected, :connection_not_ready], do: :refused
  defp pool(_), do: :unknown
end
