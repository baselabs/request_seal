Code.require_file("support/http_signature_peer_helper.exs", __DIR__)

defmodule RequestSeal.DeliveryClassificationTest do
  use ExUnit.Case, async: false
  alias RequestSeal.HTTPSignaturePeer, as: Peer
  alias RequestSeal.Adapter.Error

  setup do
    handle = Peer.handle()
    on_exit(fn -> RequestSeal.Custody.release(handle) end)
    start_supervised!({Finch, name: __MODULE__.Pool})
    %{handle: handle}
  end

  test "signed requests classify actual HTTP statuses from the listener", %{handle: handle} do
    for client <- [:req, :finch], status <- [200, 503, 502, 504] do
      {origin, task} = Peer.start([%{status: status}], handle)
      result = send_request(client, origin, handle)
      assert {:ok, %{status: ^status}} = result
      assert classify(client, result) == if(status in [502, 504], do: :unknown, else: :answered)
      assert_receive {:wire_request, _, {:ok, _}}
      Peer.finish(task)
    end
  end

  test "a closed local port refuses before sending", %{handle: handle} do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    :ok = :gen_tcp.close(listener)

    for client <- [:req, :finch] do
      result = send_request(client, "http://127.0.0.1:#{port}", handle)
      assert {:error, %{reason: :econnrefused}} = result
      assert classify(client, result) == :refused
    end
  end

  test "an accepted signed request without a response has unknown delivery", %{handle: handle} do
    for client <- [:req, :finch] do
      {origin, task} = Peer.start([:hold], handle)
      result = send_request(client, origin, handle, receive_timeout: 50)
      assert {:error, %{reason: :timeout}} = result
      assert classify(client, result) == :unknown
      assert_receive {:wire_request, _, {:ok, _}}
      assert_receive {:holding, _}
      assert_receive {:peer_closed, {:error, :closed}}
      Peer.finish(task)
    end
  end

  test "own pre-send refusals and post-send verification failures remain distinct", c do
    released = Peer.handle()
    :ok = RequestSeal.Custody.release(released)

    for client <- [:req, :finch] do
      {origin, task} = Peer.start([%{}], c.handle)
      assert {:error, %Error{stage: :sign}} = result = send_request(client, origin, released)
      assert classify(client, result) == :refused
      assert_receive :no_connection
      Peer.finish(task)
    end

    assert {:error, %Error{stage: :attach}} = result = RequestSeal.Req.attach(:invalid, [])
    assert RequestSeal.Req.classify(result) == :refused

    for {client, adapter} <- [{RequestSeal.Req, :req}, {RequestSeal.Finch, :finch}] do
      assert client.classify({:error, Error.new(:response_rejected, adapter, :verify, 1)}) ==
               :unknown
    end
  end

  test "raw HTTP/2 peers refuse the particular stream with RST_STREAM or GOAWAY", c do
    start_supervised!(
      Supervisor.child_spec(
        {Finch, name: __MODULE__.H2Pool, pools: %{default: [protocols: [:http2]]}},
        id: :h2_pool
      )
    )

    for client <- [:req, :finch], frame <- [:rst_stream, :goaway] do
      {origin, task} = h2_peer(frame)
      result = send_request(client, origin, c.handle, [], __MODULE__.H2Pool)
      assert {:error, _} = result
      assert classify(client, result) == :refused
      assert_receive {:h2_stream, stream_id} when stream_id > 0
      send(task.pid, :stop)
      Task.await(task, 5_000)
    end
  end

  test "only source-proven transport and stream shapes refuse; every other term is unknown" do
    for {client, transport} <- [
          {RequestSeal.Req, Req.TransportError},
          {RequestSeal.Finch, Finch.TransportError},
          {RequestSeal.Finch, Mint.TransportError}
        ] do
      for reason <- [
            :econnrefused,
            :nxdomain,
            :ehostunreach,
            :enetunreach,
            :protocol_not_negotiated,
            {:bad_alpn_protocol, "other"}
          ] do
        assert client.classify({:error, struct!(transport, reason: reason)}) == :refused
      end

      for reason <- [
            :timeout,
            :connect_timeout,
            :closed,
            :econnreset,
            {:tls_alert, {:handshake_failure, ~c"alert"}}
          ] do
        assert client.classify({:error, struct!(transport, reason: reason)}) == :unknown
      end
    end

    for reason <- [
          :unprocessed,
          {:server_closed_request, :refused_stream},
          :disconnected,
          :connection_not_ready
        ] do
      result = {:error, %Req.HTTPError{protocol: :http2, reason: reason}}
      assert RequestSeal.Req.classify(result) == :refused
    end

    for type <- [Finch.HTTPError, Mint.HTTPError],
        reason <- [:unprocessed, {:server_closed_request, :refused_stream}] do
      result = {:error, struct!(type, module: Mint.HTTP2, reason: reason)}
      assert RequestSeal.Finch.classify(result) == :refused
      result = {:error, struct!(type, module: Mint.HTTP1, reason: reason)}
      assert RequestSeal.Finch.classify(result) == :unknown
    end

    for reason <- [:disconnected, :connection_not_ready] do
      assert RequestSeal.Finch.classify({:error, Finch.Error.exception(reason)}) == :refused

      for type <- [Finch.HTTPError, Mint.HTTPError] do
        result = {:error, struct!(type, module: Mint.HTTP2, reason: reason)}
        assert RequestSeal.Finch.classify(result) == :unknown
      end
    end

    for client <- [RequestSeal.Req, RequestSeal.Finch],
        term <- [
          nil,
          42,
          :ok,
          [],
          [1 | 2],
          self(),
          make_ref(),
          fn -> :ok end,
          {:ok, %{status: 200}},
          {:error, %{reason: :econnrefused}},
          {:error, Finch.Error.exception(:read_only)},
          {:error,
           %Mint.HTTPError{
             module: Mint.HTTP2,
             reason: {:server_closed_connection, :refused_stream, ""}
           }},
          {:error, %Req.HTTPError{protocol: :http1, reason: :unprocessed}},
          {:ok, %Req.Response{status: nil}},
          {:ok, %Finch.Response{status: "200"}}
        ] do
      assert client.classify(term) == :unknown
    end
  end

  defp classify(:req, result), do: RequestSeal.Req.classify(result)
  defp classify(:finch, result), do: RequestSeal.Finch.classify(result)

  defp send_request(client, origin, handle, opts \\ [], pool \\ __MODULE__.Pool) do
    url = origin <> "/foo?param=Value"
    headers = [{"accept", "text/plain"}]

    case client do
      :req ->
        request =
          Req.new(
            url: url,
            headers: headers,
            finch: [name: pool],
            retry: false,
            redirect: false,
            decode_body: false
          )

        with {:ok, request} <-
               RequestSeal.Req.attach(request,
                 sign: Peer.spec(),
                 signer: handle,
                 verify: :none
               ) do
          Req.request(request, opts)
        end

      :finch ->
        with {:ok, request} <-
               RequestSeal.Finch.sign(Finch.build(:get, url, headers), Peer.spec(), handle) do
          Finch.request(request, pool, opts)
        end
    end
  end

  defp h2_peer(frame) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    owner = self()

    task =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)

        try do
          {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)
          :ok = :gen_tcp.send(socket, <<0::24, 4, 0, 0::32>>)
          stream_id = request_stream(socket)
          send(owner, {:h2_stream, stream_id})

          payload =
            case frame do
              :rst_stream -> <<4::24, 3, 0, stream_id::32, 7::32>>
              :goaway -> <<8::24, 7, 0, 0::32, 0::32, 7::32>>
            end

          :ok = :gen_tcp.send(socket, payload)
          receive do: (:stop -> :ok)
        after
          :gen_tcp.close(socket)
          :gen_tcp.close(listener)
        end
      end)

    on_exit(fn ->
      monitor = Process.monitor(task.pid)
      Process.exit(task.pid, :kill)
      receive do: ({:DOWN, ^monitor, :process, _, _} -> :ok)
      :gen_tcp.close(listener)
    end)

    {"http://127.0.0.1:#{port}", task}
  end

  defp request_stream(socket) do
    {:ok, <<size::24, type, flags, _reserved::1, stream_id::31>>} =
      :gen_tcp.recv(socket, 9, 5_000)

    if size > 0, do: assert(match?({:ok, _}, :gen_tcp.recv(socket, size, 5_000)))

    cond do
      type == 1 and stream_id > 0 ->
        stream_id

      type == 4 and flags == 0 ->
        :ok = :gen_tcp.send(socket, <<0::24, 4, 1, 0::32>>)
        request_stream(socket)

      true ->
        request_stream(socket)
    end
  end
end
