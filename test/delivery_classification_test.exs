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
      {result, request} = send_request(client, origin, handle)
      assert {:ok, %{status: ^status}} = result

      assert classify(client, result, request) ==
               if(status in [502, 504], do: :unknown, else: :answered)

      assert_receive {:wire_request, _, {:ok, _}}
      Peer.finish(task)
    end
  end

  test "a closed local port is unknown because open connections report the same reason",
       %{handle: handle} do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    :ok = :gen_tcp.close(listener)

    for client <- [:req, :finch] do
      {result, request} = send_request(client, "http://127.0.0.1:#{port}", handle)
      assert {:error, %{reason: :econnrefused}} = result
      assert classify(client, result, request) == :unknown
    end
  end

  # RFC 6761 Section 6.4: names under .invalid never resolve.
  test "a name that cannot resolve refuses before any connection", %{handle: handle} do
    for client <- [:req, :finch], body <- [nil, "", Peer.body()] do
      {result, request} =
        send_request(client, "http://request-seal.invalid", handle, [], __MODULE__.Pool, body)

      assert {:error, %{reason: :nxdomain}} = result
      assert classify(client, result, request) == :refused
    end
  end

  test "a POST answered with a refused cross-origin redirect has unknown delivery", c do
    {destination, destination_task} = Peer.start([%{}], c.handle)

    {origin, task} =
      Peer.start(
        [%{status: 303, headers: [{"location", destination <> "/foo?param=Value"}]}],
        c.handle
      )

    assert {:ok, request} =
             req_request(origin, c.handle, method: :post, body: Peer.body(), redirect: true)

    assert {:error, %Error{reason: :cross_origin_redirect, stage: :sign, attempt: 2}} =
             result = Req.request(request)

    assert RequestSeal.Req.classify(result) == :unknown
    assert_receive {:wire_request, %{method: "POST", body: %{bytes: body}}, {:ok, _}}
    assert body == Peer.body()
    assert_receive :no_connection, 1_500
    Peer.finish(task)
    Peer.finish(destination_task)
  end

  test "name resolution failure after an allowed redirect keeps earlier delivery unknown", c do
    destination = "http://request-seal.invalid"

    {origin, task} =
      Peer.start(
        [%{status: 303, headers: [{"location", destination <> "/foo?param=Value"}]}],
        c.handle
      )

    assert {:ok, request} =
             req_request(
               origin,
               c.handle,
               [method: :post, body: Peer.body(), redirect: true],
               redirect: {:allow, [destination]}
             )

    assert {:error, %Error{reason: :transport_failed, stage: :transport, attempt: 2}} =
             result = Req.request(observe_errors(request))

    assert {:error, %Error{source: nil, retryable: false}} = result
    assert_receive {:attempt_error, 2, %Req.TransportError{reason: :nxdomain}}
    assert_receive {:wire_request, %{method: "POST"}, {:ok, _}}
    assert RequestSeal.Req.classify(result) == :unknown
    Peer.finish(task)
  end

  test "a signing refusal after a 503 retry keeps earlier delivery unknown", c do
    {origin, task} = Peer.start([%{status: 503}], c.handle)

    retry = fn
      _, %Req.Response{status: 503} ->
        :ok = RequestSeal.Custody.release(c.handle)
        true

      _, _ ->
        false
    end

    assert {:ok, request} =
             req_request(origin, c.handle,
               method: :post,
               body: Peer.body(),
               retry: retry,
               retry_delay: 0,
               max_retries: 1
             )

    assert {:error, %Error{reason: :signing_failed, stage: :sign, attempt: 2}} =
             result = Req.request(request)

    assert_receive {:wire_request, %{method: "POST"}, {:ok, _}}
    assert RequestSeal.Req.classify(result) == :unknown
    Peer.finish(task)
  end

  test "transport refusals after response and transport retries have unknown delivery", c do
    for action <- [%{status: 503}, :hold] do
      {origin, task} = Peer.start([action], c.handle)

      assert {:ok, request} =
               req_request(
                 origin,
                 c.handle,
                 [retry: :transient, retry_delay: 0, max_retries: 1, receive_timeout: 50],
                 redirect: {:allow, ["http://request-seal.invalid"]}
               )

      request =
        Req.Request.prepend_request_steps(request,
          retry_destination: fn request ->
            if request.private.request_seal.attempt > 0,
              do: %{request | url: URI.parse("http://request-seal.invalid/foo?param=Value")},
              else: request
          end
        )

      assert {:error, %Error{reason: :transport_failed, stage: :transport, attempt: 2}} =
               result = Req.request(observe_errors(request))

      assert_receive {:attempt_error, 2, %Req.TransportError{reason: :nxdomain}}
      assert_receive {:wire_request, _, {:ok, _}}
      assert RequestSeal.Req.classify(result) == :unknown

      if action == :hold do
        assert_receive {:attempt_error, 1, %Req.TransportError{reason: :timeout}}
        assert_receive {:holding, _}
        assert_receive {:peer_closed, {:error, :closed}}
      end

      Peer.finish(task)
    end
  end

  test "a later transport error reaches Req retry handling before classification", c do
    {origin, task} = Peer.start([%{status: 503}, :timeout, %{}], c.handle)

    assert {:ok, request} =
             req_request(origin, c.handle,
               retry: :transient,
               retry_delay: 80,
               max_retries: 2,
               receive_timeout: 50
             )

    assert {:ok, %Req.Response{status: 200}} = result = Req.request(observe_errors(request))
    assert_receive {:attempt_error, 2, %Req.TransportError{reason: :timeout}}
    assert RequestSeal.Req.classify(result) == :answered
    for _ <- 1..3, do: assert_receive({:wire_request, _, {:ok, _}})
    Peer.finish(task)
  end

  test "removing the delivery error step refuses before transport", c do
    {origin, task} = Peer.start([%{}], c.handle)
    assert {:ok, request} = req_request(origin, c.handle)
    steps = Keyword.delete(request.error_steps, :request_seal_delivery)

    assert {:error, %Error{reason: :unsupported_delivery, stage: :sign, attempt: 1}} =
             result = Req.request(%{request | error_steps: steps})

    assert RequestSeal.Req.classify(result) == :refused
    assert_receive :no_connection, 1_500
    Peer.finish(task)
  end

  test "an accepted signed request without a response has unknown delivery", %{handle: handle} do
    for client <- [:req, :finch] do
      {origin, task} = Peer.start([:hold], handle)
      {result, request} = send_request(client, origin, handle, receive_timeout: 50)
      assert {:error, %{reason: :timeout}} = result
      assert classify(client, result, request) == :unknown
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
      {result, request} = send_request(client, origin, released)
      assert {:error, %Error{stage: :sign}} = result
      assert classify(client, result, request) == :refused
      assert_receive :no_connection
      Peer.finish(task)
    end

    assert {:error, %Error{stage: :attach}} = result = RequestSeal.Req.attach(:invalid, [])
    assert RequestSeal.Req.classify(result) == :refused

    for {client, adapter} <- [{:req, :req}, {:finch, :finch}] do
      result = {:error, Error.new(:response_rejected, adapter, :verify, 1)}
      assert classify(client, result, Finch.build(:get, "http://example.com/")) == :unknown
    end
  end

  test "raw HTTP/2 stream refusals require a nil request body", c do
    start_supervised!(
      Supervisor.child_spec(
        {Finch, name: __MODULE__.H2Pool, pools: %{default: [protocols: [:http2]]}},
        id: :h2_pool
      )
    )

    for client <- [:req, :finch],
        frame <- [:rst_stream, :goaway],
        body <- [nil, "", Peer.body()] do
      {origin, task} = h2_peer(frame)
      {result, request} = send_request(client, origin, c.handle, [], __MODULE__.H2Pool, body)
      assert {:error, _} = result
      assert request.body == body
      assert classify(client, result, request) == if(body == nil, do: :refused, else: :unknown)

      if client == :req and body != nil do
        assert {:error, %Error{reason: :transport_failed, stage: :transport, attempt: 1}} = result
      end

      assert_receive {:h2_stream, stream_id} when stream_id > 0
      send(task.pid, :stop)
      Task.await(task, 5_000)
    end
  end

  test "a hidden HTTP/2 rerun cannot erase the first partially sent request", c do
    for {client, pool} <- [{:req, __MODULE__.ReqH2Pool}, {:finch, __MODULE__.FinchH2Pool}] do
      {origin, task} = h2_rerun_peer()

      start_supervised!(
        Supervisor.child_spec(
          {Finch,
           name: pool,
           pools: %{
             origin => [
               protocols: [:http2],
               count: 2,
               http2: [wait_for_server_settings?: true]
             ]
           }},
          id: pool
        )
      )

      for _ <- 1..2, do: assert_receive({:h2_ready, _}, 5_000)
      body = String.duplicate("request-body", 8_192)
      {result, request} = send_request(client, origin, c.handle, [], pool, body)
      assert {:error, _} = result
      assert_receive {:h2_first_headers, first, stream_id, flags}
      assert stream_id > 0
      assert Bitwise.band(flags, 1) == 0
      assert_receive {:h2_partial_body, ^first, bytes, data_flags}
      assert bytes > 0 and bytes < byte_size(body)
      assert Bitwise.band(data_flags, 1) == 0
      assert_receive {:h2_rerun_headers, second, second_stream, _}
      assert first != second
      assert second_stream > 0
      assert classify(client, result, request) == :unknown

      case client do
        :req ->
          assert {:error, %Error{reason: :transport_failed, stage: :transport, attempt: 1}} =
                   result

        :finch ->
          assert {:error,
                  %Finch.HTTPError{
                    module: Mint.HTTP2,
                    reason: {:server_closed_request, :refused_stream}
                  }} = result
      end

      send(task.pid, :stop)
      Task.await(task, 5_000)
      stop_supervised!(pool)
    end
  end

  test "Finch classification requires the actual Finch request" do
    for request <- [nil, :invalid, %{}, %{body: nil}, Req.new(), "", 42],
        result <- [
          {:ok, %Finch.Response{status: 200}},
          {:error, %Finch.TransportError{reason: :nxdomain}},
          {:error, Error.new(:signing_failed, :finch, :sign, 1)}
        ] do
      assert RequestSeal.Finch.classify(result, request) == :unknown
    end
  end

  test "only source-proven transport and stream shapes refuse; every other term is unknown" do
    request = Finch.build(:get, "http://example.com/")

    for {client, adapter} <- [{:req, :req}, {:finch, :finch}] do
      for attempt <- [nil, -1, 0, 2, 3, "1"] do
        result = {:error, Error.new(:signing_failed, adapter, :sign, attempt)}
        assert classify(client, result, request) == :unknown
      end

      result = {:error, Error.new(:invalid_options, adapter, :attach, 1)}
      assert classify(client, result, request) == :unknown
    end

    for {client, transport} <- [
          {:req, Req.TransportError},
          {:finch, Finch.TransportError},
          {:finch, Mint.TransportError}
        ] do
      for reason <- [:nxdomain, :protocol_not_negotiated, {:bad_alpn_protocol, "other"}],
          body <- [nil, "", "body"] do
        result = {:error, struct!(transport, reason: reason)}
        assert classify(client, result, %{request | body: body}) == :refused
      end

      for reason <- [
            :econnrefused,
            :ehostunreach,
            :enetunreach,
            :timeout,
            :connect_timeout,
            :closed,
            :econnreset,
            {:tls_alert, {:handshake_failure, ~c"alert"}}
          ] do
        assert classify(client, {:error, struct!(transport, reason: reason)}, request) == :unknown
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
      assert RequestSeal.Finch.classify(result, request) == :refused

      for body <- ["", "body", {:stream, ["body"]}] do
        assert RequestSeal.Finch.classify(result, %{request | body: body}) == :unknown
      end

      result = {:error, struct!(type, module: Mint.HTTP1, reason: reason)}
      assert RequestSeal.Finch.classify(result, request) == :unknown
    end

    for reason <- [:disconnected, :connection_not_ready] do
      result = {:error, Finch.Error.exception(reason)}
      assert RequestSeal.Finch.classify(result, request) == :refused

      for body <- ["", "body", {:stream, ["body"]}] do
        assert RequestSeal.Finch.classify(result, %{request | body: body}) == :unknown
      end

      for type <- [Finch.HTTPError, Mint.HTTPError] do
        result = {:error, struct!(type, module: Mint.HTTP2, reason: reason)}
        assert RequestSeal.Finch.classify(result, request) == :unknown
      end
    end

    for client <- [:req, :finch],
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
      assert classify(client, term, request) == :unknown
    end
  end

  defp classify(:req, result, _request), do: RequestSeal.Req.classify(result)
  defp classify(:finch, result, request), do: RequestSeal.Finch.classify(result, request)

  defp send_request(client, origin, handle, opts \\ [], pool \\ __MODULE__.Pool, body \\ nil) do
    url = origin <> "/foo?param=Value"
    headers = [{"accept", "text/plain"}]
    method = if body == nil, do: :get, else: :post

    case client do
      :req ->
        case req_request(origin, handle, finch: [name: pool], method: method, body: body) do
          {:ok, request} -> {Req.request(request, opts), request}
          error -> {error, nil}
        end

      :finch ->
        request = Finch.build(method, url, headers, body)

        case RequestSeal.Finch.sign(request, Peer.spec(), handle) do
          {:ok, signed} -> {Finch.request(signed, pool, opts), signed}
          error -> {error, request}
        end
    end
  end

  defp req_request(origin, handle, req_opts \\ [], seal_opts \\ []) do
    request =
      Req.new(
        Keyword.merge(
          [
            url: origin <> "/foo?param=Value",
            headers: [{"accept", "text/plain"}],
            finch: [name: __MODULE__.Pool],
            retry: false,
            redirect: false,
            decode_body: false,
            retry_log_level: false,
            redirect_log_level: false
          ],
          req_opts
        )
      )

    RequestSeal.Req.attach(
      request,
      Keyword.merge([sign: Peer.spec(), signer: handle, verify: :none], seal_opts)
    )
  end

  defp observe_errors(request) do
    owner = self()

    Req.Request.prepend_error_steps(request,
      observe_attempt: fn {request, error} ->
        send(owner, {:attempt_error, request.private.request_seal.attempt, error})
        {request, error}
      end
    )
  end

  defp h2_rerun_peer do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    owner = self()

    task =
      Task.async(fn ->
        peer = self()

        workers =
          for _ <- 1..2 do
            {:ok, socket} = :gen_tcp.accept(listener, 5_000)
            Task.async(fn -> h2_upload_peer(socket, peer, owner) end)
          end

        receive do
          {:h2_request, worker, stream_id, flags} ->
            send(owner, {:h2_first_headers, worker, stream_id, flags})
            send(worker, {:drain, stream_id})
        after
          5_000 -> flunk("HTTP/2 peer did not receive the first request")
        end

        receive do
          {:h2_request, worker, stream_id, flags} ->
            send(owner, {:h2_rerun_headers, worker, stream_id, flags})
            send(worker, {:refuse, stream_id})
        after
          5_000 -> flunk("HTTP/2 peer did not receive Finch's rerun")
        end

        receive do: (:stop -> :ok)

        for worker <- workers do
          send(worker.pid, :stop)
          Task.await(worker, 5_000)
        end

        :gen_tcp.close(listener)
      end)

    on_exit(fn ->
      monitor = Process.monitor(task.pid)
      Process.exit(task.pid, :kill)
      receive do: ({:DOWN, ^monitor, :process, _, _} -> :ok)
      :gen_tcp.close(listener)
    end)

    {"http://127.0.0.1:#{port}", task}
  end

  defp h2_upload_peer(socket, peer, owner) do
    try do
      {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)
      :ok = :gen_tcp.send(socket, <<6::24, 4, 0, 0::32, 4::16, 8::32>>)
      settings_ack(socket)
      send(owner, {:h2_ready, self()})
      {stream_id, flags} = request_headers(socket)
      send(peer, {:h2_request, self(), stream_id, flags})

      receive do
        {:drain, ^stream_id} ->
          {bytes, data_flags} = request_data(socket, stream_id)
          send(owner, {:h2_partial_body, self(), bytes, data_flags})
          :ok = :gen_tcp.send(socket, <<8::24, 7, 0, 0::32, stream_id::32, 0::32>>)

        {:refuse, ^stream_id} ->
          # Finch 0.24.0 HTTP2.Pool.handle_response/3 reads the receive telemetry
          # that complete_request_if_done/3 sets only after the whole body is
          # sent. Refusing a still-uploading stream exits the pool, so open both
          # windows and read the full body before refusing the rerun.
          :ok = :gen_tcp.send(socket, <<6::24, 4, 0, 0::32, 4::16, 1_048_576::32>>)
          :ok = :gen_tcp.send(socket, <<4::24, 8, 0, 0::32, 0::1, 1_048_576::31>>)

          request_body(socket, stream_id)
          :ok = :gen_tcp.send(socket, <<4::24, 3, 0, stream_id::32, 7::32>>)
      after
        5_000 -> flunk("HTTP/2 peer did not receive its response instruction")
      end

      receive do: (:stop -> :ok)
    after
      :gen_tcp.close(socket)
    end
  end

  defp settings_ack(socket) do
    case h2_frame(socket) do
      {4, 1, 0, ""} ->
        :ok

      {4, 0, 0, _} ->
        :ok = :gen_tcp.send(socket, <<0::24, 4, 1, 0::32>>)
        settings_ack(socket)

      _ ->
        settings_ack(socket)
    end
  end

  defp request_data(socket, stream_id) do
    case h2_frame(socket) do
      {0, flags, ^stream_id, data} -> {byte_size(data), flags}
      _ -> request_data(socket, stream_id)
    end
  end

  defp request_body(socket, stream_id) do
    case h2_frame(socket) do
      {0, flags, ^stream_id, _data} when Bitwise.band(flags, 1) == 1 -> :ok
      _ -> request_body(socket, stream_id)
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
          {stream_id, _flags} = request_headers(socket)
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

  defp request_headers(socket) do
    {type, flags, stream_id, _payload} = h2_frame(socket)

    cond do
      type == 1 and stream_id > 0 ->
        {stream_id, flags}

      type == 4 and flags == 0 ->
        :ok = :gen_tcp.send(socket, <<0::24, 4, 1, 0::32>>)
        request_headers(socket)

      true ->
        request_headers(socket)
    end
  end

  defp h2_frame(socket) do
    {:ok, <<size::24, type, flags, _reserved::1, stream_id::31>>} =
      :gen_tcp.recv(socket, 9, 5_000)

    {:ok, payload} = if size > 0, do: :gen_tcp.recv(socket, size, 5_000), else: {:ok, ""}
    {type, flags, stream_id, payload}
  end
end
