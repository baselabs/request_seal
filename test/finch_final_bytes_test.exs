Code.require_file("support/plug_transport_helper.exs", __DIR__)

defmodule RequestSeal.FinchFinalBytesTest do
  use ExUnit.Case, async: false
  alias RequestSeal.PlugTransport, as: T

  @components ~s[("@method" "@scheme" "@authority" "@path" "accept" "content-type" "content-length" "content-digest")]
  @bytes <<0, 255, "exact\r\nbody", 0>>

  defmodule Receiver do
    @behaviour Plug
    def init(options), do: options

    def call(conn, options) do
      {:ok, body, conn} = Plug.Conn.read_body(conn, length: 4096, read_timeout: 1000)
      [authority] = Plug.Conn.get_req_header(conn, "host")

      # This test uses a nonempty query. Plug does not prove an empty query
      # delimiter or every raw target form; do not generalize this observation.
      target = conn.request_path <> "?" <> conn.query_string

      {:ok, message} =
        RequestSeal.Message.request(
          conn.method,
          "http://" <> authority <> target,
          conn.req_headers,
          body
        )

      verification = RequestSeal.verify(message, options[:policy], label: "sig")
      send(options[:owner], {:finch_wire, self(), message, verification})

      case options[:action] do
        :hold ->
          receive do
            :stop -> exit(:normal)
          after
            5_000 -> exit(:normal)
          end

        :drop ->
          # Terminate the real connection handler after reading and verifying
          # the entire upload, without producing an HTTP response.
          Process.exit(self(), :kill)

        _ ->
          Plug.Conn.send_resp(conn, if(match?({:ok, _}, verification), do: 204, else: 401), "")
      end
    end
  end

  setup do
    handle = T.handle()
    on_exit(fn -> RequestSeal.Custody.release(handle) end)
    start_supervised!({Finch, name: __MODULE__.Pool})
    %{handle: handle}
  end

  test "returned Finch bytes equal the request Bandit actually receives", c do
    origin = receiver()

    for body <- [
          [<<0, 255>>, ["exact\r\n", "body"], <<0>>],
          {:stream, [<<0, 255>>, "exact\r\nbody", <<0>>]}
        ] do
      request = build(origin, body)

      assert {:ok, signed} =
               RequestSeal.Finch.sign(request, T.spec(@components), c.handle,
                 body: {:retain, 4096}
               )

      assert {:ok, returned} = RequestSeal.Finch.request_message(signed)
      result = Finch.request(signed, __MODULE__.Pool)
      assert_receive {:finch_wire, _, observed, verification}, 5_000

      assert match?({:ok, _}, verification), "Bandit rejected finalized Finch bytes"
      assert signed.body == @bytes
      assert returned.body.bytes == observed.body.bytes
      assert observed.body.bytes == @bytes
      assert returned.method == observed.method
      assert returned.scheme == observed.scheme
      assert returned.authority == observed.authority
      assert returned.raw_target == observed.raw_target
      assert observed.raw_target == "/a%2Fb?value=%2f&value=two"

      expected_headers =
        Enum.map(signed.headers, fn {name, value} -> {String.downcase(name), value} end)

      names = Enum.map(expected_headers, &elem(&1, 0))

      received_headers =
        for field <- observed.fields, field.name in names, do: {field.name, field.value}

      assert received_headers == expected_headers

      assert for(field <- observed.fields, field.name == "accept", do: field.value) == [
               "text/plain",
               "*/*"
             ]

      [{_, "sig=" <> input}] = Enum.filter(expected_headers, &(elem(&1, 0) == "signature-input"))
      assert {:ok, base} = RequestSeal.SignatureBase.build(returned, input)
      assert {:ok, ^base} = RequestSeal.SignatureBase.build(observed, input)
      assert {:ok, %{status: 204}} = result
      assert RequestSeal.Finch.classify(result, signed) == :answered
    end
  end

  test "mutating finalized body path or repeated header order is rejected by Bandit", c do
    origin = receiver()

    assert {:ok, signed} =
             RequestSeal.Finch.sign(build(origin, @bytes), T.spec(@components), c.handle)

    mutations = [
      %{signed | body: <<1, 255, "exact\r\nbody", 0>>},
      %{signed | path: "/changed?value=%2f&value=two"},
      %{signed | headers: Enum.reverse(signed.headers)}
    ]

    for mutated <- mutations do
      assert {:ok, response} = Finch.request(mutated, __MODULE__.Pool)
      assert response.status == 401, "Bandit must reject a changed signed request"
      assert_receive {:finch_wire, _, _, {:error, %RequestSeal.Error{reason: reason}}}, 5_000
      assert reason in [:invalid_signature, :digest_mismatch]
    end
  end

  test "timeout after Bandit receives the complete signed request is unknown", c do
    origin = receiver(:hold)

    assert {:ok, signed} =
             RequestSeal.Finch.sign(build(origin, @bytes), T.spec(@components), c.handle)

    task = Task.async(fn -> Finch.request(signed, __MODULE__.Pool, receive_timeout: 500) end)
    assert_receive {:finch_wire, handler, %{body: %{bytes: @bytes}}, {:ok, _}}, 5_000
    on_exit(fn -> send(handler, :stop) end)
    monitor = Process.monitor(handler)
    assert {:error, %{reason: :timeout}} = result = Task.await(task, 5_000)

    assert RequestSeal.Finch.classify(result, signed) == :unknown,
           "a sent timeout has unknown outcome"

    send(handler, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^handler, _}, 5_000
  end

  test "drop after Bandit receives the complete signed request is unknown", c do
    origin = receiver(:drop)

    assert {:ok, signed} =
             RequestSeal.Finch.sign(build(origin, @bytes), T.spec(@components), c.handle)

    result = Finch.request(signed, __MODULE__.Pool)
    assert_receive {:finch_wire, _, %{body: %{bytes: @bytes}}, {:ok, _}}, 5_000
    assert {:error, %{reason: reason}} = result
    assert reason in [:closed, :econnreset]

    assert RequestSeal.Finch.classify(result, signed) == :unknown,
           "a sent drop has unknown outcome"
  end

  test "a signing refusal is not sent to Bandit", c do
    origin = receiver()
    request = build(origin, @bytes)
    request = %{request | headers: [{"Host", "other.example"} | request.headers]}
    result = RequestSeal.Finch.sign(request, T.spec(@components), c.handle)
    assert {:error, %RequestSeal.Adapter.Error{reason: :invalid_options, stage: :sign}} = result

    assert RequestSeal.Finch.classify(result, request) == :refused,
           "a pre-send refusal is not sent"

    refute_receive {:finch_wire, _, _, _}, 200
  end

  defp build(origin, body) do
    Finch.build(
      :post,
      origin <> "/a%2Fb?value=%2f&value=two",
      [
        {"accept", "text/plain"},
        {"accept", "*/*"},
        {"content-type", "application/octet-stream"}
      ],
      body
    )
  end

  defp receiver(action \\ :answer) do
    server =
      start_supervised!(
        {Bandit,
         plug: {Receiver, owner: self(), policy: T.policy(@components), action: action},
         ip: {127, 0, 0, 1},
         port: 0,
         startup_log: false}
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(server)
    "http://127.0.0.1:#{port}"
  end
end
