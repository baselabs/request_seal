defmodule RequestSeal.HTTPSignaturePeer do
  @moduledoc false
  alias RequestSeal.{Body, Custody, Digest, FieldOccurrence, Message, Policy, TransportFacts}
  @body ~s[{"hello": "world"}]
  @components ~s[("@method" "@target-uri" "@authority" "@query-param";name="param" "accept" "content-digest" "content-length")]
  @response_components ~s[("@status" "content-digest" "@method";req "@target-uri";req)]

  def body, do: @body
  def components, do: @components
  def response_components, do: @response_components

  def handle do
    {:ok, h} =
      RequestSeal.Custody.Local.new(
        "hmac-sha256",
        {:hmac,
         Base.decode64!(
           String.trim(File.read!(Path.join(__DIR__, "../fixtures/crypto/hmac.txt")))
         )}
      )

    h
  end

  def policy(components, handle, section \\ :headers, resolver_observer \\ nil) do
    {:ok, p} =
      Policy.new(%{
        algorithms: ["hmac-sha256"],
        components: components,
        key_resolver: fn _ ->
          if resolver_observer, do: send(resolver_observer, :resolved)

          {:ok,
           %{
             algorithm: "hmac-sha256",
             key: fn _, base, sig -> Custody.verify(handle, base, sig) end
           }}
        end,
        freshness: :not_evaluated,
        content: %{kind: :content, algorithms: ["sha-256"], section: section},
        replay: :not_required
      })

    p
  end

  def spec(components \\ @components) do
    %{
      label: "sig",
      components: components,
      algorithm: "hmac-sha256",
      parameters: %{
        created: true,
        expires_in: 60,
        nonce: :random,
        alg: true,
        keyid: "test-shared-secret",
        tag: nil
      },
      digest: ["sha-256"],
      field_schemas: %{}
    }
  end

  def start(actions, handle, components \\ @components) do
    {:ok, socket} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        packet: :line,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, {_, port}} = :inet.sockname(socket)
    origin = "http://127.0.0.1:#{port}"
    owner = self()

    task =
      Task.async(fn ->
        Enum.each(actions, fn action ->
          case :gen_tcp.accept(socket, 1_000) do
            {:ok, conn} ->
              {:ok, line} = :gen_tcp.recv(conn, 0, 2_000)
              [method, target, "HTTP/1.1"] = String.split(String.trim(line), " ")
              headers = headers(conn, [])
              :ok = :inet.setopts(conn, packet: :raw)
              content = read_body(conn, headers)

              {:ok, message} =
                Message.new(%{
                  kind: :request,
                  method: method,
                  raw_target: target,
                  target_form: :origin,
                  scheme: "http",
                  authority: "127.0.0.1:#{port}",
                  fields: fields(headers),
                  trailers: [],
                  body: retained(content),
                  transport: %TransportFacts{}
                })

              verified = RequestSeal.verify(message, policy(components, handle), label: "sig")
              send(owner, {:wire_request, message, verified})
              respond(conn, message, action, handle, owner)
              :gen_tcp.close(conn)

            {:error, :timeout} ->
              send(owner, :no_connection)

            {:error, :closed} ->
              :ok
          end
        end)

        :gen_tcp.close(socket)
      end)

    ExUnit.Callbacks.on_exit(fn -> :gen_tcp.close(socket) end)
    {origin, task}
  end

  def finish(task), do: Task.await(task, 6_000)

  defp headers(conn, acc) do
    {:ok, line} = :gen_tcp.recv(conn, 0, 2_000)

    if line == "\r\n" do
      Enum.reverse(acc)
    else
      [name, value] = String.split(String.trim_trailing(line, "\r\n"), ":", parts: 2)
      headers(conn, [{String.downcase(name), String.trim_leading(value)} | acc])
    end
  end

  defp read_body(conn, headers) do
    case List.keyfind(headers, "content-length", 0) do
      {_, "0"} ->
        ""

      {_, n} ->
        {:ok, body} = :gen_tcp.recv(conn, String.to_integer(n), 2_000)
        body

      nil ->
        ""
    end
  end

  defp respond(_, _, :timeout, _, _) do
    Process.sleep(120)
  end

  defp respond(conn, _, :hold, _, owner) do
    send(owner, {:holding, self()})
    send(owner, {:peer_closed, :gen_tcp.recv(conn, 0, 2_000)})
  end

  defp respond(conn, request, action, handle, owner) do
    status = Map.get(action, :status, 200)
    trailers? = Map.get(action, :trailers, false)
    content = Map.get(action, :body, @body)
    content = if Map.get(action, :gzip, false), do: :zlib.gzip(content), else: content
    digest_field = {"content-digest", digest(content)}

    components =
      if trailers?,
        do: String.replace(@response_components, "\"content-digest\"", "\"content-digest\";tr"),
        else: @response_components

    h =
      [{"connection", "close"}, {"content-type", "application/json"}] ++
        Map.get(action, :headers, [])

    h = if Map.get(action, :gzip, false), do: h ++ [{"content-encoding", "gzip"}], else: h

    h =
      if trailers?,
        do: h ++ [{"transfer-encoding", "chunked"}, {"trailer", "content-digest"}],
        else:
          h ++
            [
              {"content-length",
               to_string(byte_size(content) + Map.get(action, :missing_tail, 0))},
              digest_field
            ]

    {:ok, response} =
      Message.new(%{
        kind: :response,
        status: status,
        fields: fields(h),
        trailers: if(trailers?, do: fields([digest_field], :trailers), else: []),
        body: retained(content),
        related_request: request,
        transport: %TransportFacts{}
      })

    {:ok, signed} =
      RequestSeal.sign(
        response,
        %{label: "res", signature_input: components, algorithm: "hmac-sha256"},
        fn _, base -> Custody.sign(handle, base) end
      )

    fields = if Map.get(action, :unsigned, false), do: response.fields, else: signed.fields

    body =
      if Map.get(action, :tamper, false),
        do: String.replace(content, "world", "earth"),
        else: content

    framing =
      if trailers?,
        do: [
          Integer.to_string(byte_size(body), 16),
          "\r\n",
          body,
          "\r\n0\r\ncontent-digest: ",
          digest(content),
          "\r\n\r\n"
        ],
        else: body

    :gen_tcp.send(conn, [
      "HTTP/1.1 ",
      to_string(status),
      " Response\r\n",
      Enum.map(fields, &[&1.name, ": ", &1.value, "\r\n"]),
      "\r\n",
      framing
    ])

    if Map.get(action, :missing_tail, 0) > 0 do
      send(owner, {:peer_closed, :gen_tcp.recv(conn, 0, 2_000)})
    end
  end

  def retained(bytes), do: %Body{state: :retained, bytes: bytes, max_bytes: byte_size(bytes)}

  def fields(headers, section \\ :headers),
    do:
      Enum.map(headers, fn {name, value} ->
        %FieldOccurrence{name: name, value: value, section: section, provenance: :http1}
      end)

  def digest(body) do
    {:ok, value} = Digest.compute(retained(body), ["sha-256"])
    {:ok, wire} = Digest.serialize(value)
    wire
  end
end
