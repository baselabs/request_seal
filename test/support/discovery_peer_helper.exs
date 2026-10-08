unless Code.ensure_loaded?(:ssl), do: Mix.ensure_application!(:ssl)

defmodule RequestSeal.DiscoveryPeer do
  @moduledoc false
  alias RequestSeal.{Body, Message, FieldOccurrence, TransportFacts}

  def start(handler, hostname \\ ~c"localhost") do
    {:ok, _} = Application.ensure_all_started(:ssl)

    data =
      :public_key.pkix_test_data(%{
        server_chain: %{
          root: [key: {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, digest: :sha256],
          intermediates: [],
          peer: [
            key: {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
            digest: :sha256,
            extensions: [{:Extension, {2, 5, 29, 17}, false, [{:dNSName, hostname}]}]
          ]
        },
        client_chain: %{
          root: [key: {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, digest: :sha256],
          intermediates: [],
          peer: [key: {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, digest: :sha256]
        }
      })

    owner = self()
    ref = make_ref()

    pid =
      spawn(fn ->
        {:ok, listen} =
          :ssl.listen(
            0,
            [ip: {127, 0, 0, 1}, active: false, mode: :binary, reuseaddr: true, log_level: :none] ++
              data.server_config
          )

        {:ok, {_, port}} = :ssl.sockname(listen)
        send(owner, {ref, listen, port})
        accept(listen, owner, handler)
      end)

    receive do
      {^ref, listen, port} ->
        %{pid: pid, listen: listen, port: port, cacerts: data.client_config[:cacerts]}
    after
      5_000 -> raise "TLS publisher startup deadline"
    end
  end

  def stop(peer) do
    :ssl.close(peer.listen)
    Process.exit(peer.pid, :kill)
  end

  defp accept(listen, owner, handler) do
    case :ssl.transport_accept(listen) do
      {:ok, socket} ->
        worker =
          spawn_link(fn ->
            receive do
              {:socket, socket} ->
                case :ssl.handshake(socket, 5_000) do
                  {:ok, socket} ->
                    send(owner, {:accepted, self()})
                    {:ok, request} = headers(socket, "")
                    handler.(socket, request)
                    :ssl.close(socket)

                  _ ->
                    :ssl.close(socket)
                end
            end
          end)

        :ok = :ssl.controlling_process(socket, worker)
        send(worker, {:socket, socket})
        accept(listen, owner, handler)

      _ ->
        :ok
    end
  end

  defp headers(socket, buffer) do
    if String.contains?(buffer, "\r\n\r\n") do
      {:ok, buffer}
    else
      case :ssl.recv(socket, 0, 5_000) do
        {:ok, bytes} -> headers(socket, buffer <> bytes)
        error -> error
      end
    end
  end

  def public_jwk do
    :json.decode(File.read!("test/fixtures/custody/rfc8037.json")) |> Map.delete("d")
  end

  def directory(keys \\ [public_jwk()]) do
    :json.encode(%{"keys" => keys}) |> IO.iodata_to_binary()
  end

  def reply(socket, body, headers \\ [], status \\ 200) do
    :ssl.send(socket, [
      "HTTP/1.1 ",
      Integer.to_string(status),
      " Publisher\r\n",
      Enum.map(headers, fn {k, v} -> [k, ": ", v, "\r\n"] end),
      "Content-Length: ",
      Integer.to_string(byte_size(body)),
      "\r\nConnection: close\r\n\r\n",
      body
    ])
  end

  def signed(socket, request, body, authority \\ nil, parameters \\ []) do
    message = signed_message(request, body, authority, parameters)
    reply(socket, body, Enum.map(message.fields, &{&1.name, &1.value}))
  end

  def signed_message(request, body, authority \\ nil, parameters \\ []) do
    host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, request) |> Enum.at(1)
    now = System.system_time(:second)
    {:ok, b} = Body.new(%{state: :retained, bytes: body})
    {:ok, empty} = Body.new(%{state: :retained, bytes: ""})
    {:ok, transport} = TransportFacts.new(%{})

    {:ok, host_field} =
      FieldOccurrence.new(%{
        name: "Host",
        value: " " <> host,
        section: :headers,
        provenance: :http1
      })

    {:ok, req} =
      Message.new(%{
        kind: :request,
        method: "GET",
        raw_target: "/.well-known/http-message-signatures-directory",
        target_form: :origin,
        scheme: "https",
        authority: authority || host,
        fields: [host_field],
        trailers: [],
        body: empty,
        transport: transport
      })

    digest = "sha-256=:" <> Base.encode64(:crypto.hash(:sha256, body)) <> ":"

    encoding =
      if Keyword.get(parameters, :gzip, false), do: [{"Content-Encoding", "gzip"}], else: []

    fields =
      for {name, value} <-
            encoding ++
              [
                {"Content-Type", "application/http-message-signatures-directory+json"},
                {"Content-Digest", digest},
                {"Cache-Control", "max-age=30"}
              ] do
        {:ok, field} = FieldOccurrence.new(%{name: name, value: value, section: :headers})
        field
      end

    {:ok, response} =
      Message.new(%{
        kind: :response,
        status: 200,
        fields: fields,
        trailers: [],
        body: b,
        transport: transport,
        related_request: req
      })

    algorithm = Keyword.get(parameters, :algorithm, "ed25519")

    {:ok, handle} =
      if algorithm == "ed25519" do
        RequestSeal.Custody.Local.import(
          algorithm,
          :json.decode(File.read!("test/fixtures/custody/rfc8037.json")),
          :jwk
        )
      else
        RequestSeal.Custody.Local.import(
          algorithm,
          File.read!("test/fixtures/crypto/rsa_private.pem"),
          :pem
        )
      end

    {:ok, public} = RequestSeal.Custody.public_key(handle)
    {:ok, kid} = RequestSeal.PublicKey.thumbprint(public)
    tag = Keyword.get(parameters, :tag, "http-message-signatures-directory")
    created = Keyword.get(parameters, :created, now)
    expires = Keyword.get(parameters, :expires, now + 60)

    components = Keyword.get(parameters, :components, "\"@authority\";req \"content-digest\"")

    input =
      "(#{components});created=#{created};expires=#{expires};keyid=\"#{kid}\";tag=\"#{tag}\""

    {:ok, signed} =
      RequestSeal.sign(
        response,
        %{
          label: Keyword.get(parameters, :label, "directory"),
          signature_input: input,
          algorithm: algorithm
        },
        fn _, base -> RequestSeal.Custody.sign(handle, base) end
      )

    signed
  end
end
