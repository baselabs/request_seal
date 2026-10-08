defmodule RequestSeal.PlugGzipJSON do
  @moduledoc false
  # Caller-selected content decoder; capture continues to retain the encoded bytes.
  def decode!(bytes), do: bytes |> :zlib.gunzip() |> Jason.decode!()
end

defmodule RequestSeal.PlugTransport do
  @moduledoc false
  import Plug.Conn
  alias RequestSeal.{Policy, PublicKey, SignatureFields}
  @root Path.join(__DIR__, "../fixtures")
  @vectors :json.decode(File.read!(Path.join(@root, "verification/rfc9421.json")))
  @bases :json.decode(File.read!(Path.join(@root, "signature_base/rfc9421.json")))
  @body ~s[{"hello": "world"}]
  @response ~s[{"message": "good dog"}]
  @components ~s[("@method" "@scheme" "@authority" "@path" "accept" "content-digest")]
  @response_components ~s[("@status" "content-digest" "@method";req "@path";req)]

  def body, do: @body
  def response, do: @response
  def components, do: @components
  def response_components, do: @response_components
  def vector(section), do: Enum.find(@vectors, &(&1["section"] == section))
  def base(section), do: Enum.find(@bases, &(&1["section"] == section))

  def handle do
    {:ok, handle} =
      RequestSeal.Custody.Local.import(
        "ed25519",
        File.read!(Path.join(@root, "crypto/ed25519_private.pem")),
        :pem
      )

    handle
  end

  def public(key \\ "ed25519") do
    {:ok, key} = PublicKey.import(File.read!(Path.join(@root, "crypto/#{key}_public.pem")), :pem)
    key
  end

  def policy(components \\ @components, opts \\ []) do
    key = public(Keyword.get(opts, :key, "ed25519"))
    algorithm = Keyword.get(opts, :algorithm, "ed25519")
    owner = Keyword.get(opts, :owner)

    resolver = fn meta ->
      if owner, do: send(owner, {:resolved, meta})
      if meta.keyid == "unknown", do: :error, else: {:ok, %{algorithm: algorithm, key: key}}
    end

    {:ok, p} =
      Policy.new(%{
        algorithms: [algorithm],
        components: components,
        key_resolver: resolver,
        freshness: Keyword.get(opts, :freshness, :not_evaluated),
        content:
          Keyword.get(opts, :content, %{
            kind: :content,
            algorithms: ["sha-256"],
            section: :headers
          }),
        replay: Keyword.get(opts, :replay, :not_required)
      })

    p
  end

  def published_policy(section, opts \\ []) do
    v = vector(section)
    {:ok, input} = SignatureFields.inner(base(section)["parameters"])

    {:ok, components} =
      RequestSeal.StructuredFields.serialize(
        %RequestSeal.StructuredFields.Value{type: :list, value: [%{input | parameters: []}]},
        SignatureFields.schema(:list)
      )

    content =
      if section in ["B.2.3", "B.2.4"],
        do: %{kind: :content, algorithms: ["sha-512"], section: :headers},
        else: :not_required

    policy(
      components,
      Keyword.merge(
        [
          key: v["key"],
          algorithm: v["algorithm"],
          content: content,
          freshness: %{
            clock: fn -> 1_618_884_473 end,
            max_age: 60,
            skew: 0,
            require_expires: false
          }
        ],
        opts
      )
    )
  end

  def spec(components \\ @components) do
    %{
      label: "sig",
      components: components,
      algorithm: "ed25519",
      digest: ["sha-256"],
      field_schemas: %{},
      parameters: %{
        created: true,
        expires_in: 60,
        nonce: :random,
        keyid: "test-key-ed25519",
        tag: nil,
        alg: true
      }
    }
  end

  def capture_opts(opts) do
    [
      origin: Keyword.get(opts, :origin, :connection),
      max_body_bytes: Keyword.get(opts, :max_body_bytes, 4096),
      read_timeout: 1000
    ]
  end

  def parser(conn, reader, gzip \\ false, extra \\ []) do
    opts = [
      parsers: [:json],
      pass: ["*/*"],
      json_decoder: if(gzip, do: RequestSeal.PlugGzipJSON, else: Jason)
    ]

    opts =
      if reader,
        do: Keyword.put(opts, :body_reader, {RequestSeal.Plug.Capture, :read_body, []}),
        else: opts

    Plug.Parsers.call(conn, Plug.Parsers.init(Keyword.merge(opts, extra)))
  end

  def init(opts), do: opts

  def call(conn, opts) do
    if opts[:owner], do: send(opts[:owner], {:ingress_adapter, elem(conn.adapter, 0)})
    if opts[:target_evidence], do: send(opts[:owner], {:target_ingress, conn})
    if opts[:trace_body], do: :erlang.trace(self(), true, [:call, {:tracer, opts[:owner]}])
    conn = if opts[:connect_method], do: %{conn | method: "CONNECT"}, else: conn

    conn =
      if opts[:bare_host],
        do: %{conn | host: conn.host |> String.trim_leading("[") |> String.trim_trailing("]")},
        else: conn

    conn = if opts[:parser_first], do: parser(conn, false), else: conn

    conn =
      if opts[:no_capture],
        do: conn,
        else:
          RequestSeal.Plug.Capture.call(conn, RequestSeal.Plug.Capture.init(capture_opts(opts)))

    conn =
      if not conn.halted and opts[:capture_twice],
        do:
          RequestSeal.Plug.Capture.call(conn, RequestSeal.Plug.Capture.init(capture_opts(opts))),
        else: conn

    conn =
      if not conn.halted and opts[:parse],
        do: parse_request(conn, opts),
        else: conn

    conn =
      if opts[:replay_tamper] do
        state = conn.private[:request_seal]

        body = %{
          state.capture.message.body
          | bytes: String.replace(state.capture.message.body.bytes, "world", "earth")
        }

        capture = %{state.capture | message: %{state.capture.message | body: body}}
        put_private(conn, :request_seal, %{state | capture: capture})
      else
        conn
      end

    conn = if opts[:before_verify], do: opts[:before_verify].(conn), else: conn

    conn =
      if not conn.halted and opts[:direct_claim] do
        {:ok, captured} = RequestSeal.Plug.capture(conn)

        send(
          opts[:owner],
          {:direct_claim,
           RequestSeal.verify(captured.message, opts[:policy],
             label: Keyword.get(opts, :label, "sig")
           )}
        )

        conn
      else
        conn
      end

    conn =
      if not conn.halted and opts[:policy] do
        verify =
          RequestSeal.Plug.Verify.init(
            policy: opts[:policy],
            label: Keyword.get(opts, :label, "sig"),
            on_reject: Keyword.get(opts, :on_reject, :continue),
            assign: Keyword.get(opts, :assign)
          )

        verify =
          if opts[:invalid_verify_policy],
            do: Keyword.update!(verify, :policy, &%{&1 | components: "policy-canary"}),
            else: verify

        conn = RequestSeal.Plug.Verify.call(conn, verify)

        if opts[:owner],
          do: send(opts[:owner], {:first_verification, RequestSeal.Plug.verification(conn)})

        if opts[:owner],
          do:
            send(opts[:owner], {:verification_attempt, conn.private[:request_seal].verification})

        if opts[:twice], do: RequestSeal.Plug.Verify.call(conn, verify), else: conn
      else
        conn
      end

    if opts[:owner],
      do:
        send(
          opts[:owner],
          {:observed, conn, RequestSeal.Plug.capture(conn), RequestSeal.Plug.verification(conn)}
        )

    cond do
      conn.halted ->
        conn

      opts[:published_response] ->
        published_response(conn)

      true ->
        conn =
          if opts[:response_date],
            do: put_resp_header(conn, "date", "Tue, 20 Apr 2021 02:07:56 GMT"),
            else: conn

        conn =
          if opts[:cookie_header],
            do: put_resp_header(conn, "set-cookie", "control=header"),
            else: conn

        conn =
          if opts[:cookie] == :late,
            do: register_before_send(conn, &put_resp_cookie(&1, "session", "retained")),
            else: conn

        conn =
          if opts[:cookie] == :pending,
            do: put_resp_cookie(conn, "session", "retained"),
            else: conn

        conn = if opts[:existing_signature], do: published_signature(conn), else: conn

        conn =
          if opts[:late_signature],
            do: register_before_send(conn, &published_signature/1),
            else: conn

        conn = if opts[:before_sign], do: opts[:before_sign].(conn), else: conn

        conn =
          if opts[:sign] do
            RequestSeal.Plug.SignResponse.call(
              conn,
              RequestSeal.Plug.SignResponse.init(
                sign: opts[:sign],
                signer: opts[:signer],
                signing_timeout: 1000,
                clock: Keyword.get(opts, :clock, fn -> 1_618_884_473 end),
                on_failure: {:respond, 503}
              )
            )
          else
            conn
          end

        conn = if opts[:after_sign], do: opts[:after_sign].(conn), else: conn

        conn =
          if opts[:wrong_related] do
            state = conn.private[:request_seal]
            captured = %{state.capture | message: %{state.capture.message | raw_target: "/wrong"}}
            Plug.Conn.put_private(conn, :request_seal, %{state | capture: captured})
          else
            conn
          end

        conn =
          if opts[:transform_response],
            do: register_before_send(conn, fn c -> %{c | resp_body: @body} end),
            else: conn

        conn =
          case opts[:delivery] do
            :closed_chunk ->
              conn = %{conn | adapter: RequestSeal.Plug.Delivery.wrap(conn.adapter)}
              conn = send_chunked(conn, 200)
              {:ok, conn} = chunk(conn, @response)
              {adapter, payload} = conn.adapter
              {:ok, _, payload} = adapter.chunk(payload, "")
              conn = %{conn | adapter: {adapter, payload}}
              result = adapter.chunk(payload, "after end of stream")
              send(opts[:owner], {:closed_chunk, result})
              conn

            :chunked ->
              conn = send_chunked(conn, 200)
              result = chunk(conn, @response)
              if opts[:owner], do: send(opts[:owner], {:chunk_write, result})

              case result do
                {:ok, conn} -> conn
                {:error, :closed} -> conn
              end

            :file ->
              send_file(conn, 200, Path.join(@root, "http/response.http"))

            :deny ->
              send_resp(conn, 403, "")

            _ ->
              send_resp(conn, 200, @response)
          end

        if opts[:owner], do: send(opts[:owner], {:sent, conn})
        conn
    end
  end

  def wrapper_reader(conn, opts, transform) do
    case RequestSeal.Plug.Capture.read_body(conn, opts) do
      {tag, bytes, conn} when tag in [:ok, :more] ->
        bytes = if transform, do: String.replace(bytes, "world", "earth"), else: bytes
        {tag, bytes, conn}

      result ->
        result
    end
  end

  # Deliberately misconfigured caller reader: exercise the documented observation boundary.
  def bypass_reader(conn, _opts) do
    {:ok, capture} = RequestSeal.Plug.capture(conn)
    {:ok, String.replace(capture.message.body.bytes, "world", "earth"), conn}
  end

  defp parse_request(conn, opts) do
    extra = Keyword.get(opts, :parser_opts, [])

    extra =
      if Keyword.has_key?(opts, :wrapper_transform),
        do:
          Keyword.put(
            extra,
            :body_reader,
            {__MODULE__, :wrapper_reader, [opts[:wrapper_transform]]}
          ),
        else: extra

    try do
      parser(conn, Keyword.get(opts, :reader, true), Keyword.get(opts, :gzip, false), extra)
    rescue
      e in Plug.Parsers.RequestTooLargeError ->
        send(opts[:owner], {:parser_rejection, e.__struct__})
        conn |> send_resp(413, "") |> halt()
    end
  end

  defp published_signature(conn) do
    v = vector("B.2.4")

    conn
    |> put_resp_header("signature-input", v["signature_input"])
    |> put_resp_header("signature", v["signature"])
  end

  defp published_response(conn) do
    v = vector("B.2.4")

    fields =
      base("B.2.4")["message"]["fields"] ++
        [["Signature-Input", v["signature_input"]], ["Signature", v["signature"]]]

    conn =
      Enum.reduce(fields, conn, fn [n, v], c -> put_resp_header(c, String.downcase(n), v) end)

    send_resp(conn, 200, @response)
  end

  def tls do
    :public_key.pkix_test_data(%{
      server_chain: %{
        root: [key: {:rsa, 2048, 65537}, digest: :sha256],
        intermediates: [],
        peer: [key: {:rsa, 2048, 65537}, digest: :sha256]
      },
      client_chain: %{
        root: [key: {:rsa, 2048, 65537}, digest: :sha256],
        intermediates: [],
        peer: [key: {:rsa, 2048, 65537}, digest: :sha256]
      }
    })
  end

  def start(opts, server_opts \\ []) do
    spec =
      {Bandit,
       Keyword.merge(
         [
           plug: {__MODULE__, opts},
           ip: {127, 0, 0, 1},
           port: 0,
           startup_log: false,
           http_options: [compress: false, log_protocol_errors: false]
         ],
         server_opts
       )}

    pid = ExUnit.Callbacks.start_supervised!(Supervisor.child_spec(spec, id: make_ref()))
    {:ok, {_, port}} = ThousandIsland.listener_info(pid)

    ExUnit.Callbacks.on_exit(fn ->
      case :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 500) do
        {:error, :econnrefused} ->
          :ok

        {:ok, socket} ->
          :gen_tcp.close(socket)
          raise "listener remained open after teardown"

        {:error, reason} ->
          raise "listener teardown probe returned #{reason}"
      end
    end)

    scheme = Keyword.get(server_opts, :scheme, :http)
    {"#{scheme}://127.0.0.1:#{port}", pid}
  end

  def wire(section, message \\ nil, body \\ @body) do
    v = vector(section)
    m = message || base(section)["message"]

    fields =
      Enum.reject(m["fields"], fn [n, _] ->
        String.downcase(n) in ["signature", "signature-input"]
      end)

    fields =
      fields ++
        [
          ["Signature-Input", v["signature_input"]],
          ["Signature", v["signature"]],
          ["Connection", "close"]
        ]

    body = if m["method"] == "GET", do: "", else: body

    [
      m["method"],
      " ",
      m["raw_target"],
      " HTTP/1.1\r\n",
      Enum.map(fields, fn [n, v] -> [n, ": ", v, "\r\n"] end),
      "\r\n",
      body
    ]
  end

  def raw(origin, bytes) do
    uri = URI.parse(origin)
    transport = if uri.scheme == "https", do: :ssl, else: :gen_tcp
    options = [:binary, active: false]

    options =
      if transport == :ssl,
        do: options ++ [verify: :verify_none, alpn_advertised_protocols: ["http/1.1"]],
        else: options

    {:ok, socket} = transport.connect(~c"127.0.0.1", uri.port, options, 2000)
    :ok = transport.send(socket, bytes)
    result = collect(transport, socket, "")
    transport.close(socket)
    result
  end

  defp collect(transport, socket, acc) do
    case transport.recv(socket, 0, 3000) do
      {:ok, bytes} -> collect(transport, socket, acc <> bytes)
      {:error, :closed} -> acc
      {:error, reason} -> raise "raw transport failed: #{reason}"
    end
  end
end
