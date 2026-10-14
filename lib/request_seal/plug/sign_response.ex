if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.SignResponse do
    @moduledoc """
    Sign final buffered response bytes in a Plug `before_send` callback.

    The signing callback runs after other registered callbacks, including callbacks
    registered earlier that mutate signed facts. Their changes are included before
    signing. Plug merges `resp_cookies` into headers afterward, so covering
    `set-cookie` while cookies are pending fails closed; this also applies to
    cookies set by session callbacks. Explicit final `set-cookie` response
    headers can be signed without pending cookies. Transformations in the server
    after Plug's callbacks (such as Bandit compression) must be disabled when
    covering bytes; no `no-transform` field is injected. Request fields selected
    with `req` retain their captured values and do not establish response
    content integrity.
    """
    @behaviour Plug
    alias RequestSeal.{Body, KeyHandle, Message, TransportFacts}
    alias RequestSeal.Adapter.{Error, Signing}
    alias RequestSeal.Plug.{Delivery, State, Target}

    @doc """
    Validates response signing options once, at plug initialization.

    ## Parameters

      * `opts` - keyword list of the options below. All five are required;
        unknown or duplicate options reject.

    ## Options

      * `:sign` - the signing map. It contains exactly `:label` (signature
        label), `:components` (serialized component Inner List without metadata
        parameters), `:algorithm` (exact supported HTTP signature algorithm),
        `:parameters`, `:digest`, and `:field_schemas` (explicit field schema
        map). `:parameters` contains exactly `:created` and `:alg` (Booleans),
        `:expires_in` (positive seconds or nil, requiring created when present),
        `:nonce` (`:random` or nil), and `:keyid` and `:tag` (bounded strings or
        nil). The adapter generates selected metadata for each signing
        operation. `:digest` is nil or a nonempty unique selection of
        `"sha-256"` and `"sha-512"`; present digests must match those
        algorithms and the retained response body. `req` components bind to the
        captured request; `host` and `tr` components are unsupported. The short
        `t:RequestSeal.signing_spec/0` form is not accepted here.
      * `:signer` - a `RequestSeal.KeyHandle` or an arity-two function signer
        `(algorithm, base)`.
      * `:signing_timeout` - 1..300,000 milliseconds.
      * `:clock` - arity-zero function returning Unix seconds.
      * `:on_failure` - `{:respond, status}` with a final status in 200..599.

    ## Returns

      * keyword list - the validated options.

    Raises `RequestSeal.Adapter.Error` with stage `:sign` and reason
    `:invalid_options` (a missing, unknown, or invalid option),
    `:unsupported_component` (`host` or `tr` components), or `:limit` (the
    component list exceeds its bound).

    ## Examples

        iex> try do
        ...>   RequestSeal.Plug.SignResponse.init(
        ...>     sign: %{label: "res", algorithm: "ed25519", components: ~s[("@status")], expires_in: 60},
        ...>     signer: fn _algorithm, _base -> {:error, :unused} end,
        ...>     signing_timeout: 5_000,
        ...>     clock: fn -> 0 end,
        ...>     on_failure: {:respond, 500}
        ...>   )
        ...> rescue
        ...>   error in RequestSeal.Adapter.Error -> {error.reason, error.stage}
        ...> end
        {:invalid_options, :sign}
    """
    @impl Plug
    def init(opts) do
      case Signing.protect(:plug, :attach, 0, fn ->
             Signing.options(opts, [:sign, :signer, :signing_timeout, :clock, :on_failure])

             Signing.ensure(
               Enum.all?(
                 [:sign, :signer, :signing_timeout, :clock, :on_failure],
                 &Keyword.has_key?(opts, &1)
               ),
               :invalid_options
             )

             Signing.spec!(opts[:sign], related: true)
             Signing.sign_options!(Keyword.take(opts, [:signing_timeout, :clock]))

             Signing.ensure(
               is_function(opts[:signer], 2) or match?(%KeyHandle{}, opts[:signer]),
               :invalid_options
             )

             Signing.ensure(failure?(opts[:on_failure]), :invalid_options)
             opts
           end) do
        {:error, error} -> raise %{error | stage: :sign}
        opts -> opts
      end
    end

    defp failure?({:respond, status}), do: is_integer(status) and status in 200..599
    defp failure?(_), do: false

    @doc """
    Wraps the transport and registers a final `before_send` callback that signs the response.

    The callback signs the status, final response headers, and, when the
    connection state is `:set`, the buffered body, bound to the request in
    `RequestSeal.Plug.capture/1` at the time the callback runs. A covered
    missing `date` header is added from the same sampled `:clock` value as
    `created` and `expires`. Required body coverage needs `conn.state == :set`:
    file and chunked delivery cannot authenticate unretained bytes.
    Status-only streaming signatures are supported without body coverage. The
    transport wrapper is request-local, redacted, and starts no process.

    ## Parameters

      * `conn` - a `Plug.Conn`, normally after `RequestSeal.Plug.Capture`.
      * `opts` - options returned by `init/1`.

    ## Returns

      * `Plug.Conn` - with the wrapped adapter and the signing callback
        appended after all registered callbacks. Absent or nil callback state
        means no callbacks.

    When the response is sent, success appends `signature-input` and
    `signature` (and any generated `content-digest`) to the response headers.
    On failure the `:on_failure` status and an empty unsigned body replace any
    delivery, including file and chunked modes; signature, digest,
    `content-length`, `content-encoding`, `transfer-encoding`, and `trailer`
    headers are removed, and later chunk writes return `{:error, :closed}`.
    Private state's `:error` holds a
    `%RequestSeal.Adapter.Error{stage: :sign, attempt: 1}` with reason:
    `:unsupported_delivery` (malformed callback state, which replaces delivery
    at once; pending `resp_cookies` with `set-cookie` covered; or body
    coverage without `conn.state == :set`), `:unsupported_component` (request
    `@request-target`, `@target-uri`, or `@query` selected with `req`, because
    Plug lacks exact target evidence, or a component the message cannot
    supply), `:not_captured` (no capture), `:invalid_options` (a clock value
    outside 0..253,402,300,799, or a signer whose algorithm differs),
    `:body_unavailable`, `:digest_conflict`, `:invalid_request`, `:limit`, and
    `:signing_failed` (signer or custody failure, or an unexpected exception),
    with the meanings of `RequestSeal.Finch.sign/4`. Meanings:
    `RequestSeal.Adapter.Error`.

    ## Examples

        iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        iex> sign = %{
        ...>   label: "res",
        ...>   algorithm: "ed25519",
        ...>   components: ~s[("@status" "content-type" "content-digest" "@method";req)],
        ...>   parameters: %{created: true, expires_in: 60, nonce: :random, alg: true, keyid: nil, tag: nil},
        ...>   digest: ["sha-256"],
        ...>   field_schemas: %{}
        ...> }
        iex> opts =
        ...>   RequestSeal.Plug.SignResponse.init(
        ...>     sign: sign,
        ...>     signer: handle,
        ...>     signing_timeout: 5_000,
        ...>     clock: fn -> System.system_time(:second) end,
        ...>     on_failure: {:respond, 500}
        ...>   )
        iex> capture =
        ...>   RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: 1_024, read_timeout: 5_000)
        iex> conn =
        ...>   Plug.Test.conn(:get, "https://docs.example.com/guides/1")
        ...>   |> RequestSeal.Plug.Capture.call(capture)
        ...>   |> RequestSeal.Plug.SignResponse.call(opts)
        ...>   |> Plug.Conn.put_resp_content_type("text/plain")
        ...>   |> Plug.Conn.send_resp(200, "guide text")
        iex> {conn.status, Enum.map(conn.resp_headers, &elem(&1, 0)) -- ["cache-control"]}
        {200, ["content-type", "content-digest", "signature-input", "signature"]}
        iex> uncaptured =
        ...>   Plug.Test.conn(:get, "https://docs.example.com/guides/1")
        ...>   |> RequestSeal.Plug.SignResponse.call(opts)
        ...>   |> Plug.Conn.send_resp(200, "guide text")
        iex> {uncaptured.status, uncaptured.resp_body, uncaptured.private.request_seal.error.reason}
        {500, "", :not_captured}
        iex> RequestSeal.Custody.Local.release(handle)
        :ok
    """
    @impl Plug
    def call(conn, opts) do
      conn = %{conn | adapter: Delivery.wrap(conn.adapter)}
      callbacks = Map.get(conn.private, :before_send)
      callbacks = if is_nil(callbacks), do: [], else: callbacks

      if callbacks?(callbacks) do
        # Plug prepends new callbacks; append signing so all transformations run first.
        sign = &before_send(&1, opts)
        conn = Plug.Conn.register_before_send(conn, sign)
        Plug.Conn.put_private(conn, :before_send, callbacks ++ [sign])
      else
        error = Error.new(:unsupported_delivery, :plug, :sign, 1)

        conn
        |> State.error(error)
        |> Plug.Conn.put_private(:before_send, [fn c -> fail_response(c, error, opts) end])
      end
    end

    defp callbacks?([]), do: true
    defp callbacks?([callback | rest]) when is_function(callback, 1), do: callbacks?(rest)
    defp callbacks?(_), do: false

    defp before_send(conn, opts) do
      result =
        Signing.protect(:plug, :sign, 1, fn ->
          input = Signing.spec!(opts[:sign], related: true)
          Signing.ensure(Target.response_supported?(input), :unsupported_component)

          Signing.ensure(
            not Signing.covered?(input, "set-cookie") or map_size(conn.resp_cookies) == 0,
            :unsupported_delivery
          )

          Signing.ensure(
            not Signing.body_required?(input, opts[:sign]) or conn.state == :set,
            :unsupported_delivery
          )

          capture =
            case RequestSeal.Plug.capture(conn) do
              {:ok, capture} -> capture
              :error -> Signing.fail(:not_captured)
            end

          body =
            if conn.state == :set,
              do: Signing.retained(IO.iodata_to_binary(conn.resp_body)),
              else: %Body{state: :unavailable}

          fields = Enum.map(conn.resp_headers, fn {n, v} -> Signing.field(n, v) end)

          {fields, signing_opts} =
            if Signing.covered?(input, "date") and
                 not Enum.any?(fields, &(String.downcase(&1.name) == "date")) do
              now = opts[:clock].()
              Signing.ensure(is_integer(now) and now in 0..253_402_300_799, :invalid_options)

              {fields ++ [Signing.field("date", date!(now))],
               Keyword.put(opts, :clock, fn -> now end)}
            else
              {fields, opts}
            end

          {:ok, message} =
            Message.new(%{
              kind: :response,
              status: conn.status,
              fields: fields,
              trailers: :unavailable,
              body: body,
              related_request: capture.message,
              transport: %TransportFacts{
                http_version: capture.message.transport.http_version,
                tls: capture.message.transport.tls
              }
            })

          Signing.sign(
            message,
            opts[:sign],
            opts[:signer],
            Keyword.take(signing_opts, [:signing_timeout, :clock]),
            related: true
          )
        end)

      case result do
        {:error, %Error{} = error} ->
          fail_response(conn, error, opts)

        %Message{} = signed ->
          %{conn | resp_headers: Enum.map(signed.fields, &{String.downcase(&1.name), &1.value})}
      end
    end

    defp fail_response(conn, error, opts) do
      {:respond, status} = opts[:on_failure]

      case conn.adapter do
        {Delivery, payload} -> Delivery.fail(payload, status)
        # Plug dispatches this callback's failure status and body directly.
        _ -> :ok
      end

      conn = State.error(conn, error)

      %{
        conn
        | status: status,
          resp_body: "",
          resp_headers:
            Enum.reject(conn.resp_headers, fn {n, _} ->
              n in [
                "signature",
                "signature-input",
                "content-digest",
                "repr-digest",
                "content-length",
                "content-encoding",
                "transfer-encoding",
                "trailer"
              ]
            end)
      }
    end

    defp date!(now) do
      {{year, month, day}, {hour, minute, second}} =
        now |> DateTime.from_unix!() |> DateTime.to_naive() |> NaiveDateTime.to_erl()

      weekday =
        Enum.at(~w(Mon Tue Wed Thu Fri Sat Sun), :calendar.day_of_the_week(year, month, day) - 1)

      month_name = Enum.at(~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec), month - 1)

      "#{weekday}, #{pad(day)} #{month_name} #{year} #{pad(hour)}:#{pad(minute)}:#{pad(second)} GMT"
    end

    defp pad(n), do: n |> Integer.to_string() |> String.pad_leading(2, "0")
  end
end
