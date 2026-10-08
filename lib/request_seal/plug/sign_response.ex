if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.SignResponse do
    @moduledoc """
    Sign final buffered response bytes in a Plug `before_send` callback.

    Requires all five options: `:sign` (the signing map described below),
    `:signer` (caller signer or key handle), `:signing_timeout` (1..300,000 ms),
    `:clock` (arity zero returning Unix seconds), and `:on_failure`
    (`{:respond, status}` with final status in 200..599). `req` components bind
    to the captured request; `tr` components are unsupported. A covered missing `date` is added
    before signing from the same sampled `:clock` as `created` and `expires`.
    Request `@request-target`, `@target-uri`, and `@query` coverage
    rejects with `:unsupported_component` because Plug lacks exact target evidence.
    Required body coverage needs `conn.state == :set`:
    file/chunked delivery cannot authenticate unretained bytes. Status-only
    streaming signatures are supported without body coverage.

    The signing callback runs after other registered callbacks, including callbacks
    registered earlier that mutate signed facts. Their changes are included before
    signing. Absent or nil callback state means no callbacks; malformed callback
    state replaces delivery with a bounded `:unsupported_delivery` failure.
    Plug merges
    `resp_cookies` into headers afterward; if response coverage includes
    `set-cookie` and cookies are pending, signing fails closed with
    `:unsupported_delivery`. This also applies to cookies set by session callbacks.
    Explicit final `set-cookie` response headers can be signed without pending
    cookies. Transformations in the server after Plug's callbacks (such as Bandit
    compression) must be disabled when covering bytes; no `no-transform` field
    is injected.
    On failure the requested status and empty unsigned body replace any delivery,
    including file and chunked modes. Later chunk writes return `{:error, :closed}`.
    A redacted request-local transport wrapper enforces that replacement without
    starting a process. Private state's `error` holds the bounded failure.

    The signing map contains exactly `:label` (signature label), `:components`
    (serialized component Inner List without metadata parameters), `:algorithm`
    (exact supported HTTP signature algorithm), `:parameters`, `:digest`, and
    `:field_schemas` (explicit field schema map). `:parameters` contains exactly
    `:created` and `:alg` (Booleans), `:expires_in` (positive seconds or nil,
    requiring created when present), `:nonce` (`:random` or nil), and `:keyid`
    and `:tag` (bounded strings or nil). The adapter generates selected metadata
    for each signing operation. `:digest` is nil or a nonempty unique selection
    of `"sha-256"` and `"sha-512"`; present digests must match those algorithms
    and the retained response body. Request fields selected with `req` retain
    their captured values and do not establish response content integrity.
    """
    @behaviour Plug
    alias RequestSeal.{Body, KeyHandle, Message, TransportFacts}
    alias RequestSeal.Adapter.{Error, Signing}
    alias RequestSeal.Plug.{Delivery, State, Target}

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
