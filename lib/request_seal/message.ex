defmodule RequestSeal.Message do
  @moduledoc """
  Lossless HTTP message values for later component derivation.

  `new/1` accepts a map. Required for both kinds: `:kind` (`:request` or
  `:response`), ordered `:fields` of `RequestSeal.FieldOccurrence`, `:trailers`,
  a `RequestSeal.Body`, and `:transport` (`RequestSeal.TransportFacts`). Trailers
  are an ordered list (including an observed empty list), `:unavailable`, or
  `:pending` while the body is streaming. A streaming body describes unread
  caller-owned content, not transport progress: a completed capture may have
  known trailers while its content stream remains unread. Header and trailer
  sections never mix.
  Total fields and trailers are bounded to 1,024 occurrences and 1,048,576 bytes
  of names and values. Field maps, tuples, and invalid nested structs reject.

  Requests require a token `:method` (at most 256 bytes), `:raw_target` (at most
  16,384 bytes), and explicit `:target_form`: `:origin`, `:absolute`, `:authority`
  (CONNECT with a port), or `:asterisk` (OPTIONS). URI octets and percent-encoding
  remain unchanged; fragments, userinfo, malformed escapes, and controls reject.
  Absolute targets require a scheme and authority. Optional `:scheme` and
  `:authority` are a pair of caller-declared authoritative origin facts, never
  inferred from Host or Forwarded. Scheme is bounded to 64 bytes; authority to
  1,024 bytes. Ports are decimal numbers in 0..65535. Missing origin is preserved
  as `nil`; a later component rule decides whether it is required. When supplied,
  an absolute target must match the declared scheme and authority byte for byte;
  a CONNECT target must match the declared authority. No normalization is used
  to reconcile conflicting declarations.

  Bracketed hosts follow [RFC 3986 Section 3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2):
  only IPv6address or IPvFuture literals accept. Bracketed IPv4, shortened,
  decimal or hexadecimal IPv4 forms, and zone identifiers (including `%25`)
  reject. IPv6 with a full dotted-decimal IPv4 tail remains valid.
  The IPvFuture version flag accepts `[vV]` case-insensitively because quoted
  ABNF literals are case-insensitive under
  [RFC 5234 Section 2.3](https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3).

  Responses require integer `:status` in 100..599. Optional `:related_request`
  is a validated request (not another response); absent context remains `nil`.
  Request-only fields must be `nil` on responses. Requests cannot carry status
  or another related request. Unknown options reject; no normalization occurs.

  `validate/1` applies the same checks to directly constructed or modified structs.
  Success establishes a well-formed value, not HTTP framing, component availability,
  cryptographic validity, or authentication. Signature-base derivation is provided by `RequestSeal.SignatureBase`.
  Generic signing and verification are provided by `RequestSeal`; optional Req/Finch
  adapters, Plug integration (also used by Phoenix), Ash scope mapping, and Web Bot Auth protocol-00
  are implemented. Other named application profiles use `RequestSeal.Profile`
  in extension packages. This module starts no process and reads no stream.
  Default inspection is redacted.

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :unavailable})
      iex> {:ok, transport} = RequestSeal.TransportFacts.new(%{})
      iex> {:ok, request} = RequestSeal.Message.new(%{kind: :request, method: "GET", raw_target: "/a%2Fb?", target_form: :origin, fields: [], trailers: :unavailable, body: body, transport: transport})
      iex> {request.raw_target, request.body.state, request.scheme}
      {"/a%2Fb?", :unavailable, nil}
      iex> RequestSeal.Message.validate(request)
      :ok
      iex> RequestSeal.Message.new(%{kind: :request})
      {:error, %RequestSeal.Message.Error{reason: :invalid_message}}
  """
  alias RequestSeal.{Body, FieldOccurrence, TransportFacts}
  alias RequestSeal.Message.Validation
  @derive {Inspect, only: []}
  defstruct [
    :kind,
    :method,
    :raw_target,
    :target_form,
    :scheme,
    :authority,
    :status,
    :fields,
    :trailers,
    :body,
    :related_request,
    :transport
  ]

  @type t :: %__MODULE__{
          kind: :request | :response,
          method: binary() | nil,
          raw_target: binary() | nil,
          target_form: :origin | :absolute | :authority | :asterisk | nil,
          scheme: binary() | nil,
          authority: binary() | nil,
          status: 100..599 | nil,
          fields: [FieldOccurrence.t()],
          trailers: [FieldOccurrence.t()] | :unavailable | :pending,
          body: Body.t(),
          related_request: t() | nil,
          transport: TransportFacts.t()
        }

  @doc "Construct a request or response; return a bounded error on invalid input."
  @spec new(map()) :: {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def new(attrs),
    do:
      Validation.construct(
        attrs,
        __MODULE__,
        [:kind, :fields, :trailers, :body, :transport],
        :invalid_message
      )

  @doc """
  Build a request from an absolute HTTP(S) URL, ordered headers, and exact body bytes.

  Scheme and host are lowercased; default ports (HTTPS 443 and HTTP 80)
  are omitted, matching Finch and Req. Percent escapes and query bytes
  are preserved. An absent path becomes `/`; an empty query retains its `?`.
  Header case, order, and repeats remain unchanged. `nil` and `""` both retain
  empty content. Transport declarations stay unknown and trailers unavailable.
  All values pass through `new/1`, including its 1 MiB body retention limit.

  The only option is `:digest`, default `nil`: a nonempty unique list of
  `"sha-256"` and/or `"sha-512"` adds Content-Digest over the exact bytes.
  Existing Content-Digest headers reject when generating a digest; omit the
  option to preserve caller-supplied headers. Invalid options return
  `:invalid_message`; invalid headers and bodies retain their existing errors.

      iex> {:ok, message} = RequestSeal.Message.request("post", "https://example.com:8443/a%2Fb?", [{"X", "one"}, {"X", "two"}], nil)
      iex> {message.method, message.authority, message.raw_target, message.body.bytes}
      {"post", "example.com:8443", "/a%2Fb?", ""}
      iex> Enum.map(message.fields, &{&1.name, &1.value})
      [{"X", "one"}, {"X", "two"}]
  """
  @spec request(binary(), binary(), [{binary(), binary()}], binary() | nil, keyword()) ::
          {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def request(method, url, headers, bytes, opts \\ []) do
    with :ok <- builder_options(opts, [:digest]),
         {:ok, scheme, authority, target} <- request_parts(url),
         {:ok, attrs} <- builder_parts(headers, bytes, opts) do
      new(
        Map.merge(attrs, %{
          kind: :request,
          method: method,
          scheme: scheme,
          authority: authority,
          raw_target: target,
          target_form: :origin
        })
      )
    end
  end

  @doc """
  Build a response with ordered headers and retained bytes (`nil` means empty).

  Accepts the same `:digest` option as `request/5`. Optional `:request` links a
  validated request for components with `req`; no linkage is inferred. Status,
  fields, body, and related request pass through `new/1` unchanged.

      iex> {:ok, request} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
      iex> {:ok, response} = RequestSeal.Message.response(204, [], nil, request: request)
      iex> {response.status, response.related_request == request, response.body.bytes}
      {204, true, ""}
  """
  @spec response(100..599, [{binary(), binary()}], binary() | nil, keyword()) ::
          {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def response(status, headers, bytes, opts \\ []) do
    with :ok <- builder_options(opts, [:digest, :request]),
         {:ok, attrs} <- builder_parts(headers, bytes, opts) do
      new(
        Map.merge(attrs, %{
          kind: :response,
          status: status,
          related_request: Keyword.get(opts, :request)
        })
      )
    end
  end

  defp builder_options(opts, allowed) do
    if is_list(opts) and Keyword.keyword?(opts) and
         length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) and
         Enum.all?(Keyword.keys(opts), &(&1 in allowed)),
       do: :ok,
       else: Validation.error(:invalid_message)
  end

  defp request_parts(url) when is_binary(url) and byte_size(url) <= 17_480 do
    # Preserve path/query octets; normalize only the transport origin.
    if String.valid?(url) and not String.contains?(url, "#") do
      case Regex.run(~r/\A((?i:https?)):\/\/([^\/?]+)((?:[\/?].*)?)\z/, url) do
        [_, scheme, authority, tail] ->
          scheme = String.downcase(scheme)
          authority = String.downcase(authority, :ascii)
          default_port = if scheme == "https", do: 443, else: 80

          authority =
            case Regex.run(~r/\A(\[[^\]]+\]|[^:]+):([0-9]+)\z/, authority) do
              [_, host, port] ->
                if String.to_integer(port) == default_port, do: host, else: authority

              _ ->
                authority
            end

          target = if tail == "" or String.starts_with?(tail, "?"), do: "/" <> tail, else: tail
          {:ok, scheme, authority, target}

        _ ->
          Validation.error(:invalid_message)
      end
    else
      Validation.error(:invalid_message)
    end
  end

  defp request_parts(_), do: Validation.error(:invalid_message)

  defp builder_parts(headers, bytes, opts) do
    with {:ok, body} <- builder_body(bytes),
         {:ok, fields} <- builder_fields(headers, []),
         {:ok, fields} <- builder_digest(fields, body, Keyword.get(opts, :digest)),
         {:ok, transport} <- TransportFacts.new(%{}) do
      {:ok, %{fields: fields, body: body, trailers: :unavailable, transport: transport}}
    end
  end

  defp builder_body(nil), do: builder_body("")
  defp builder_body(bytes), do: Body.new(%{state: :retained, bytes: bytes})

  defp builder_fields([], fields), do: {:ok, Enum.reverse(fields)}

  defp builder_fields([{name, value} | rest], fields) when length(fields) < 1024 do
    with {:ok, field} <- FieldOccurrence.new(%{name: name, value: value, section: :headers}) do
      builder_fields(rest, [field | fields])
    end
  end

  defp builder_fields(_, _), do: Validation.error(:invalid_field)

  defp builder_digest(fields, _, nil), do: {:ok, fields}

  defp builder_digest(fields, body, algorithms) do
    if algorithms in [["sha-256"], ["sha-512"], ["sha-256", "sha-512"], ["sha-512", "sha-256"]] and
         not Enum.any?(fields, &(String.downcase(&1.name) == "content-digest")) do
      with {:ok, digest} <- RequestSeal.Digest.compute(body, algorithms),
           {:ok, wire} <- RequestSeal.Digest.serialize(digest),
           {:ok, field} <-
             FieldOccurrence.new(%{name: "content-digest", value: wire, section: :headers}) do
        {:ok, fields ++ [field]}
      else
        _ -> Validation.error(:invalid_body)
      end
    else
      Validation.error(:invalid_message)
    end
  end

  @doc "Validate all nested values, states, bounds, targets, and request linkage."
  @spec validate(term()) :: :ok | {:error, RequestSeal.Message.Error.t()}
  def validate(%__MODULE__{} = message) do
    with true <- Validation.exact_struct?(message, __MODULE__),
         :ok <- Body.validate(message.body),
         :ok <- TransportFacts.validate(message.transport),
         true <- kind_valid?(message),
         {:ok, count, bytes} <- fields(message.fields, :headers, 0, 0),
         {:ok, _, _} <- trailers(message, count, bytes) do
      :ok
    else
      {:error, _} = error -> error
      _ -> Validation.error(:invalid_message)
    end
  end

  def validate(_), do: Validation.error(:invalid_message)

  defp kind_valid?(%{kind: :request, status: nil, related_request: nil} = m),
    do:
      Validation.token?(m.method, 256) and origin_valid?(m.scheme, m.authority) and
        target_valid?(m)

  defp kind_valid?(%{
         kind: :response,
         method: nil,
         raw_target: nil,
         target_form: nil,
         scheme: nil,
         authority: nil,
         status: status,
         related_request: request
       }),
       do: is_integer(status) and status in 100..599 and related_valid?(request)

  defp kind_valid?(_), do: false

  defp related_valid?(nil), do: true
  defp related_valid?(%__MODULE__{kind: :request} = request), do: validate(request) == :ok
  defp related_valid?(_), do: false
  defp origin_valid?(nil, nil), do: true

  defp origin_valid?(scheme, authority),
    do: Validation.scheme?(scheme) and Validation.authority?(authority)

  defp target_valid?(%{raw_target: raw} = m) when is_binary(raw) and byte_size(raw) in 1..16_384,
    do:
      Validation.uri_bytes?(raw) and form_valid?(m.target_form, m.method, raw) and
        target_origin_valid?(m)

  defp target_valid?(_), do: false
  defp form_valid?(:authority, "CONNECT", raw), do: Validation.authority?(raw, true)
  defp form_valid?(_, "CONNECT", _), do: false
  defp form_valid?(:asterisk, "OPTIONS", "*"), do: true
  defp form_valid?(:origin, _, "/" <> _ = raw), do: path_query_valid?(raw)

  defp form_valid?(:absolute, _, raw) do
    case Regex.run(~r/\A([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?]+)((?:[\/?].*)?)\z/, raw) do
      [_, scheme, authority, tail] ->
        Validation.scheme?(scheme) and Validation.authority?(authority) and
          path_query_valid?(tail)

      _ ->
        false
    end
  end

  defp form_valid?(_, _, _), do: false

  defp target_origin_valid?(%{scheme: nil, authority: nil}), do: true

  defp target_origin_valid?(%{target_form: :authority, raw_target: raw, authority: authority}),
    do: raw == authority

  defp target_origin_valid?(%{
         target_form: :absolute,
         raw_target: raw,
         scheme: scheme,
         authority: authority
       }) do
    case Regex.run(~r/\A([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?]+)/, raw) do
      [_, ^scheme, ^authority] -> true
      _ -> false
    end
  end

  defp target_origin_valid?(_), do: true

  defp path_query_valid?(raw), do: :binary.match(raw, ["[", "]"]) == :nomatch

  defp fields([], _, count, bytes), do: {:ok, count, bytes}

  defp fields([%FieldOccurrence{section: section} = field | rest], section, count, bytes)
       when count < 1024 do
    with :ok <- FieldOccurrence.validate(field),
         total = bytes + byte_size(field.name) + byte_size(field.value),
         true <- total <= 1_048_576 do
      fields(rest, section, count + 1, total)
    else
      _ -> Validation.error(:invalid_field)
    end
  end

  defp fields(_, _, _, _), do: Validation.error(:invalid_field)

  defp trailers(%{trailers: :unavailable}, count, bytes), do: {:ok, count, bytes}

  defp trailers(%{trailers: :pending, body: %Body{state: :streaming}}, count, bytes),
    do: {:ok, count, bytes}

  defp trailers(%{trailers: :pending}, _, _), do: Validation.error(:invalid_message)

  defp trailers(%{trailers: trailers}, count, bytes),
    do: fields(trailers, :trailers, count, bytes)
end
