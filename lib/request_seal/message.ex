defmodule RequestSeal.Message do
  @moduledoc """
  Lossless HTTP message values for later component derivation.

  A message is a request or a response holding ordered `RequestSeal.FieldOccurrence`
  values, trailers, a `RequestSeal.Body` availability snapshot, and
  `RequestSeal.TransportFacts` declarations. URI octets, percent-encoding, field
  name case, and field value bytes are kept exactly as supplied; no normalization
  is used to make inputs agree. Header and trailer sections never mix.

  Trailers can be an observed list, `:unavailable`, or `:pending` while the body
  is streaming. A streaming body describes unread caller-owned content, not
  transport progress: a completed capture may have known trailers while its
  content stream remains unread.

  A request's `:scheme` and `:authority` are caller-declared authoritative origin
  facts, never inferred from Host or Forwarded. A missing origin is preserved as
  `nil`; a later component rule decides whether it is required.

  Use `request/5` and `response/4` to build common messages from a URL, headers,
  and body bytes, and `new/1` for full control over every attribute. `validate/1`
  applies the same checks to directly constructed or modified structs. Success
  establishes a well-formed value, not HTTP framing, component availability,
  cryptographic validity, or authentication. Signature-base derivation is provided by `RequestSeal.SignatureBase`.
  Generic signing and verification are provided by `RequestSeal`; optional Req/Finch
  adapters, Plug integration (also used by Phoenix), Ash scope mapping, and Web Bot Auth protocol-00
  are implemented. Other named application profiles use `RequestSeal.Profile`
  in extension packages. This module starts no process and reads no stream.
  Default inspection is redacted.
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

  @doc """
  Construct a request or response from an attribute map and validate it with `validate/1`.

  ## Parameters

    * `attrs` - a plain map (not a struct) using only the keys below. Unknown keys
      reject; no value is normalized.

  Keys for both kinds:

    * `:kind` (required) - `:request` or `:response`.
    * `:fields` (required) - ordered list of `RequestSeal.FieldOccurrence` values
      with section `:headers`. Field maps, tuples, and invalid nested structs reject.
    * `:trailers` (required) - ordered list of `:trailers` occurrences (an observed
      empty list is valid), `:unavailable`, or `:pending`. `:pending` requires a
      `:streaming` body.
    * `:body` (required) - a `RequestSeal.Body`.
    * `:transport` (required) - a `RequestSeal.TransportFacts`.

  Fields and trailers together are bounded to 1,024 occurrences and 1,048,576 bytes
  of names and values.

  Request keys (`:status` and `:related_request` must be absent or `nil`):

    * `:method` - an HTTP token of 1..256 bytes, case-sensitive. `"CONNECT"` requires
      the `:authority` target form.
    * `:raw_target` - 1..16,384 bytes of RFC 3986 URI characters and well-formed
      percent escapes, kept unchanged. Fragments, userinfo, malformed escapes, and
      controls reject.
    * `:target_form` - `:origin` (starts with `/`), `:absolute` (requires a scheme
      and authority), `:authority` (`CONNECT` only, with a port), or `:asterisk`
      (exactly `*`, `OPTIONS` only). Origin and absolute paths and queries cannot
      contain `[` or `]`.
    * `:scheme` and `:authority` - optional pair; supply both or neither. Scheme is
      an RFC 3986 scheme of at most 64 bytes; authority is at most 1,024 bytes with
      an optional decimal port of at most five digits in 0..65535. When supplied,
      an absolute target must match the declared scheme and authority byte for
      byte, and an authority-form target must equal the declared authority.

  Bracketed hosts follow [RFC 3986 Section 3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2):
  only IPv6address or IPvFuture literals accept. Bracketed IPv4, shortened,
  decimal or hexadecimal IPv4 forms, and zone identifiers (including `%25`)
  reject. IPv6 with a full dotted-decimal IPv4 tail remains valid.
  The IPvFuture version flag accepts `[vV]` case-insensitively because quoted
  ABNF literals are case-insensitive under
  [RFC 5234 Section 2.3](https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3).

  Response keys (`:method`, `:raw_target`, `:target_form`, `:scheme`, and
  `:authority` must be absent or `nil`):

    * `:status` - integer in 100..599.
    * `:related_request` - optional valid request (not a response); absent
      context remains `nil`.

  ## Returns

    * `{:ok, %RequestSeal.Message{}}` - the validated value, exactly as supplied.
    * `{:error, %RequestSeal.Message.Error{}}` - reasons this function can return:
      `:invalid_message` (not a map, missing or unknown keys, kind, method, target,
      origin, status, related request, or `:pending` trailers without a streaming
      body), `:invalid_field` (an invalid or misplaced field or trailer occurrence,
      or the combined bound exceeded), `:invalid_body`, and `:invalid_transport`.
      Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :unavailable})
      iex> {:ok, transport} = RequestSeal.TransportFacts.new(%{})
      iex> {:ok, request} = RequestSeal.Message.new(%{kind: :request, method: "GET", raw_target: "/a%2Fb?", target_form: :origin, fields: [], trailers: :unavailable, body: body, transport: transport})
      iex> {request.raw_target, request.body.state, request.scheme}
      {"/a%2Fb?", :unavailable, nil}
      iex> RequestSeal.Message.new(%{kind: :request})
      {:error, %RequestSeal.Message.Error{reason: :invalid_message}}

  An absolute target must agree with the declared origin byte for byte:

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :unavailable})
      iex> {:ok, transport} = RequestSeal.TransportFacts.new(%{})
      iex> attrs = %{kind: :request, method: "GET", raw_target: "https://docs.example/reports/7", target_form: :absolute, scheme: "https", authority: "docs.example", fields: [], trailers: :unavailable, body: body, transport: transport}
      iex> {:ok, _request} = RequestSeal.Message.new(attrs)
      iex> RequestSeal.Message.new(%{attrs | authority: "DOCS.example"})
      {:error, %RequestSeal.Message.Error{reason: :invalid_message}}

  A response with pending trailers needs a streaming body:

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: "build 118 passed"})
      iex> {:ok, transport} = RequestSeal.TransportFacts.new(%{http_version: :http2})
      iex> attrs = %{kind: :response, status: 200, fields: [], trailers: [], body: body, transport: transport}
      iex> {:ok, response} = RequestSeal.Message.new(attrs)
      iex> response.status
      200
      iex> RequestSeal.Message.new(%{attrs | trailers: :pending})
      {:error, %RequestSeal.Message.Error{reason: :invalid_message}}
  """
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
  Build an origin-form request from an absolute HTTP(S) URL, ordered headers, and exact body bytes.

  The scheme and authority are ASCII-lowercased; a port numerically equal to the
  scheme default (HTTPS 443, HTTP 80) is omitted, matching Finch and Req. Path and
  query bytes, including percent escapes, are preserved. An absent path becomes
  `/`; an empty query retains its `?`. Transport declarations stay unknown and
  trailers `:unavailable`. The result passes through `new/1`.

  ## Parameters

    * `method` - HTTP token of 1..256 bytes, kept as given (no case change).
    * `url` - valid UTF-8 binary of at most 17,480 bytes: `http://` or `https://`
      (scheme case-insensitive), a nonempty authority, then an optional path and
      query. Any `#` rejects. The authority and resulting target must satisfy
      `new/1`; userinfo rejects.
    * `headers` - ordered list of at most 1,024 `{name, value}` binary tuples, each
      becoming a `:headers` `RequestSeal.FieldOccurrence` with `:caller`
      provenance. Name case, order, and repeats remain unchanged.
    * `bytes` - exact body bytes retained in a `RequestSeal.Body`, or `nil` for
      empty content. At most 1,048,576 bytes (the body's default retention limit).

  ## Options

    * `:digest` - `nil` (default) or a nonempty unique list of `"sha-256"` and/or
      `"sha-512"`. A list appends one `content-digest` header computed by
      `RequestSeal.Digest.compute/3` over the exact bytes, in list order. Existing
      Content-Digest headers (any case) reject when generating a digest; omit the
      option to keep caller-supplied headers.

  ## Returns

    * `{:ok, %RequestSeal.Message{kind: :request, target_form: :origin}}`.
    * `{:error, %RequestSeal.Message.Error{}}` - reasons this function can return:
      `:invalid_message` (unknown or duplicate options, an invalid `:digest` value,
      an existing Content-Digest with `:digest`, a URL that is not absolute
      HTTP(S), or a method, authority, or target that `new/1` rejects),
      `:invalid_field` (a header that is not a binary pair, an invalid name or
      value, more than 1,024 headers, or the combined field bound), and
      `:invalid_body` (bytes not a binary or `nil`, or over the retention limit).
      Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, message} = RequestSeal.Message.request("post", "https://example.com:8443/a%2Fb?", [{"X", "one"}, {"X", "two"}], nil)
      iex> {message.method, message.authority, message.raw_target, message.body.bytes}
      {"post", "example.com:8443", "/a%2Fb?", ""}
      iex> Enum.map(message.fields, &{&1.name, &1.value})
      [{"X", "one"}, {"X", "two"}]

  Default ports are dropped and a digest header can be added:

      iex> {:ok, message} = RequestSeal.Message.request("POST", "HTTPS://Telemetry.Example:443/ingest", [{"Content-Type", "application/json"}], ~s({"hello": "world"}), digest: ["sha-256"])
      iex> {message.scheme, message.authority, message.raw_target}
      {"https", "telemetry.example", "/ingest"}
      iex> Enum.map(message.fields, &{&1.name, &1.value})
      [{"Content-Type", "application/json"}, {"content-digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}]
      iex> RequestSeal.Message.request("GET", "https://example.org/page#top", [], nil)
      {:error, %RequestSeal.Message.Error{reason: :invalid_message}}
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
  Build a response with ordered headers and retained bytes.

  Status, fields, body, and related request pass through `new/1` unchanged.
  Transport declarations stay unknown and trailers `:unavailable`.

  ## Parameters

    * `status` - integer in 100..599.
    * `headers` - ordered list of at most 1,024 `{name, value}` binary tuples, as in
      `request/5`.
    * `bytes` - exact body bytes, or `nil` for empty content; at most 1,048,576 bytes.

  ## Options

    * `:digest` - same as in `request/5`: `nil` (default) or a nonempty unique list
      of `"sha-256"` and/or `"sha-512"` that appends a `content-digest` header.
    * `:request` - a valid request `RequestSeal.Message` to link as
      `:related_request` for components with the `req` parameter; default `nil`.
      No linkage is inferred.

  ## Returns

    * `{:ok, %RequestSeal.Message{kind: :response}}`.
    * `{:error, %RequestSeal.Message.Error{}}` - reasons this function can return:
      `:invalid_message` (unknown or duplicate options, an invalid `:digest` value,
      an existing Content-Digest with `:digest`, a status outside 100..599, or a
      `:request` value that is not a valid request), `:invalid_field` (as in
      `request/5`), and `:invalid_body` (bytes not a binary or `nil`, or over the
      retention limit). Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, request} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
      iex> {:ok, response} = RequestSeal.Message.response(204, [], nil, request: request)
      iex> {response.status, response.related_request == request, response.body.bytes}
      {204, true, ""}
      iex> RequestSeal.Message.response(200, [], nil, request: response)
      {:error, %RequestSeal.Message.Error{reason: :invalid_message}}
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

  @doc """
  Validate all nested values, states, bounds, targets, and request linkage.

  Applies every rule listed for `new/1` to an existing struct, including one built
  or modified directly. Checks run in order: struct shape, body, transport, kind
  rules, header fields, then trailers; the first failure is returned.

  ## Parameters

    * `message` - any term; only a `RequestSeal.Message` struct can pass.

  ## Returns

    * `:ok` - the value is well formed. This says nothing about HTTP framing,
      component availability, cryptographic validity, or authentication.
    * `{:error, %RequestSeal.Message.Error{}}` - reasons this function can return:
      `:invalid_message`, `:invalid_field`, `:invalid_body`, and
      `:invalid_transport`, with the same causes as in `new/1`.
      Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, request} = RequestSeal.Message.request("GET", "https://example.com/orders/17", [], nil)
      iex> RequestSeal.Message.validate(request)
      :ok
      iex> RequestSeal.Message.validate(%{request | method: "GET ORDERS"})
      {:error, %RequestSeal.Message.Error{reason: :invalid_message}}
      iex> RequestSeal.Message.validate(%{request | transport: :tls})
      {:error, %RequestSeal.Message.Error{reason: :invalid_transport}}
  """
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
