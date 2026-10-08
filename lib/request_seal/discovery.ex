defmodule RequestSeal.Discovery do
  # SSL is optional: the consuming application declares and starts it.
  @compile {:no_warn_undefined, :ssl}
  @moduledoc """
  Explicit bounded HTTPS discovery of HTTP Message Signatures Directories, JWKS
  and Client ID Metadata Documents. Construct a `Discovery.Source` from trusted
  caller configuration. A message/key ID never defines a URL to fetch.

  `fetch/2` performs one discovery operation with no cache. Options are `:timeout`
  (1–300,000 milliseconds, capped by the source timeout) and `:clock` (arity-zero
  Unix-seconds function, default system time). Unknown/duplicate options reject.
  The caller starts SSL; the library starts no application, listener, store,
  timer or background refresh. A monitored worker enforces a single absolute
  deadline across DNS, TLS, redirects and CIMD's optional JWKS subresource, and
  terminates socket owners on caller death or timeout.

  Source policy controls exact private-address exceptions, redirects and resource
  limits. Every address in a DNS response is vetted; TLS connects by tuple and
  checks its connected peer. Responses require HTTP 200 and the selected media
  type; framing rejects ambiguous Content-Length/Transfer-Encoding. Trailer
  signatures cannot establish a proof. Gzip is expanded under a separate bound.
  Content-coding tokens are case-insensitive; `x-gzip` is accepted as gzip per
  RFC 9110 Section 8.4.1.3. Unknown or stacked codings reject.

  Required public JWK members produce RFC 7638/8037 SHA-256 key IDs. A supplied
  `kid` must equal that value by default. Explicit `Source.key_id: :directory`
  requires unique printable directory-assigned IDs while retaining thumbprints
  for identity, revocation and cache removal; private material and malformed keys reject the
  entire set. HTTP `alg` tokens map to the JOSE restriction held by `PublicKey`.
  Keys whose use/operation restrictions forbid verification, and not-yet-valid,
  expired or revoked keys, are not resolvable. Duplicate IDs reject among eligible
  entries only. Directory sources require thumbprint mode. Directory
  signatures use the existing `RequestSeal.verify/3` contract to bind `@authority;req`, digest, created/expires, key ID and tag.
  Directory proof means cryptographic possession, never principal attribution.
  Proof selection uses the `directory` label or a directory-tagged member whose
  key ID names a published directory key. Unrelated labels are ignored; missing
  or invalid selected members reject.

  `resolver/2` bridges a snapshot or `{cache, source}` to `Policy.key_resolver`.
  It accepts only `algorithms: [...]`, ignores label/tag and returns only
  `{:ok, %{algorithm: ..., key: ...}}` or `:error`. A key ID never selects a URL.
  `Discovery.Cache` is an optional caller-started bounded cache with explicit
  refresh/removal/invalidation; it never serves stale keys.

  The generic resolver bridge evaluates cache freshness and key expiry with the
  cache's configured clock; snapshot resolution uses system wall time. This preserves
  the generic caller's explicit clock policy. Named profiles enforce their own
  key/proof validity clock independently of request-freshness policy.

  Web Bot Auth protocol-00 Appendix C.4 states: "A verifier should not fetch the
  directory for every request." Freshness follows `Cache-Control: max-age` before
  `Expires`, accounting for `Date` and `Age` under RFC 9111. Without either
  freshness field, the default is 300 seconds, caller-configurable via `min_ttl`.
  Invalid or past `Expires` is immediately stale. `max_ttl`, key/signature expiry,
  and no-cache/no-store still bound freshness.
  Appendix C.5 states: "Negative cache entries should expire after no more than
  five minutes." Accordingly, `negative_ttl` cannot exceed 300 seconds.
  It also states: "Network failures, TLS failures, and 5xx responses should be
  treated as transient unless local policy says otherwise." This adapter marks
  5xx `:unexpected_status` retryable and 4xx non-retryable; retry scheduling and
  decisions remain caller-owned.

  Sources: [Web Bot Auth protocol-00](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html),
  [CIMD-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html),
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html),
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html),
  [RFC 9110 Section 8.4.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1.3),
  [RFC 9111 Section 4.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1),
  [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html).
  """
  alias RequestSeal.{PublicKey, Policy, SignatureFields, StructuredFields}
  alias RequestSeal.Crypto.Algorithm

  alias RequestSeal.Discovery.{
    Source,
    Support,
    Transport,
    HTTP1,
    Error,
    KeySet,
    Resolution,
    Cache
  }

  import Support, only: [ensure: 2]

  @doc "Fetch a configured source once under a cancellable absolute deadline."
  @spec fetch(Source.t(), keyword()) :: {:ok, KeySet.t()} | {:error, Error.t()}
  def fetch(source, opts \\ []) do
    Support.safe(fn ->
      Source.validate!(source)
      Support.options(opts, [:timeout, :clock])
      timeout = Keyword.get(opts, :timeout, source.timeout)
      ensure(is_integer(timeout) and timeout in 1..300_000, :invalid_options)
      clock = Keyword.get(opts, :clock, fn -> System.system_time(:second) end)
      Support.clock(clock)

      Support.run(min(timeout, source.timeout), fn deadline ->
        fetch_source(source, clock, deadline)
      end)
    end)
  end

  @doc "Build a Policy resolver using source-selected IDs and an algorithm allowlist."
  @spec resolver(KeySet.t() | {GenServer.server(), Source.t()}, keyword()) :: (map() -> term())
  def resolver(input, opts) do
    valid =
      Support.safe(fn ->
        Support.options(opts, [:algorithms])
        algorithms = Keyword.get(opts, :algorithms)

        ensure(
          is_list(algorithms) and length(algorithms) in 1..64 and
            Enum.all?(algorithms, &SignatureFields.algorithm?/1),
          :invalid_options
        )

        {:ok, algorithms}
      end)

    fn request ->
      case valid do
        {:ok, algorithms} ->
          result =
            case {input, request} do
              {%KeySet{} = set, %{keyid: keyid}} ->
                KeySet.lookup(set, keyid, algorithms)

              {{cache, %Source{} = source}, %{keyid: keyid}} ->
                Cache.resolve(cache, source, keyid, algorithms: algorithms)

              _ ->
                :error
            end

          case result do
            {:ok, %Resolution{key: key, algorithm: algorithm}} ->
              {:ok, %{key: key, algorithm: algorithm}}

            _ ->
              :error
          end

        _ ->
          :error
      end
    end
  end

  # Returns unproven body keys for bounded-body tests and measurements.
  # Directory possession proof requires fetch/2 and its signed response.
  @doc false
  def parse_body(bytes, source, now) do
    Support.safe(fn ->
      Source.validate!(source)
      ensure(source.type in [:directory, :jwks_uri], :invalid_source)

      ensure(
        not (source.type == :directory and source.require_signed_directory),
        :directory_unsigned
      )

      ensure(is_binary(bytes), :invalid_response)
      ensure(byte_size(bytes) <= source.max_bytes, :limit)
      ensure(is_integer(now) and now in 0..999_999_999_999_999, :invalid_options)
      document = body_document(bytes, source)
      origin = Source.origin(URI.parse(source.location))
      {:ok, keys(document, source, origin, source.location, now)}
    end)
  end

  defp body_document(bytes, source) do
    ensure(is_binary(bytes), :invalid_response)

    ceiling =
      if source.type == :cimd,
        do: min(source.max_decoded_bytes, 5120),
        else: source.max_decoded_bytes

    ensure(byte_size(bytes) <= ceiling, :limit)
    json(bytes)
  end

  defp fetch_source(source, clock, deadline) do
    uri = Source.url!(source.location)
    {fields, message, location, decoded} = resource(uri, source, deadline, 0)
    now = Support.clock(clock)
    expires = expiry(fields, source, now)

    {document, key_message, key_fields, location, expires, key_bytes} =
      case source.type do
        :cimd ->
          doc = body_document(decoded, source)
          ensure(is_map(doc) and doc["client_id"] == source.location, :client_id_mismatch)

          ensure(
            not (Map.has_key?(doc, "jwks") and Map.has_key?(doc, "jwks_uri")),
            :ambiguous_key_source
          )

          cond do
            Map.has_key?(doc, "jwks") ->
              {doc["jwks"], message, fields, location, expires, decoded}

            Map.has_key?(doc, "jwks_uri") ->
              nested = Source.url!(doc["jwks_uri"])
              ensure(Source.origin(nested) == Source.origin(uri), :redirect_denied)
              nested_source = %{source | type: :jwks_uri}

              {nested_fields, nested_message, nested_location, nested_bytes} =
                resource(nested, nested_source, deadline, 0)

              {body_document(nested_bytes, nested_source), nested_message, nested_fields,
               nested_location, min(expires, expiry(nested_fields, source, now)), nested_bytes}

            true ->
              ensure(false, :invalid_key_set)
          end

        _ ->
          {body_document(decoded, source), message, fields, location, expires, decoded}
      end

    origin = Source.origin(URI.parse(location))
    keys = keys(document, source, origin, location, now)

    {proof, proof_expiry} =
      if source.type == :directory,
        do: proof(key_message, key_fields, keys, source, clock, now),
        else: {:not_applicable, now + source.max_ttl}

    expires = min(expires, proof_expiry)

    keys =
      Map.new(keys, fn {kid, resolution} ->
        {kid, %{resolution | proof: proof, expires_at: min(resolution.expires_at, proof_expiry)}}
      end)

    expires = Enum.reduce(keys, expires, fn {_, key}, bound -> min(bound, key.expires_at) end)
    Support.remaining(deadline)

    {:ok,
     %KeySet{
       source: source,
       origin: origin,
       keys: keys,
       fetched_at: now,
       expires_at: expires,
       revision: Base.url_encode64(:crypto.hash(:sha256, key_bytes), padding: false),
       proof: proof
     }}
  end

  defp resource(uri, source, deadline, redirects) do
    socket = Transport.connect(uri, source, deadline)

    response =
      try do
        HTTP1.request(socket, uri, source, deadline)
      after
        :ssl.close(socket)
      end

    case response do
      {200, fields, message, decoded} ->
        media = HTTP1.value(fields, "content-type")
        ensure(is_binary(media), :unexpected_media_type)
        media = media |> String.split(";", parts: 2) |> hd() |> String.trim() |> String.downcase()

        allowed =
          case source.type do
            :directory -> ["application/http-message-signatures-directory+json"]
            :jwks_uri -> ["application/jwk-set+json", "application/json"]
            :cimd -> ["application/json"]
          end

        ensure(media in allowed, :unexpected_media_type)
        {fields, message, URI.to_string(uri), decoded}

      {code, fields, _, _} when code in [301, 302, 303, 307, 308] ->
        ensure(source.max_redirects > 0, :redirect_denied)
        ensure(redirects < source.max_redirects, :redirect_limit)
        location = HTTP1.value(fields, "location")
        ensure(is_binary(location) and byte_size(location) <= 2048, :redirect_denied)

        target =
          Support.safe(fn -> {:ok, Source.url!(URI.to_string(URI.merge(uri, location)))} end)

        ensure(match?({:ok, _}, target), :redirect_denied)
        {:ok, target} = target

        ensure(
          source.redirect_scope == :any_https or
            Source.origin(target) == Source.origin(URI.parse(source.location)),
          :redirect_denied
        )

        resource(target, source, deadline, redirects + 1)

      {code, _, _, _} ->
        throw({:discovery_error, %Error{reason: :unexpected_status, retryable: code in 500..599}})
    end
  end

  defp json(bytes) do
    json_depth(bytes, 0, false, false)

    decoders = %{
      object_push: fn key, value, acc ->
        ensure(length(acc) < 256, :limit)
        ensure(not List.keymember?(acc, key, 0), :invalid_response)
        [{key, value} | acc]
      end,
      array_push: fn value, acc ->
        ensure(length(acc) < 256, :limit)
        [value | acc]
      end
    }

    {value, _, rest} = :json.decode(bytes, nil, decoders)
    ensure(json_whitespace?(rest), :invalid_response)
    value
  rescue
    _ -> ensure(false, :invalid_response)
  end

  # RFC 8259 Section 2 permits only SP, HTAB, LF, and CR outside a value.
  defp json_whitespace?(<<>>), do: true

  defp json_whitespace?(<<byte, rest::binary>>) when byte in [32, 9, 10, 13],
    do: json_whitespace?(rest)

  defp json_whitespace?(_), do: false

  defp json_depth(<<>>, depth, string, _),
    do: ensure(depth == 0 and not string, :invalid_response)

  defp json_depth(<<_, rest::binary>>, depth, true, true),
    do: json_depth(rest, depth, true, false)

  defp json_depth(<<92, rest::binary>>, depth, true, false),
    do: json_depth(rest, depth, true, true)

  defp json_depth(<<34, rest::binary>>, depth, string, false),
    do: json_depth(rest, depth, not string, false)

  defp json_depth(<<byte, rest::binary>>, depth, false, false) when byte in [123, 91] do
    ensure(depth < 32, :limit)
    json_depth(rest, depth + 1, false, false)
  end

  defp json_depth(<<byte, rest::binary>>, depth, false, false) when byte in [125, 93] do
    ensure(depth > 0, :invalid_response)
    json_depth(rest, depth - 1, false, false)
  end

  defp json_depth(<<_, rest::binary>>, depth, string, escape),
    do: json_depth(rest, depth, string, escape)

  defp keys(%{"keys" => jwks}, source, origin, location, now) when is_list(jwks) do
    ensure(length(jwks) <= source.max_keys, :limit)

    Enum.reduce(jwks, %{}, fn jwk, acc ->
      ensure(is_map(jwk) and map_size(jwk) <= 32, :invalid_key_set)
      asserted = jwk["alg"]
      ensure(asserted == nil or asserted in Algorithm.http(), :invalid_key_set)

      imported =
        if asserted == nil,
          do: jwk,
          else: Map.put(jwk, "alg", elem(Algorithm.resolve(asserted), 0))

      public =
        case PublicKey.import(imported, :jwk) do
          {:ok, public} -> public
          _ -> ensure(false, :invalid_key_set)
        end

      {:ok, thumbprint} = PublicKey.thumbprint(public)
      kid = if source.key_id == :directory, do: jwk["kid"], else: thumbprint
      ensure(Source.key_id?(source, kid), :invalid_key_set)

      ensure(
        source.key_id == :directory or not Map.has_key?(jwk, "kid") or jwk["kid"] == thumbprint,
        :invalid_key_set
      )

      for field <- ["nbf", "exp"] do
        ensure(
          not Map.has_key?(jwk, field) or
            (is_integer(jwk[field]) and jwk[field] in 0..999_999_999_999_999),
          :invalid_key_set
        )
      end

      algorithm = asserted || default_algorithm(public)

      valid_time =
        (jwk["nbf"] == nil or now >= jwk["nbf"]) and (jwk["exp"] == nil or now < jwk["exp"])

      # Temporal/operation restrictions exclude the key rather than changing it.
      if binding?(public, algorithm) and valid_time and thumbprint not in source.revoked do
        ensure(not Map.has_key?(acc, kid), :invalid_key_set)

        entry = %Resolution{
          key: public,
          thumbprint: thumbprint,
          key_id: kid,
          algorithm: algorithm,
          asserted_algorithm: asserted,
          origin: origin,
          source_type: source.type,
          location: location,
          fetched_at: now,
          expires_at: min(now + source.max_ttl, jwk["exp"] || now + source.max_ttl),
          proof: :not_applicable
        }

        Map.put(acc, kid, entry)
      else
        acc
      end
    end)
  end

  defp keys(_, _, _, _, _), do: ensure(false, :invalid_key_set)
  defp default_algorithm(%{material: {:ed25519, _}}), do: "ed25519"
  defp default_algorithm(%{material: {:ec, "P-256", _}}), do: "ecdsa-p256-sha256"
  defp default_algorithm(%{material: {:ec, "P-384", _}}), do: "ecdsa-p384-sha384"
  defp default_algorithm(_), do: "rsa-pss-sha512"

  defp binding?(key, algorithm) do
    PublicKey.bind!(key, Algorithm.resolve(algorithm))
    true
  catch
    _, _ -> false
  end

  defp proof(message, fields, keys, source, clock, now) do
    inputs = HTTP1.values(fields, "signature-input")
    signatures = HTTP1.values(fields, "signature")

    if inputs == [] and signatures == [] do
      ensure(not source.require_signed_directory, :directory_unsigned)
      {:unsigned, now + source.max_ttl}
    else
      parsed =
        StructuredFields.parse(Enum.join(inputs, ", "), SignatureFields.schema(:dictionary))

      ensure(match?({:ok, _}, parsed), :directory_signature_invalid)
      {:ok, dictionary} = parsed
      ensure(length(dictionary.value) in 1..64, :directory_signature_invalid)

      signature_schema = SignatureFields.schema(:dictionary, [:bytes], false)

      parsed_signatures =
        StructuredFields.parse(Enum.join(signatures, ", "), signature_schema,
          max_members: 64,
          max_value_bytes: 1024
        )

      ensure(match?({:ok, _}, parsed_signatures), :directory_signature_invalid)
      {:ok, signature_dictionary} = parsed_signatures

      selected =
        Enum.filter(dictionary.value, fn {label, value} ->
          params = SignatureFields.parameters(value)

          label == "directory" or
            (params["tag"] == "http-message-signatures-directory" and
               Map.has_key?(keys, params["keyid"]))
        end)

      ensure(selected != [], :directory_signature_invalid)

      expirations =
        Enum.map(selected, fn {label, value} ->
          signature = List.keyfind(signature_dictionary.value, label, 0)
          ensure(signature != nil, :directory_signature_invalid)

          selected_message =
            proof_message(message, %{dictionary | value: [{label, value}]}, %{
              signature_dictionary
              | value: [signature]
            })

          ensure(SignatureFields.valid_inner?(value), :directory_signature_invalid)
          params = SignatureFields.parameters(value)

          ensure(
            params["tag"] == "http-message-signatures-directory" and
              Source.thumbprint?(params["keyid"]),
            :directory_signature_invalid
          )

          ensure(
            is_integer(params["created"]) and params["created"] <= now and
              is_integer(params["expires"]),
            :directory_signature_invalid
          )

          entry = Map.get(keys, params["keyid"])
          ensure(entry != nil, :directory_signature_invalid)
          # Verification-time expiry is checked separately from cache freshness;
          # max-age=0 still permits this fetch to validate its possession proof.
          candidates =
            Enum.filter(Algorithm.http(), fn algorithm ->
              entry.asserted_algorithm in [nil, algorithm] and binding?(entry.key, algorithm)
            end)

          valid =
            Enum.any?(candidates, fn algorithm ->
              resolver = fn %{keyid: kid} ->
                if kid == entry.thumbprint,
                  do: {:ok, %{algorithm: algorithm, key: entry.key}},
                  else: :error
              end

              {:ok, policy} =
                Policy.new(%{
                  algorithms: [algorithm],
                  components: "(\"@authority\";req \"content-digest\")",
                  key_resolver: resolver,
                  freshness: %{clock: clock, max_age: nil, skew: 0, require_expires: true},
                  content: %{
                    kind: :content,
                    algorithms: ["sha-256", "sha-512"],
                    section: :headers
                  },
                  replay: :not_required,
                  max_signatures: 64
                })

              match?({:ok, _}, RequestSeal.verify(selected_message, policy, label: label))
            end)

          ensure(valid, :directory_signature_invalid)

          params["expires"]
        end)

      {:signed, Enum.min(expirations)}
    end
  end

  defp proof_message(message, input, signature) do
    selected_fields =
      for {name, dictionary, schema} <- [
            {"Signature-Input", input, SignatureFields.schema(:dictionary)},
            {"Signature", signature, SignatureFields.schema(:dictionary, [:bytes], false)}
          ] do
        {:ok, bytes} = StructuredFields.serialize(dictionary, schema)

        Support.unwrap(
          RequestSeal.FieldOccurrence.new(%{name: name, value: bytes, section: :headers})
        )
      end

    fields =
      Enum.reject(message.fields, &(String.downcase(&1.name) in ["signature-input", "signature"]))

    %{message | fields: fields ++ selected_fields}
  end

  defp expiry(fields, source, now) do
    controls =
      HTTP1.values(fields, "cache-control")
      |> Enum.join(",")
      |> String.downcase()
      |> String.split(",")
      |> Enum.map(&String.trim/1)

    no_cache = Enum.any?(controls, &(&1 in ["no-store", "no-cache"]))

    ages =
      for control <- controls,
          String.starts_with?(control, "max-age="),
          do: String.replace_prefix(control, "max-age=", "") |> String.trim("\"")

    ensure(length(ages) <= 1, :invalid_response)

    date = http_date(HTTP1.value(fields, "date"), now) || now

    ttl =
      case ages do
        [] ->
          case HTTP1.value(fields, "expires") do
            nil -> source.min_ttl
            expires -> max((http_date(expires, now) || date) - date, 0)
          end

        [age] ->
          ensure(byte_size(age) in 1..10 and Regex.match?(~r/\A[0-9]+\z/, age), :invalid_response)
          String.to_integer(age)
      end

    age = HTTP1.value(fields, "age") || "0"
    ensure(byte_size(age) in 1..10 and Regex.match?(~r/\A[0-9]+\z/, age), :invalid_response)
    age = max(String.to_integer(age), max(now - date, 0))
    ttl = max(min(ttl, source.max_ttl) - age, 0)
    now + if(no_cache, do: 0, else: ttl)
  end

  # RFC 9110 HTTP-date: IMF-fixdate plus both obsolete recipient formats.
  # Keep the strict parser: observed on OTP 29.1.1 by running the
  # discovery_http_date_test.exs table through :httpd_util.convert_request_date/1,
  # OTP accepts invalid dates/times, signed days, lowercase weekdays and trailing
  # bytes, and maps every RFC 850 year to 20xx instead of the caller-clock cutoff.
  defp http_date(nil, _), do: nil

  defp http_date(value, now) do
    parts =
      Regex.run(
        ~r/\A(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-9]{2}) ([A-Z][a-z]{2}) ([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT\z/,
        value,
        capture: :all_but_first
      )

    parts = parts || obsolete_date(value, now)

    case parts do
      [day, month, year, hour, minute, second] ->
        month =
          Enum.find_index(~w(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec), &(&1 == month))

        with true <- month != nil,
             {:ok, date} <- Date.new(String.to_integer(year), month + 1, String.to_integer(day)),
             {:ok, time} <-
               Time.new(
                 String.to_integer(hour),
                 String.to_integer(minute),
                 String.to_integer(second)
               ),
             {:ok, datetime} <- DateTime.new(date, time, "Etc/UTC") do
          DateTime.to_unix(datetime)
        else
          _ -> nil
        end

      _ ->
        nil
    end
  end

  defp obsolete_date(value, now) do
    case Regex.run(
           ~r/\A(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-9]{2})-([A-Z][a-z]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) GMT\z/,
           value,
           capture: :all_but_first
         ) do
      [day, month, year, hour, minute, second] ->
        current_year = DateTime.from_unix!(now).year
        year = div(current_year, 100) * 100 + String.to_integer(year)
        year = if year > current_year + 50, do: year - 100, else: year
        [day, month, Integer.to_string(year), hour, minute, second]

      nil ->
        case Regex.run(
               ~r/\A(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Z][a-z]{2}) ( [0-9]|[0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4})\z/,
               value,
               capture: :all_but_first
             ) do
          [month, day, hour, minute, second, year] ->
            [String.trim(day), month, year, hour, minute, second]

          nil ->
            nil
        end
    end
  end
end
