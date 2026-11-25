defmodule RequestSeal.VerificationRecord do
  @moduledoc """
  Retain the public key, signed bytes, and signature from accepted HTTP verification.

  Pass `capture: true` to `RequestSeal.verify/3` or
  `RequestSeal.WebBotAuth.verify/3`. For Web Bot Auth, select one accepted
  signature from the result. Only public-key verification supports capture.
  Default inspection hides the record and no telemetry is emitted.

  Profile, directory and outcome describe the original verification. They
  are outside the signed HTTP bytes.

  The version 1 envelope is compact UTF-8 JSON with `digest` and `record`
  members and a 2 MiB limit. Its closed schema has ASCII member names sorted by
  byte order, printable ASCII strings with only quote and backslash escaped, ordered
  arrays, null, and nonnegative decimal integers without leading zeros.
  The digest is unpadded Base64url SHA-256 of the canonical record object.
  Signature bases, signatures and DER are also unpadded Base64url. Keys
  retain their validated public JWK restrictions. A PSS-only RSA key uses
  public SubjectPublicKeyInfo DER plus optional `alg`, `use`, and `key_ops`
  restrictions in the same object.

  Offline checks establish mathematical validity against the retained key.
  Trust in that key, freshness, replay, and body integrity are time- and
  message-dependent live checks. The record carries no authorization.
  A retired key can still verify an old record mathematically. Protect the
  covered bytes, which may contain sensitive values, and protect the record
  or its digest against substitution. An attacker who can replace both
  can create a different self-consistent record with a different key.

  Sources are [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html),
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), and
  [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html).
  """

  alias RequestSeal.{Crypto, PublicKey, SignatureBase, SignatureFields, Verification}
  alias RequestSeal.Discovery.{Resolution, Source}

  @max_bytes 2_097_152
  @max_base 1_048_576
  @max_signature 1024
  @max_second 253_402_300_799
  @refusal {:error, :invalid_record}

  @derive {Inspect, only: []}
  defstruct [:data, :digest]

  @opaque t :: %__MODULE__{data: map(), digest: binary()}

  @doc """
  Build a record from an accepted result with captured public material.

  Accepts a `RequestSeal.Verification` or its `{:ok, verification}` tuple.
  Optional `directory: resolution` records the origin and fetch time of a
  `RequestSeal.Discovery.Resolution` for the same public key. A Web Bot Auth
  agent already supplies these historical facts. An explicit resolution must
  agree with them. A Web Bot Auth held-key principal rejects explicit
  directory provenance. Provenance describes the original verification and is
  outside the HTTP signature.

  Returns `{:ok, record}` or `{:error, :not_accepted}` when the result lacks
  sound capture evidence or the options or directory provenance are invalid.
  """
  @spec from_verification(term(), keyword()) :: {:ok, t()} | {:error, :not_accepted}
  def from_verification(result, opts \\ [])
  def from_verification({:ok, %Verification{} = result}, opts),
    do: from_verification(result, opts)

  def from_verification(
        %Verification{
          authorization: :not_evaluated,
          signature: %{
            algorithm: algorithm,
            covered: covered,
            crypto: :valid,
            keyid: keyid,
            parameters: parameters,
            record_material: %{key: key, base: base, signature: signature}
          }
        } = verification,
        opts
      ) do
    with true <- SignatureFields.label?(verification.label),
         true <- SignatureFields.algorithm?(algorithm),
         {:ok, %{inner_list: inner}} <- SignatureBase.parse(base),
         ^parameters <- SignatureFields.parameters(inner),
         ^keyid <- parameters["keyid"],
         {:ok, ^covered} <- SignatureFields.identifiers(inner.value),
         true <- is_binary(signature) and byte_size(signature) in 1..@max_signature,
         {:ok, public} <- export_key(key),
         {:ok, thumbprint} <- PublicKey.thumbprint(key),
         {:ok, directory} <- directory(verification, opts, thumbprint),
         {:ok, profile} <- export_profile(verification.profile) do
      data = %{
        "algorithm" => encode_algorithm(algorithm),
        "base" => b64(base),
        "covered" => covered,
        "directory" => directory,
        "key" => public,
        "outcome" => "accepted",
        "profile" => profile,
        "signature" => b64(signature),
        "thumbprint" => thumbprint,
        "version" => 1
      }

      record = %__MODULE__{data: data, digest: checksum(data)}

      case reverify(record) do
        :ok -> {:ok, record}
        {:error, _} -> {:error, :not_accepted}
      end
    else
      _ -> {:error, :not_accepted}
    end
  rescue
    _ -> {:error, :not_accepted}
  catch
    _, _ -> {:error, :not_accepted}
  end

  def from_verification(_, _), do: {:error, :not_accepted}

  @doc """
  Encode a validated record as canonical version 1 JSON. Rechecks the
  signature and digest. Returns `{:ok, bytes}` or `{:error, :invalid_record}`.
  """
  @spec encode(t()) :: {:ok, binary()} | {:error, :invalid_record}
  def encode(record), do: check(record, nil)

  @doc """
  Decode exact canonical version 1 JSON and recheck its digest and signature.
  Noncanonical, malformed, or unverifiable input returns `{:error, :invalid_record}`.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, :invalid_record}
  def decode(bytes) when is_binary(bytes) and byte_size(bytes) <= @max_bytes do
    :ok = json_bound(bytes, 0, false, 0)

    {envelope, _, <<>>} =
      :json.decode(bytes, nil, %{
        null: nil,
        integer: &decimal/1,
        float: fn _ -> throw(:invalid_record) end,
        object_push: &object_member/3,
        array_push: &array_item/2
      })

    with %{"record" => data, "digest" => digest} when map_size(envelope) == 2 <- envelope,
         record = %__MODULE__{data: data, digest: digest},
         {:ok, ^bytes} <- check(record, bytes) do
      {:ok, record}
    else
      _ -> @refusal
    end
  rescue
    _ -> @refusal
  catch
    _, _ -> @refusal
  end

  def decode(_), do: @refusal

  @doc """
  Recheck retained signature validity offline from a record or canonical JSON.
  Returns `:ok` or `{:error, :invalid_record}`. Performs no live trust checks.
  """
  @spec reverify(t() | binary()) :: :ok | {:error, :invalid_record}
  def reverify(bytes) when is_binary(bytes) do
    with {:ok, _} <- decode(bytes), do: :ok
  end

  def reverify(record) do
    with {:ok, _} <- check(record, nil), do: :ok
  end

  defp check(%__MODULE__{data: data, digest: digest} = record, original)
       when map_size(record) == 3 do
    with %{
           "algorithm" => algorithm,
           "base" => base_wire,
           "covered" => covered,
           "directory" => directory,
           "key" => public,
           "outcome" => "accepted",
           "profile" => profile,
           "signature" => signature_wire,
           "thumbprint" => thumbprint,
           "version" => 1
         } when map_size(data) == 10 <- data,
         true <- profile?(profile) and directory?(directory),
         {:ok, key} <- import_key(public),
         {:ok, ^thumbprint} <- PublicKey.thumbprint(key),
         {:ok, base} <- unb64(base_wire, @max_base),
         {:ok, signature} <- unb64(signature_wire, @max_signature),
         {:ok, %{inner_list: inner}} <- SignatureBase.parse(base),
         {:ok, ^covered} <- SignatureFields.identifiers(inner.value),
         algorithm = decode_algorithm(algorithm),
         true <- SignatureFields.algorithm?(algorithm),
         true <- SignatureFields.parameters(inner)["alg"] in [nil, algorithm],
         ^digest <- checksum(data),
         bytes = canonical(%{"record" => data, "digest" => digest}),
         true <- byte_size(bytes) <= @max_bytes and (original == nil or original == bytes),
         :ok <- Crypto.verify(algorithm, base, signature, key) do
      {:ok, bytes}
    else
      _ -> @refusal
    end
  rescue
    _ -> @refusal
  catch
    _, _ -> @refusal
  end

  defp check(_, _), do: @refusal

  defp export_key(%PublicKey{material: {:rsa_pss, _, _}} = key) do
    public = PublicKey.validate!(key)
    unrestricted = %{public | algorithm: nil, use: nil, operations: nil}

    with {:ok, der} <- PublicKey.export(unrestricted, :der) do
      restrictions = [
        {"alg", public.algorithm},
        {"use", public.use},
        {"key_ops", public.operations}
      ]

      members = Map.new(Enum.reject(restrictions, fn {_, value} -> is_nil(value) end))
      {:ok, Map.put(members, "spki", b64(der))}
    end
  end

  defp export_key(key) do
    with {:ok, jwk} <- PublicKey.export(key, :jwk), do: {:ok, %{"jwk" => jwk}}
  end

  defp import_key(%{"jwk" => jwk} = wire) when map_size(wire) == 1 do
    with {:ok, key} <- PublicKey.import(jwk, :jwk),
         {:ok, ^wire} <- export_key(key),
         do: {:ok, key}
  end

  defp import_key(%{"spki" => encoded} = wire) when map_size(wire) in 1..4 do
    with {:ok, der} <- unb64(encoded, 16_384),
         {:ok, %PublicKey{material: {:rsa_pss, _, _}} = key} <- PublicKey.import(der, :der),
         key = %{key | algorithm: wire["alg"], use: wire["use"], operations: wire["key_ops"]},
         {:ok, ^wire} <- export_key(key),
         do: {:ok, key}
  end

  defp import_key(_), do: :error

  defp export_profile(%{name: :rfc9421} = profile) when map_size(profile) == 1,
    do: {:ok, %{"name" => "rfc9421"}}

  defp export_profile(%{name: :web_bot_auth, revision: revision} = profile)
       when map_size(profile) == 2 do
    if ascii?(revision, 128),
      do: {:ok, %{"name" => "web_bot_auth", "revision" => revision}},
      else: :error
  end

  defp export_profile(_), do: :error

  defp profile?(%{"name" => "rfc9421"} = profile), do: map_size(profile) == 1

  defp profile?(%{"name" => "web_bot_auth", "revision" => revision} = profile),
    do: map_size(profile) == 2 and ascii?(revision, 128)

  defp profile?(_), do: false

  defp directory(%{profile: %{name: :web_bot_auth}, principal: %{kind: :key}}, opts, _) do
    if opts == [], do: {:ok, nil}, else: :error
  end

  defp directory(%{principal: principal}, opts, thumbprint) do
    with {:ok, established} <- established_directory(principal, thumbprint),
         {:ok, supplied} <- supplied_directory(opts, thumbprint),
         true <- is_nil(established) or is_nil(supplied) or established == supplied do
      {:ok, established || supplied}
    else
      _ -> :error
    end
  end

  defp established_directory(
         %{kind: :agent, origin: origin, provenance: %{fetched_at: time}, thumbprint: thumb},
         thumb
       ),
       do: checked_directory(origin, time)

  defp established_directory(%{kind: :agent}, _), do: :error
  defp established_directory(_, _), do: {:ok, nil}

  defp supplied_directory([], _), do: {:ok, nil}

  defp supplied_directory([directory: %Resolution{thumbprint: thumb} = resolution], thumb) do
    with {:ok, ^thumb} <- PublicKey.thumbprint(resolution.key),
         do: checked_directory(resolution.origin, resolution.fetched_at)
  end

  defp supplied_directory(_, _), do: :error

  defp checked_directory(origin, time) do
    info = %{"origin" => origin, "fetched_at" => time}
    if directory?(info), do: {:ok, info}, else: :error
  end

  defp directory?(nil), do: true

  defp directory?(%{"origin" => origin, "fetched_at" => time} = info) do
    with true <- map_size(info) == 2 and is_integer(time) and time in 0..@max_second,
         true <- ascii?(origin, 8192),
         {:ok, %URI{scheme: "https", host: host, port: port} = uri} <- URI.new(origin),
         true <- is_binary(host) and host != "" and port in 1..65_535,
         true <- uri.path in [nil, ""] and uri.userinfo == nil and uri.query == nil,
         true <- uri.fragment == nil do
      Source.origin(uri) == origin
    else
      _ -> false
    end
  end

  defp directory?(_), do: false

  defp ascii?(value, max) when is_binary(value) and byte_size(value) in 1..max,
    do: Enum.all?(:binary.bin_to_list(value), &(&1 in 32..126))

  defp ascii?(_, _), do: false

  defp encode_algorithm({:jws, name}), do: ["jws", name]
  defp encode_algorithm(name), do: name
  defp decode_algorithm(["jws", name]) when is_binary(name), do: {:jws, name}
  defp decode_algorithm(name) when is_binary(name), do: name
  defp decode_algorithm(_), do: nil

  defp b64(bytes), do: Base.url_encode64(bytes, padding: false)

  defp unb64(wire, limit)
       when is_binary(wire) and byte_size(wire) in 1..div(limit * 4 + 2, 3) do
    with {:ok, bytes} <- Base.url_decode64(wire, padding: false),
         true <- b64(bytes) == wire,
         do: {:ok, bytes}
  end

  defp unb64(_, _), do: :error

  defp checksum(data), do: b64(:crypto.hash(:sha256, canonical(data)))
  defp canonical(data), do: data |> json() |> IO.iodata_to_binary()

  defp json(nil), do: "null"
  defp json(n) when is_integer(n) and n in 0..@max_second, do: Integer.to_string(n)

  defp json(s) when is_binary(s) do
    escaped =
      s
      |> :binary.replace(<<92>>, <<92, 92>>, [:global])
      |> :binary.replace(<<34>>, <<92, 34>>, [:global])

    [?", escaped, ?"]
  end

  defp json(values) when is_list(values),
    do: ["[", Enum.intersperse(Enum.map(values, &json/1), ","), "]"]

  defp json(object) when is_map(object) do
    members =
      object
      |> Enum.sort()
      |> Enum.map(fn {name, value} -> [json(name), ":", json(value)] end)

    ["{", Enum.intersperse(members, ","), "}"]
  end

  defp decimal(bytes) when byte_size(bytes) <= 12, do: String.to_integer(bytes)
  defp decimal(_), do: throw(:invalid_record)

  defp object_member(name, value, acc) do
    if length(acc) >= 16 or List.keymember?(acc, name, 0), do: throw(:invalid_record)
    [{name, value} | acc]
  end

  defp array_item(value, acc) do
    if length(acc) >= 256, do: throw(:invalid_record)
    [value | acc]
  end

  # Bound nesting and total containers before the JSON decoder allocates them.
  defp json_bound(<<>>, 0, false, _), do: :ok

  defp json_bound(<<?\\, _, rest::binary>>, depth, true, nodes),
    do: json_bound(rest, depth, true, nodes)

  defp json_bound(<<?", rest::binary>>, depth, quoted, nodes),
    do: json_bound(rest, depth, not quoted, nodes)

  defp json_bound(<<byte, rest::binary>>, depth, false, nodes) when byte in [123, 91] do
    if depth >= 8 or nodes >= 1024, do: throw(:invalid_record)
    json_bound(rest, depth + 1, false, nodes + 1)
  end

  defp json_bound(<<byte, rest::binary>>, depth, false, nodes) when byte in [125, 93] do
    if depth <= 0, do: throw(:invalid_record)
    json_bound(rest, depth - 1, false, nodes)
  end

  defp json_bound(<<_, rest::binary>>, depth, quoted, nodes),
    do: json_bound(rest, depth, quoted, nodes)
end
