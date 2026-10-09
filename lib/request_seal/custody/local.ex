defmodule RequestSeal.Custody.Local do
  @moduledoc """
  Caller-owned OTP private keys and symmetric secrets, held in sensitive processes.

  `new/3` accepts the signing descriptors documented by `RequestSeal.Crypto`.
  It also accepts `{:jwe, "RSA-OAEP"}` or `{:jwe, "RSA-OAEP-256"}` with
  `{:rsa, otp_private_key}` for unwrap-only custody. RSA keys are 2048–8192 bits;
  each handle binds exactly one algorithm and cannot sign or verify.
  `import/4` accepts a single unencrypted private PEM (PKCS #1 RSA, SEC1 EC,
  PKCS #8 RSA/RSASSA-PSS/EC/Ed25519), PKCS #8 DER (`:der`), or private JWK map. Public-only material,
  inconsistent private components, algorithm/type/curve mismatches, and encrypted
  containers reject. A PSS-only private key never becomes a PKCS #1 signing key;
  parameter-constrained PSS containers reject rather than dropping restrictions.
  Imported EC/OKP public components must agree with the derived private key.
  PKCS #8 v2 (OneAsymmetricKey) containers reject with `:unsupported_format`.

  All six HTTP algorithms and the eight explicit JWS extensions in `Crypto` are
  supported. Construction derives a public key and performs an actual sign/verify
  before returning a signing handle. Unwrap construction validates RSA CRT components
  and performs an actual OAEP wrap/unwrap. Only `equivalence: nonsecret_binary` is accepted, and
  only for HMAC (1–256 bytes). Absent HMAC equivalence remains `:unknown`; no value
  is derived from the secret. HMAC verification stays inside the custodian.

  PEM/DER inputs are at most 16,384 bytes. JWK maps have at most 32 fields; components
  must be canonical unpadded Base64url. `alg`, `use`, and `key_ops` restrictions
  must permit the selected operation. For OAEP, `use` must be absent or `enc`,
  and `key_ops` must be absent or permit `decrypt` or `unwrapKey`; signing operations
  reject. Public metadata retains these restrictions. Private JWK metadata is checked at
  import; the handle's capabilities are limited to its permitted operations.
  No private key export, global store, server, or telemetry is provided.

  Each successful construction starts one unsupervised holder process. It marks
  itself sensitive before receiving key material; the handle references only its
  PID and a random 32-byte token. The holder performs OTP cryptography and returns
  signature bytes, unwrapped key bytes, verification results, or public metadata,
  never private state. `RequestSeal.Custody.unwrap/3` shares signing deadlines,
  cancellation, and safe errors. RSA-OAEP uses SHA-1/MGF1 SHA-1 and RSA-OAEP-256
  uses SHA-256/MGF1 SHA-256, both with an empty label, as defined by
  [RFC 7518 Section 4.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3).
  Process and system introspection do not export that state.

  Holders live until `release/1` or the creating process exits, including after a
  handle is transferred. Dropping a handle does not stop its holder. A long-lived
  owner such as a GenServer must call `release/1` for handles it no longer needs,
  or create handles once at startup and reuse them for its lifetime.
  Operations against a stopped holder return `:key_not_found`. No supervisor,
  registry, application callback, or process starts when the library is loaded.

  ## Decryption custody

  Import a recipient key once in its long-lived owner's process, then return the
  handle from the JWE policy resolver:

      {:ok, handle} = RequestSeal.Custody.Local.import({:jwe, "RSA-OAEP-256"}, private_pem, :pem)
      policy = %{
        algorithms: ["RSA-OAEP-256"],
        encryption: ["A256GCM"],
        max_plaintext: 1_048_576,
        timeout: 5_000,
        key_resolver: fn _ -> {:ok, %{algorithm: "RSA-OAEP-256", key: handle}} end
      }
      RequestSeal.JOSE.JWE.decrypt(compact, policy)

  The resolver's work and the holder request share the JWE deadline. Private RSA
  material stays in the holder. The CEK passes through the sensitive custody
  runner and middle process to JWE's sensitive worker for authenticated content
  decryption. OAEP padding and GCM tag failures return the same complete
  `RequestSeal.JOSE.Error`. A released or unavailable handle produces that same
  error as a forged message, by design; use
  `RequestSeal.Custody.public_key(handle)` as a startup health check to expose
  custody availability independently. Deadline expiration remains distinct.
  Release the handle with `release/1` when its owner no longer needs it.
  """
  @behaviour RequestSeal.Custody
  alias RequestSeal.{Crypto, KeyHandle, KeyIdentity, PublicKey}
  alias RequestSeal.Crypto.Algorithm
  alias RequestSeal.Custody.Support
  import Support, only: [ensure: 2, unwrap: 1]
  @rsa {1, 2, 840, 113_549, 1, 1, 1}
  @pss {1, 2, 840, 113_549, 1, 1, 10}
  @ec {1, 2, 840, 10045, 2, 1}
  @ed {1, 3, 101, 112}

  @doc "Construct an algorithm-bound signing or RSA-OAEP unwrap capability from OTP material."
  @spec new(RequestSeal.Custody.algorithm(), tuple(), keyword()) ::
          {:ok, KeyHandle.t()} | {:error, RequestSeal.Custody.Error.t()}
  def new(algorithm, material, opts \\ []) do
    Support.safe(fn ->
      {_, _, capabilities} = selection(algorithm)
      construct(algorithm, material, opts, nil, nil, capabilities)
    end)
  end

  @doc "Import one unencrypted private PEM, PKCS #8 DER, or private JWK with an explicit algorithm."
  @spec import(RequestSeal.Custody.algorithm(), term(), :pem | :der | :jwk, keyword()) ::
          {:ok, KeyHandle.t()} | {:error, RequestSeal.Custody.Error.t()}
  def import(algorithm, value, format, opts \\ []) do
    Support.safe(fn ->
      {jose, _, _} = selection(algorithm)
      {material, type, expected, capabilities} = decode(value, format, jose)
      construct(algorithm, material, opts, type, expected, capabilities)
    end)
  end

  defp construct(algorithm, material, opts, type, expected, capabilities) do
    {jose, family, _} = selection(algorithm)
    Support.options(opts, [:equivalence])
    equivalence = Keyword.get(opts, :equivalence)

    if Keyword.has_key?(opts, :equivalence) do
      ensure(
        family == :hmac and is_binary(equivalence) and byte_size(equivalence) in 1..256,
        :invalid_options
      )
    end

    ensure(type != :rsa_pss or jose in ~w(PS256 PS384 PS512), :key_mismatch)
    public = derive(material, type)
    expected_material = if is_struct(expected, PublicKey), do: expected.material, else: expected
    ensure(expected_material == nil or public.material == expected_material, :invalid_key)
    validate_operation(algorithm, material, public)
    public = if is_struct(expected, PublicKey), do: PublicKey.validate!(expected), else: public

    identity =
      case public do
        nil ->
          %KeyIdentity{kind: if(equivalence, do: :symmetric, else: :unknown), value: equivalence}

        key ->
          %KeyIdentity{kind: :public, value: KeyIdentity.normalize(key.material)}
      end

    state = {algorithm, material, public, identity, capabilities}
    {holder, token} = start_holder(state)

    {:ok,
     %KeyHandle{
       custodian: __MODULE__,
       algorithm: algorithm,
       capabilities: capabilities,
       ref: fn -> {holder, token} end
     }}
  end

  defp selection({:jwe, jose}) when jose in ["RSA-OAEP", "RSA-OAEP-256"],
    do: {jose, :rsa, [:unwrap]}

  defp selection(algorithm) do
    {jose, {family, _, _, _}} = Algorithm.resolve(algorithm)
    {jose, family, [:sign, :verify]}
  end

  defp validate_operation({:jwe, alg}, material, public) do
    ensure(match?({:rsa, _}, material), :key_mismatch)
    {:rsa, private} = material
    Crypto.validate_rsa_private!(private)
    {:rsa, n, e} = public.material
    cek = :crypto.strong_rand_bytes(32)

    wrapped =
      RequestSeal.JOSE.KeyManagement.wrap(alg, cek, %{}, {:rsa, {:RSAPublicKey, n, e}})
      |> unwrap()

    recovered =
      RequestSeal.JOSE.KeyManagement.unwrap(alg, wrapped.encrypted_key, %{}, material) |> unwrap()

    ensure(:crypto.hash_equals(cek, recovered), :invalid_key)
  end

  defp validate_operation(algorithm, material, public) do
    signature = Crypto.sign(algorithm, "", material) |> unwrap()
    Crypto.verify(algorithm, "", signature, public || material) |> unwrap()
  end

  @doc "Stop a local holder and discard its key material. Releasing it again returns :ok."
  @spec release(KeyHandle.t()) :: :ok | {:error, RequestSeal.Custody.Error.t()}
  def release(handle) do
    Support.safe(
      fn ->
        ensure(match?(%KeyHandle{custodian: __MODULE__}, handle), :invalid_handle)
        ensure(map_size(handle) == 5 and is_function(handle.ref, 0), :invalid_handle)
        {pid, token} = address(handle.ref)
        monitor = Process.monitor(pid)
        send(pid, {:release, token})

        try do
          receive do
            {:DOWN, ^monitor, :process, ^pid, _} -> :ok
          after
            5_000 -> {:error, :deadline_exceeded}
          end
          |> Support.unwrap()
        after
          Process.demonitor(monitor, [:flush])
        end
      end,
      :invalid_handle
    )
  end

  @impl true
  def sign(ref, algorithm, bytes, context),
    do: request(ref, {:sign, algorithm, bytes}, context)

  @impl true
  def verify(ref, algorithm, bytes, signature, context),
    do: request(ref, {:verify, algorithm, bytes, signature}, context)

  @impl true
  def unwrap(ref, algorithm, bytes, context),
    do: request(ref, {:unwrap, algorithm, bytes}, context)

  @impl true
  def public_key(ref), do: request(ref, :public_key, default_context())

  @impl true
  def identity(ref), do: request(ref, :identity, default_context())

  defp default_context do
    %RequestSeal.Custody.Context{
      owner: self(),
      deadline: System.monotonic_time(:millisecond) + 5_000
    }
  end

  defp address(ref) do
    {pid, token} = ref.()

    ensure(
      is_pid(pid) and node(pid) == node() and is_binary(token) and byte_size(token) == 32,
      :invalid_handle
    )

    {pid, token}
  end

  defp request(ref, operation, context) do
    {pid, token} = address(ref)
    monitor = Process.monitor(pid)
    reply = :erlang.alias()

    try do
      send(pid, {:request, token, self(), reply, context, operation})

      receive do
        {^reply, result} -> result
        {:DOWN, ^monitor, :process, ^pid, _} -> {:error, :key_not_found}
      after
        RequestSeal.Custody.Context.remaining(context) -> {:error, :deadline_exceeded}
      end
    after
      :erlang.unalias(reply)
      Process.demonitor(monitor, [:flush])
    end
  end

  defp start_holder(state) do
    owner = self()
    token = :crypto.strong_rand_bytes(32)
    # This spawn environment contains no key material. The readiness handshake
    # ensures sensitivity is set before even the initialization message is sent.
    {pid, monitor} = spawn_monitor(fn -> holder_init(owner, token) end)

    try do
      await_holder(pid, monitor, token, :ready, System.monotonic_time(:millisecond) + 5_000)
      send(pid, {:initialize, token, state})
      await_holder(pid, monitor, token, :initialized, System.monotonic_time(:millisecond) + 5_000)
      {pid, token}
    catch
      kind, reason ->
        Process.exit(pid, :kill)
        :erlang.raise(kind, reason, __STACKTRACE__)
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp await_holder(pid, monitor, token, phase, deadline) do
    receive do
      {candidate, ^phase} ->
        if valid_token?(candidate, token),
          do: :ok,
          else: await_holder(pid, monitor, token, phase, deadline)

      {:DOWN, ^monitor, :process, ^pid, _} ->
        ensure(false, :custodian_failure)
    after
      max(0, deadline - System.monotonic_time(:millisecond)) ->
        ensure(false, :deadline_exceeded)
    end
  end

  defp holder_init(owner, token) do
    Process.flag(:sensitive, true)
    monitor = Process.monitor(owner)
    send(owner, {token, :ready})
    holder_initialize(owner, monitor, token)
  end

  defp holder_initialize(owner, monitor, token) do
    receive do
      {:initialize, candidate, state} ->
        if valid_token?(candidate, token) do
          send(owner, {token, :initialized})
          holder_loop(owner, monitor, token, state)
        else
          holder_initialize(owner, monitor, token)
        end

      {:DOWN, ^monitor, :process, ^owner, _} ->
        :ok
    end
  end

  defp holder_loop(owner, monitor, token, state) do
    receive do
      {:DOWN, ^monitor, :process, ^owner, _} ->
        :ok

      {:release, candidate} ->
        if valid_token?(candidate, token),
          do: :ok,
          else: holder_loop(owner, monitor, token, state)

      {:request, candidate, runner, reply, context, operation} ->
        # A queued request cannot start cryptography after its deadline, caller
        # cancellation, or creator death. Replies target a runner-owned alias,
        # automatically revoked when the custody worker is killed.
        if valid_token?(candidate, token) and Process.alive?(owner) and Process.alive?(runner) and
             Process.alive?(context.owner) and RequestSeal.Custody.Context.remaining(context) > 0 do
          result = Support.safe(fn -> holder_operation(operation, state) end, :custodian_failure)

          if RequestSeal.Custody.Context.remaining(context) > 0,
            do: send(reply, {reply, result})
        end

        holder_loop(owner, monitor, token, state)

      {:system, from, _request} ->
        # A plain process deliberately rejects sys state, status, trace, suspend,
        # and replace_state requests rather than exposing a secret-bearing state.
        :gen.reply(from, {:error, :unsupported_operation})
        holder_loop(owner, monitor, token, state)

      _ ->
        holder_loop(owner, monitor, token, state)
    end
  end

  defp valid_token?(candidate, token)
       when is_binary(candidate) and byte_size(candidate) == 32 and
              is_binary(token) and byte_size(token) == 32,
       do: :crypto.hash_equals(candidate, token)

  defp valid_token?(_, _), do: false

  defp holder_operation({:sign, algorithm, bytes}, {bound, material, _, _, capabilities}) do
    ensure(algorithm == bound, :key_mismatch)
    ensure(:sign in capabilities, :unsupported_operation)
    Crypto.sign(algorithm, bytes, material)
  end

  defp holder_operation(
         {:verify, algorithm, bytes, signature},
         {bound, material, public, _, capabilities}
       ) do
    ensure(algorithm == bound, :key_mismatch)
    ensure(:verify in capabilities, :unsupported_operation)
    Crypto.verify(algorithm, bytes, signature, public || material)
  end

  defp holder_operation(:public_key, {_, _, nil, _, _}), do: {:error, :no_public_key}
  defp holder_operation(:public_key, {_, _, public, _, _}), do: {:ok, public}
  defp holder_operation(:identity, {_, _, _, identity, _}), do: identity

  defp holder_operation({:unwrap, algorithm, bytes}, {bound, material, _, _, capabilities}) do
    ensure(algorithm == bound, :key_mismatch)
    ensure(:unwrap in capabilities, :unsupported_operation)
    {:jwe, alg} = bound
    RequestSeal.JOSE.KeyManagement.unwrap(alg, bytes, %{}, material)
  end

  defp derive({:rsa, {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}}, type),
    do: unwrap(PublicKey.import({type || :rsa, n, e}, :raw))

  defp derive({:ec, crv, scalar}, _) do
    {curve, _, _} = Algorithm.curve(crv)
    {point, _} = :crypto.generate_key(:ecdh, curve, scalar)
    unwrap(PublicKey.import({:ec, crv, point}, :raw))
  end

  defp derive({:ed25519, seed}, _) do
    ensure(is_binary(seed) and byte_size(seed) == 32, :invalid_key)
    {public, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    unwrap(PublicKey.import({:ed25519, public}, :raw))
  end

  defp derive({:hmac, _}, _), do: nil
  defp derive(_, _), do: ensure(false, :invalid_key)

  defp decode(value, :pem, jose) do
    ensure(is_binary(value) and byte_size(value) in 1..16_384, :invalid_key)

    ensure(
      not String.contains?(value, ["ENCRYPTED PRIVATE KEY", "Proc-Type: 4,ENCRYPTED"]),
      :unsupported_format
    )

    [entry] = :public_key.pem_decode(value)
    {type, der, encryption} = entry
    ensure(encryption == :not_encrypted, :unsupported_format)

    {material, restriction, expected} =
      case type do
        :RSAPrivateKey -> {{:rsa, canonical(:RSAPrivateKey, der)}, :rsa, nil}
        :ECPrivateKey -> ec_private(canonical(:ECPrivateKey, der))
        :PrivateKeyInfo -> pkcs8(der)
        _ -> ensure(false, :invalid_key)
      end

    {material, restriction, expected, capabilities(jose)}
  end

  defp decode(value, :der, jose) do
    ensure(is_binary(value) and byte_size(value) in 1..16_384, :invalid_key)
    {material, restriction, expected} = pkcs8(value)
    {material, restriction, expected, capabilities(jose)}
  end

  defp decode(value, :jwk, jose) do
    ensure(is_map(value) and not is_struct(value) and map_size(value) <= 32, :invalid_key)
    ensure(not Map.has_key?(value, "oth"), :invalid_key)

    for key <- ~w(alg use key_ops),
        do: ensure(not Map.has_key?(value, key) or value[key] != nil, :invalid_key)

    encryption = jose in ["RSA-OAEP", "RSA-OAEP-256"]
    use = if encryption, do: "enc", else: "sig"
    allowed_ops = if encryption, do: ~w(encrypt decrypt wrapKey unwrapKey), else: ~w(sign verify)
    required_ops = if encryption, do: ~w(decrypt unwrapKey), else: ~w(sign)
    ensure(value["alg"] in [nil, jose] and value["use"] in [nil, use], :key_mismatch)
    ops = value["key_ops"]

    ensure(
      ops == nil or
        (is_list(ops) and length(ops) <= length(allowed_ops) and Enum.uniq(ops) == ops and
           Enum.all?(ops, &(&1 in allowed_ops))),
      :invalid_key
    )

    ensure(ops == nil or Enum.any?(ops, &(&1 in required_ops)), :key_mismatch)

    capabilities =
      cond do
        encryption -> [:unwrap]
        ops == nil or "verify" in ops -> [:sign, :verify]
        true -> [:sign]
      end

    {material, expected} =
      case value do
        %{
          "kty" => "RSA",
          "n" => n,
          "e" => e,
          "d" => d,
          "p" => p,
          "q" => q,
          "dp" => dp,
          "dq" => dq,
          "qi" => qi
        } ->
          values = Enum.map([n, e, d, p, q, dp, dq, qi], &uint/1)
          [n, e, d, p, q, dp, dq, qi] = values

          {{:rsa, {:RSAPrivateKey, :"two-prime", n, e, d, p, q, dp, dq, qi, :asn1_NOVALUE}},
           {:rsa, n, e}}

        %{"kty" => "EC", "crv" => crv, "x" => x, "y" => y, "d" => d} ->
          {_, width, _} = Algorithm.curve(crv)
          x = b64(x)
          y = b64(y)
          d = b64(d)

          ensure(
            byte_size(x) == width and byte_size(y) == width and byte_size(d) == width,
            :invalid_key
          )

          {{:ec, crv, d}, {:ec, crv, <<4, x::binary, y::binary>>}}

        %{"kty" => "OKP", "crv" => "Ed25519", "x" => x, "d" => d} ->
          {{:ed25519, b64(d)}, {:ed25519, b64(x)}}

        %{"kty" => "oct", "k" => k} ->
          {{:hmac, b64(k)}, nil}

        _ ->
          ensure(false, :invalid_key)
      end

    expected =
      if expected == nil do
        nil
      else
        %PublicKey{
          material: expected,
          algorithm: value["alg"],
          use: value["use"],
          operations: ops
        }
      end

    {material, nil, expected, capabilities}
  end

  defp decode(_, _, _), do: ensure(false, :unsupported_format)

  defp capabilities(jose) when jose in ["RSA-OAEP", "RSA-OAEP-256"], do: [:unwrap]
  defp capabilities(_), do: [:sign, :verify]

  defp canonical(type, der) do
    decoded = :public_key.der_decode(type, der)
    ensure(:public_key.der_encode(type, decoded) == der, :invalid_key)
    decoded
  end

  defp pkcs8(der) do
    # public_key's PrivateKeyInfo decoder unwraps RSA-PSS and fills default
    # parameters. Read the container first to preserve absent vs constrained PSS.
    info =
      case :"PKCS-FRAME".decode(:PrivateKeyInfo, der) do
        {:ok, info} -> info
        _ -> ensure(false, :unsupported_format)
      end

    {:ok, encoded} = :"PKCS-FRAME".encode(:PrivateKeyInfo, info)
    ensure(encoded == der, :invalid_key)

    {oid, params, private} =
      case info do
        {:PrivateKeyInfo, :v1, {:PrivateKeyInfo_privateKeyAlgorithm, oid, params}, private, _} ->
          {oid, params, private}

        {:OneAsymmetricKey, :v1, {:PrivateKeyAlgorithmIdentifier, oid, params}, private, _,
         :asn1_NOVALUE} ->
          {oid, params, private}

        _ ->
          ensure(false, :unsupported_format)
      end

    params =
      case params do
        {:asn1_OPENTYPE, bytes} -> bytes
        absent -> absent
      end

    case oid do
      oid when oid in [@rsa, @pss] ->
        ensure(
          if(oid == @pss, do: params == :asn1_NOVALUE, else: params in [:asn1_NOVALUE, <<5, 0>>]),
          :unsupported_format
        )

        {{:rsa, canonical(:RSAPrivateKey, private)}, if(oid == @pss, do: :rsa_pss, else: :rsa),
         nil}

      @ec ->
        curve = :public_key.der_decode(:EcpkParameters, params)
        {:ECPrivateKey, version, scalar, inner, point, attrs} = canonical(:ECPrivateKey, private)
        ensure(inner == :asn1_NOVALUE or inner == curve, :invalid_key)
        ec_private({:ECPrivateKey, version, scalar, curve, point, attrs})

      @ed ->
        ensure(params == :asn1_NOVALUE, :invalid_key)
        <<4, 32, seed::binary-size(32)>> = private
        {{:ed25519, seed}, nil, nil}

      _ ->
        ensure(false, :unsupported_format)
    end
  end

  defp ec_private({:ECPrivateKey, _, scalar, {:namedCurve, oid}, point, _}) do
    crv =
      case oid do
        {1, 2, 840, 10045, 3, 1, 7} -> "P-256"
        {1, 3, 132, 0, 34} -> "P-384"
        _ -> ensure(false, :invalid_key)
      end

    expected = if point == :asn1_NOVALUE, do: nil, else: {:ec, crv, point}
    {{:ec, crv, scalar}, nil, expected}
  end

  defp b64(value) do
    ensure(is_binary(value) and byte_size(value) in 1..21_846, :invalid_key)
    {:ok, bytes} = Base.url_decode64(value, padding: false)
    ensure(Base.url_encode64(bytes, padding: false) == value, :invalid_key)
    bytes
  end

  defp uint(value) do
    ensure(is_binary(value) and byte_size(value) <= 1366, :invalid_key)
    bytes = b64(value)
    ensure(:binary.first(bytes) != 0, :invalid_key)
    :binary.decode_unsigned(bytes)
  end
end
