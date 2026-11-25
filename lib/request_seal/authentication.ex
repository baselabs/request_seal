defmodule RequestSeal.Authentication do
  @moduledoc false
  alias RequestSeal.{
    Body,
    Crypto,
    Custody,
    DenySet,
    Digest,
    Error,
    FieldOccurrence,
    Freshness,
    KeyHandle,
    Message,
    Policy,
    PublicKey,
    SignatureBase,
    SignatureFields,
    Verification
  }

  alias RequestSeal.Replay.Commitment
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.Value

  def verify(message, policy, opts) do
    protect(fn ->
      ensure(proper_list?(opts) and Keyword.keyword?(opts), :invalid_options, :input)

      ensure(
        not Keyword.has_key?(opts, :profile) and not Keyword.has_key?(opts, :principal),
        :invalid_profile,
        :input
      )

      opts = options(opts, [:label, :representation, :digest_state, :capture])
      label = Map.get(opts, :label)
      ensure(SignatureFields.label?(label), :invalid_options, :input)
      ensure(Policy.valid?(policy), :invalid_policy, :input)
      verify_options(opts, policy)
      ensure(Message.validate(message) == :ok, :invalid_message, :input)
      inputs = dictionary(message, "signature-input", policy.max_signatures)
      signatures = dictionary(message, "signature", policy.max_signatures)

      ensure(
        Enum.sort(Map.keys(inputs)) == Enum.sort(Map.keys(signatures)),
        :label_mismatch,
        :fields
      )

      ensure(Map.has_key?(inputs, label), :unknown_label, :fields)

      {result, _cache} =
        verify_label(message, policy, label, inputs[label], signatures[label], opts, %{})

      result
    end)
  end

  # Both entry points use this pipeline. The cache holds base-build results,
  # including failed builds, per label and schema set; cryptography runs on every call.
  @doc false
  def verify_label(message, policy, label, input, signature, opts, cache) do
    prepared =
      protect(fn ->
        ensure(SignatureFields.valid_inner?(input), :invalid_signature_input, :fields)
        params = SignatureFields.parameters(input)
        ensure(SignatureFields.nonce_valid?(params["nonce"]), :limit, :input)
        coverage(input, required(policy.components), policy.extra_components)
        freshness = freshness(params, policy.freshness)

        ensure(
          not Map.has_key?(params, "alg") or params["alg"] in policy.algorithms,
          :algorithm_not_permitted,
          :policy
        )

        {algorithm, key, scope} = resolve(policy, label, params)
        match_algorithm(params, algorithm, :policy)
        ensure(algorithm in policy.algorithms, :algorithm_not_permitted, :policy)
        capture? = Map.get(opts, :capture, false)
        deny = Map.get(policy, :deny)

        ensure(
          not capture? or algorithm not in ["hmac-sha256", {:jws, "HS256"}],
          :invalid_options,
          :input
        )

        ensure(
          deny == nil or algorithm not in ["hmac-sha256", {:jws, "HS256"}],
          :key_fingerprint_unknown,
          :key
        )

        if is_struct(key, PublicKey), do: check_public(deny, key)

        key_evidence? =
          algorithm not in ["hmac-sha256", {:jws, "HS256"}] and
            (match?(%{scope: :key}, policy.replay) or Map.has_key?(opts, :quorum_replay))

        screening = {deny, capture? or key_evidence?, Map.get(policy, :require_issued_for)}
        {:ok, {algorithm, key, scope, screening, params, freshness}}
      end)

    case prepared do
      {:ok, {algorithm, key, scope, screening, params, freshness}} ->
        schemas = policy.field_schemas
        cache_key = {label, schemas}

        built =
          case Map.fetch(cache, cache_key) do
            {:ok, built} -> built
            :error -> protect(fn -> {:ok, build(message, input, schemas)} end)
          end

        cache = Map.put(cache, cache_key, built)

        result =
          case built do
            {:ok, {bytes, components}} ->
              protect(fn ->
                signature_bytes = elem(signature.value, 1)
                public = verify_bytes(algorithm, bytes, signature_bytes, key, screening)
                content = content(message, input, policy.content, opts)

                replay =
                  replay(
                    policy.replay,
                    params,
                    algorithm,
                    freshness,
                    Map.get(opts, :profile, %{name: :rfc9421}),
                    {scope, public || key, components}
                  )

                covered =
                  case SignatureFields.identifiers(input.value) do
                    {:ok, wires} -> wires
                    :error -> fail(:invalid_signature_input, :fields)
                  end

                verification = %Verification{
                  label: label,
                  profile: Map.get(opts, :profile, %{name: :rfc9421}),
                  signature: signature_facts,
                  content: content,
                  freshness: freshness,
                  replay: replay
                }

                case Map.fetch(opts, :quorum_replay) do
                  {:ok, {quorum_scope, identifier}} ->
                    identity = Commitment.select(identifier, params, components)
                    digest = Commitment.derive("rfc9421/quorum", quorum_scope, identity)
                    {:ok, {verification, Commitment.key_identity(public || key), digest}}

                  :error ->
                    {:ok, verification}
                end
              end)

            error ->
              error
          end

        {result, cache}

      error ->
        {error, cache}
    end
  end

  @doc false
  def preflight(input, components, extra, freshness_policy) do
    protect(fn ->
      coverage(input, required(components), extra)
      {:ok, freshness(SignatureFields.parameters(input), freshness_policy)}
    end)
  end

  @doc false
  def dictionaries(message, max) do
    protect(fn ->
      entries = dictionary_entries(message, "signature-input", max, true)
      signatures = dictionary(message, "signature", max)
      inputs = Map.new(entries)

      ensure(
        Enum.sort(Map.keys(inputs)) == Enum.sort(Map.keys(signatures)),
        :label_mismatch,
        :fields
      )

      {:ok, {entries, signatures}}
    end)
  end

  def sign(message, spec, signer, opts) do
    protect(fn ->
      opts = options(opts, [:field_schemas, :signing_timeout])
      schemas = Map.get(opts, :field_schemas, %{})
      ensure(Policy.schemas?(schemas), :invalid_options, :input)
      timeout = Map.get(opts, :signing_timeout, 5_000)
      ensure(is_integer(timeout) and timeout in 1..300_000, :invalid_options, :input)

      ensure(
        is_map(spec) and
          Enum.all?([:label, :signature_input, :algorithm], &Map.has_key?(spec, &1)) and
          Enum.all?(Map.keys(spec), &(&1 in [:label, :signature_input, :algorithm, :issued_for])) and
          KeyHandle.purpose?(Map.get(spec, :issued_for)),
        :invalid_options,
        :input
      )

      ensure(
        SignatureFields.label?(spec.label) and SignatureFields.algorithm?(spec.algorithm) and
          is_struct(signer, KeyHandle),
        :invalid_options,
        :input
      )

      ensure(signer.algorithm == spec.algorithm, :signer_algorithm_mismatch, :input)
      purpose = Map.get(spec, :issued_for)
      ensure(purpose == signer.issued_for, :issued_for_mismatch, :input)

      ensure(Message.validate(message) == :ok, :invalid_message, :input)
      inputs = dictionary(message, "signature-input", 16, false)
      signatures = dictionary(message, "signature", 16, false)

      ensure(
        not Map.has_key?(inputs, spec.label) and not Map.has_key?(signatures, spec.label),
        :label_in_use,
        :fields
      )

      ensure(
        Enum.sort(Map.keys(inputs)) == Enum.sort(Map.keys(signatures)),
        :label_mismatch,
        :fields
      )

      ensure(map_size(inputs) < 16, :limit, :input)
      input = inner(spec.signature_input)
      params = SignatureFields.parameters(input)
      match_algorithm(params, spec.algorithm, :input)
      {bytes, _components} = build(message, input, schemas)

      signature = sign_bytes(signer, purpose, bytes, timeout)

      input_wire =
        case SF.serialize(
               %Value{type: :dictionary, value: [{spec.label, input}]},
               SignatureFields.schema(:dictionary)
             ) do
          {:ok, wire} -> wire
          {:error, %{reason: :limit}} -> fail(:limit, :input)
          _ -> fail(:invalid_signature_input, :fields)
        end

      signature_wire =
        case SF.serialize(
               %Value{
                 type: :dictionary,
                 value: [{spec.label, %Value{type: :item, value: {:bytes, signature}}}]
               },
               SignatureFields.schema(:dictionary, [:bytes], false)
             ) do
          {:ok, wire} -> wire
          {:error, %{reason: :limit}} -> fail(:signer_failed, :crypto)
          _ -> fail(:signer_failed, :crypto)
        end

      fields =
        message.fields ++
          [occurrence("Signature-Input", input_wire), occurrence("Signature", signature_wire)]

      output = %{message | fields: fields}
      ensure(Message.validate(output) == :ok, :invalid_message, :input)
      # Appending cannot exceed a field/dictionary ceiling even when each occurrence fits.
      dictionary(output, "signature-input", 16)
      dictionary(output, "signature", 16)
      {:ok, output}
    end)
  end

  defp sign_bytes(%KeyHandle{} = handle, purpose, bytes, timeout) do
    case RequestSeal.Signing.custody_sign(handle, bytes, timeout, purpose) do
      {:ok, sig} -> sig
      {:error, %Custody.Error{} = source} -> fail(:signing_failed, :crypto, nil, source)
    end
  end

  defp options(opts, allowed) do
    ensure(proper_list?(opts) and Keyword.keyword?(opts), :invalid_options, :input)
    keys = Keyword.keys(opts)

    ensure(
      length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in allowed)),
      :invalid_options,
      :input
    )

    Map.new(opts)
  end

  defp proper_list?([]), do: true
  defp proper_list?([_ | tail]), do: proper_list?(tail)
  defp proper_list?(_), do: false

  defp verify_options(opts, policy) do
    ensure(is_boolean(Map.get(opts, :capture, false)), :invalid_options, :input)

    ensure(
      not (Map.has_key?(opts, :representation) and Map.has_key?(opts, :digest_state)),
      :invalid_options,
      :input
    )

    if Map.has_key?(opts, :representation) do
      ensure(
        is_map(policy.content) and policy.content.kind == :representation and
          Body.validate(opts.representation) == :ok,
        :invalid_options,
        :input
      )
    end

    if Map.has_key?(opts, :digest_state) do
      ensure(
        is_map(policy.content) and match?(%Digest{}, opts.digest_state) and
          opts.digest_state.kind == policy.content.kind,
        :invalid_options,
        :input
      )
    end
  end

  defp dictionary(message, name, max, required \\ true),
    do: Map.new(dictionary_entries(message, name, max, required))

  defp dictionary_entries(message, name, max, required) do
    missing = if name == "signature", do: :missing_signature, else: :missing_signature_input
    invalid = if name == "signature", do: :invalid_signature_field, else: :invalid_signature_input

    schema =
      if name == "signature",
        do: SignatureFields.schema(:dictionary, [:bytes], false),
        else: SignatureFields.schema(:dictionary)

    limits =
      if name == "signature",
        do: [max_members: max, max_value_bytes: 1024],
        else: [max_members: max]

    case SF.parse_field_validated(
           message,
           name,
           schema,
           :headers,
           [unique_keys: :all, unique_parameters: true] ++ limits
         ) do
      {:ok, parsed} ->
        if name == "signature-input" do
          Enum.each(parsed.value, fn {_, value} ->
            ensure(value.type == :inner_list, invalid, :fields)
          end)
        end

        parsed.value

      {:error, %{reason: :missing_field}} ->
        ensure(not required, missing, :fields)
        []

      {:error, %{reason: :limit}} ->
        fail(:limit, :input)

      {:error, %{reason: :duplicate_key}} ->
        fail(:duplicate_label, :fields)

      {:error, %{reason: :duplicate_parameter}} ->
        fail(:duplicate_parameter, :fields)

      _ ->
        fail(invalid, :fields)
    end
  end

  defp inner(value) do
    case SignatureFields.inner(value) do
      {:ok, input} -> input
      {:error, %{reason: :limit}} -> fail(:limit, :input)
      _ -> fail(:invalid_signature_input, :fields)
    end
  end

  defp required(components), do: inner(components)

  defp coverage(input, required, extra) do
    covered = MapSet.new(SignatureFields.identities(input.value))
    needed = MapSet.new(SignatureFields.identities(required.value))
    ensure(MapSet.subset?(needed, covered), :missing_required_component, :policy)
    ensure(extra == :allow or MapSet.subset?(covered, needed), :unexpected_component, :policy)
  end

  defp match_algorithm(params, {:jws, _}, layer),
    do: ensure(not Map.has_key?(params, "alg"), :algorithm_mismatch, layer)

  defp match_algorithm(params, algorithm, layer),
    do:
      ensure(
        not Map.has_key?(params, "alg") or params["alg"] == algorithm,
        :algorithm_mismatch,
        layer
      )

  defp resolve(policy, label, params) do
    resolved =
      callback(
        fn ->
          policy.key_resolver.(%{keyid: params["keyid"], label: label, tag: params["tag"]})
        end,
        :key_resolver_failed,
        :key
      )

    case resolved do
      :error ->
        fail(:unknown_key, :key)

      {:ok, %{algorithm: algorithm, key: key} = result} ->
        scope = Map.get(result, :replay_scope)

        accepts_scope =
          match?(%{scope: kind} when kind in [:credential, :principal], policy.replay)

        ensure(
          map_size(result) == 2 or
            (accepts_scope and map_size(result) == 3 and Map.has_key?(result, :replay_scope)),
          :key_resolver_failed,
          :key
        )

        ensure(SignatureFields.algorithm?(algorithm), :key_resolver_failed, :key)
        ensure(match?(%PublicKey{}, key) or match?(%KeyHandle{}, key), :key_resolver_failed, :key)
        # Symmetric verification keeps the secret behind a custody handle.
        ensure(
          algorithm not in ["hmac-sha256", {:jws, "HS256"}] or match?(%KeyHandle{}, key),
          :key_resolver_failed,
          :key
        )

        handle_purpose = if is_struct(key, KeyHandle), do: Map.get(key, :issued_for)
        purpose = Map.get(result, :issued_for, handle_purpose)
        ensure(KeyHandle.purpose?(purpose), :key_resolver_failed, :key)

        if is_struct(key, KeyHandle) do
          ensure(key.algorithm == algorithm, :algorithm_mismatch, :key)
          ensure(purpose == handle_purpose, :key_issued_for_mismatch, :key)
        end

        ensure(
          Map.get(policy, :require_issued_for) == purpose,
          :key_issued_for_mismatch,
          :key
        )

        ensure(purpose == nil or KeyHandle.family(algorithm) == :http, :algorithm_mismatch, :key)

        {algorithm, key, scope}

      _ ->
        fail(:key_resolver_failed, :key)
    end
  end

  defp build(message, input, schemas) do
    case SignatureBase.build_with_components(message, input, field_schemas: schemas) do
      {:ok, bytes} -> bytes
      {:error, %{reason: reason}} -> fail(:signature_base_failed, :crypto, reason)
    end
  end

  defp check_public(deny, key) do
    case DenySet.check(deny, key) do
      :ok -> :ok
      {:error, :key_denied} -> fail(:key_denied, :key)
      {:error, :key_fingerprint_unknown} -> fail(:key_fingerprint_unknown, :key)
    end
  end

  defp verify_bytes(_, bytes, signature, %KeyHandle{} = handle, {deny, capture?, purpose}) do
    opts = [issued_for: purpose, operation: :http]

    result =
      if deny != nil or capture?,
        do: Custody.verify_bound(handle, bytes, signature, deny, opts),
        else: Custody.verify(handle, bytes, signature, opts)

    case result do
      :ok -> nil
      {:ok, public} -> public
      {:error, %{reason: :key_denied}} -> fail(:key_denied, :key)
      {:error, %{reason: :key_fingerprint_unknown}} when deny == nil ->
        fail(:invalid_options, :input)

      {:error, %{reason: :key_fingerprint_unknown}} -> fail(:key_fingerprint_unknown, :key)
      {:error, %{reason: :invalid_signature}} -> fail(:invalid_signature, :crypto)
      _ -> fail(:verifier_failed, :crypto)
    end
  end

  defp verify_bytes(algorithm, bytes, signature, key, _) do
    case Crypto.verify(algorithm, bytes, signature, key) do
      :ok -> key
      {:error, %{reason: :invalid_signature}} -> fail(:invalid_signature, :crypto)
      _ -> fail(:verifier_failed, :crypto)
    end
  end

  defp freshness(_, :not_evaluated), do: :not_evaluated

  defp freshness(params, policy) do
    with {:ok, interval} <- Freshness.read(policy.clock),
         {:ok, facts} <- Freshness.check(params, policy, interval) do
      facts
    else
      {:error, reason} -> fail(reason, :freshness)
    end
  end

  defp replay(:not_required, _, _, _, _, _), do: :not_required

  defp replay(%{scope: kind} = policy, params, _, freshness, profile, {scope, key, components}) do
    ensure(profile == %{name: :rfc9421}, :invalid_policy, :input)
    ensure(retain_until(freshness) <= policy.retain_until, :retention_exceeded, :replay)

    scope =
      case {kind, scope} do
        {:key, _} -> {:key, Commitment.key_identity(key)}
        {:credential, {:credential, _, _}} -> scope
        {:principal, {:principal, _}} -> scope
        _ -> nil
      end

    identity = Commitment.select(policy.identifier, params, components)

    case Commitment.key(scope, identity) do
      {:ok, digest} ->
        claim(
          Map.put(policy, :commitment, fn _ -> {:ok, digest} end),
          %{},
          policy.retain_until
        )

      {:error, :ambiguous_replay_scope} ->
        fail(:ambiguous_replay_scope, :replay)

      {:error, :missing_replay_identifier} ->
        fail(:missing_replay_identifier, :replay)
    end
  end

  defp replay(policy, params, algorithm, freshness, profile, _) do
    identifier = params["nonce"]

    ensure(
      is_binary(identifier) and byte_size(identifier) > 0,
      :missing_replay_identifier,
      :replay
    )

    facts = %{
      identifier: identifier,
      algorithm: algorithm,
      keyid: params["keyid"],
      tag: params["tag"],
      created: params["created"],
      expires: params["expires"],
      profile: profile
    }

    claim(policy, facts, retain_until(freshness))
  end

  @doc false
  def retain_until(freshness) do
    # Expiration is exclusive; max-age accepts its final second.
    bounds = if freshness.expires, do: [freshness.expires + freshness.skew], else: []

    bounds =
      if freshness.max_age,
        do: [freshness.created + freshness.max_age + freshness.skew + 1 | bounds],
        else: bounds

    Enum.min(bounds)
  end

  defp claim(policy, facts, retain_until) do
    ensure(retain_until <= 253_402_300_799, :retention_exceeded, :replay)

    case RequestSeal.Replay.commit(policy, facts, retain_until) do
      {:ok, receipt} -> receipt
      {:error, %{reason: reason}} -> fail(reason, :replay)
    end
  end

  defp content(_, _, :not_required, _), do: :not_required

  defp content(message, input, policy, opts) do
    name = if policy.kind == :content, do: "content-digest", else: "repr-digest"

    ensure(
      Enum.any?(input.value, fn
        %Value{value: {:string, ^name}, parameters: params} ->
          # Full field coverage, not a dictionary key, related request or binary wrap.
          permitted = if policy.section == :trailers, do: ["tr", "sf"], else: ["sf"]

          Enum.all?(params, fn {key, value} -> key in permitted and value == {:boolean, true} end) and
            List.keymember?(params, "tr", 0) == (policy.section == :trailers)

        _ ->
          false
      end),
      :digest_not_covered,
      :content
    )

    section = if policy.section == :headers, do: message.fields, else: message.trailers
    ensure(is_list(section), :body_unavailable, :content)
    fields = Enum.filter(section, &(String.downcase(&1.name) == name))
    size = Enum.reduce(fields, 0, &(byte_size(&1.value) + &2 + 2))
    ensure(size <= 65_538, :limit, :input)

    expected =
      case Digest.parse(Enum.map_join(fields, ", ", & &1.value)) do
        {:ok, value} -> value
        {:error, %{reason: :limit}} -> fail(:limit, :input)
        _ -> fail(:digest_unsupported, :content)
      end

    supported = for {name, _} <- expected.value, name in ["sha-256", "sha-512"], do: name

    ensure(
      supported != [] and Enum.all?(supported, &(&1 in policy.algorithms)),
      :digest_unsupported,
      :content
    )

    result =
      if Map.has_key?(opts, :digest_state) do
        Digest.check_stream_validated(opts.digest_state, message, section: policy.section)
      else
        check_opts = [section: policy.section]

        check_opts =
          if policy.kind == :representation,
            do: Keyword.put(check_opts, :representation, Map.get(opts, :representation)),
            else: check_opts

        Digest.check_validated(message, policy.kind, check_opts)
      end

    case result do
      {:ok, facts} ->
        facts

      {:error, %{reason: :mismatch}} ->
        fail(:digest_mismatch, :content)

      {:error, %{reason: reason}}
      when reason in [:invalid_body, :body_unavailable, :representation_required] ->
        fail(:body_unavailable, :content)

      {:error, %{reason: :limit}} ->
        fail(:limit, :input)

      _ ->
        fail(:digest_unsupported, :content)
    end
  end

  defp occurrence(name, value) do
    case FieldOccurrence.new(%{name: name, value: value, section: :headers, provenance: :caller}) do
      {:ok, field} -> field
      {:error, _} -> fail(:invalid_signature_field, :fields)
    end
  end

  defp callback(fun, reason, layer) do
    fun.()
  rescue
    _ -> fail(reason, layer)
  catch
    _, _ -> fail(reason, layer)
  end

  defp ensure(true, _, _), do: :ok
  defp ensure(_, reason, layer), do: fail(reason, layer)

  @spec fail(term(), atom()) :: no_return()
  @spec fail(term(), atom(), atom() | nil) :: no_return()

  @spec fail(term(), atom(), atom() | nil, RequestSeal.Custody.Error.t() | nil) ::
          no_return()
  defp fail(reason, layer, detail \\ nil, source \\ nil),
    do: throw({:authentication_error, reason, layer, detail, source})

  defp protect(fun) do
    fun.()
  rescue
    # Verify and sign are total at their entry points: an unexpected fault is a
    # bounded :internal error, never an escaping raise, with the exception class
    # observable in detail and telemetry.
    exception -> {:error, Error.new(:internal, :internal, exception_class(exception))}
  catch
    {:authentication_error, reason, layer, detail, source} ->
      {:error, Error.new(reason, layer, detail, source)}

    :exit, _ ->
      {:error, Error.new(:internal, :internal, :exit)}

    _, _ ->
      {:error, Error.new(:internal, :internal, :throw)}
  end

  defp exception_class(%{__struct__: module}), do: module
end
