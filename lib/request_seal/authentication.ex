defmodule RequestSeal.Authentication do
  @moduledoc false
  alias RequestSeal.{
    Body,
    Crypto,
    Digest,
    Error,
    FieldOccurrence,
    Message,
    KeyIdentity,
    Policy,
    PublicKey,
    SignatureBase,
    SignatureFields,
    Verification
  }

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

      opts = options(opts, [:label, :representation, :digest_state])
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

      case result do
        {:ok, verification, _identity} -> {:ok, verification}
        error -> error
      end
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
        ensure(params["nonce"] == nil or byte_size(params["nonce"]) <= 1024, :limit, :input)
        coverage(input, required(policy.components), policy.extra_components)
        freshness = freshness(params, policy.freshness)

        ensure(
          not Map.has_key?(params, "alg") or params["alg"] in policy.algorithms,
          :algorithm_not_permitted,
          :policy
        )

        {algorithm, key, identity} = resolve(policy, label, params)
        match_algorithm(params, algorithm, :policy)
        ensure(algorithm in policy.algorithms, :algorithm_not_permitted, :policy)
        {:ok, {algorithm, key, identity, params, freshness}}
      end)

    case prepared do
      {:ok, {algorithm, key, identity, params, freshness}} ->
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
            {:ok, bytes} ->
              protect(fn ->
                verify_bytes(algorithm, bytes, elem(signature.value, 1), key)
                content = content(message, input, policy.content, opts)

                replay =
                  replay(
                    policy.replay,
                    params,
                    algorithm,
                    freshness,
                    Map.get(opts, :profile, %{name: :rfc9421})
                  )

                {:ok,
                 %Verification{
                   label: label,
                   profile: Map.get(opts, :profile, %{name: :rfc9421}),
                   signature: %{
                     algorithm: algorithm,
                     covered: SignatureFields.identifiers(input.value),
                     parameters: params,
                     keyid: params["keyid"],
                     crypto: :valid
                   },
                   content: content,
                   freshness: freshness,
                   replay: replay
                 }, identity}
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
      opts = options(opts, [:field_schemas])
      schemas = Map.get(opts, :field_schemas, %{})
      ensure(Policy.schemas?(schemas), :invalid_options, :input)

      ensure(
        is_map(spec) and map_size(spec) == 3 and
          Enum.all?([:label, :signature_input, :algorithm], &Map.has_key?(spec, &1)),
        :invalid_options,
        :input
      )

      ensure(
        SignatureFields.label?(spec.label) and SignatureFields.algorithm?(spec.algorithm) and
          is_function(signer, 2),
        :invalid_options,
        :input
      )

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
      bytes = build(message, input, schemas)

      signature =
        case callback(fn -> signer.(spec.algorithm, bytes) end, :signer_failed, :crypto) do
          {:ok, sig} when is_binary(sig) and byte_size(sig) in 1..1024 -> sig
          _ -> fail(:signer_failed, :crypto)
        end

      {:ok, input_wire} =
        SF.serialize(
          %Value{type: :dictionary, value: [{spec.label, input}]},
          SignatureFields.schema(:dictionary)
        )

      {:ok, signature_wire} =
        SF.serialize(
          %Value{
            type: :dictionary,
            value: [{spec.label, %Value{type: :item, value: {:bytes, signature}}}]
          },
          SignatureFields.schema(:dictionary, [:bytes], false)
        )

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

    case SF.parse_field(
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

      {:ok, %{algorithm: algorithm, key: key} = result} when map_size(result) in [2, 3] ->
        ensure(SignatureFields.algorithm?(algorithm), :key_resolver_failed, :key)
        ensure(match?(%PublicKey{}, key) or is_function(key, 3), :key_resolver_failed, :key)
        # Symmetric verification must keep the secret behind the caller function.
        ensure(
          algorithm not in ["hmac-sha256", {:jws, "HS256"}] or is_function(key, 3),
          :key_resolver_failed,
          :key
        )

        ensure(
          Enum.all?(Map.keys(result), &(&1 in [:algorithm, :key, :identity])),
          :key_resolver_failed,
          :key
        )

        ensure(
          not Map.has_key?(result, :identity) or match?(%KeyIdentity{}, result.identity),
          :key_resolver_failed,
          :key
        )

        identity = identity(key, Map.get(result, :identity))
        {algorithm, key, identity}

      _ ->
        fail(:key_resolver_failed, :key)
    end
  end

  defp identity(%PublicKey{} = key, supplied) do
    derived = %KeyIdentity{kind: :public, value: key.material}
    ensure(supplied == nil or KeyIdentity.same?(derived, supplied), :key_resolver_failed, :key)
    derived
  end

  defp identity(_, nil), do: %KeyIdentity{kind: :unknown}
  defp identity(_, %KeyIdentity{kind: :unknown, value: nil} = id), do: id

  defp identity(_, %KeyIdentity{} = id) do
    ensure(KeyIdentity.same?(id, id), :key_resolver_failed, :key)
    id
  end

  defp identity(_, _), do: fail(:key_resolver_failed, :key)

  defp build(message, input, schemas) do
    case SignatureBase.build(message, input, field_schemas: schemas) do
      {:ok, bytes} -> bytes
      {:error, %{reason: reason}} -> fail(:signature_base_failed, :crypto, reason)
    end
  end

  defp verify_bytes(algorithm, bytes, signature, key) when is_function(key, 3) do
    case callback(fn -> key.(algorithm, bytes, signature) end, :verifier_failed, :crypto) do
      :ok -> :ok
      {:error, _} -> fail(:invalid_signature, :crypto)
      _ -> fail(:verifier_failed, :crypto)
    end
  end

  defp verify_bytes(algorithm, bytes, signature, key) do
    case Crypto.verify(algorithm, bytes, signature, key) do
      :ok -> :ok
      {:error, %{reason: :invalid_signature}} -> fail(:invalid_signature, :crypto)
      _ -> fail(:verifier_failed, :crypto)
    end
  end

  defp freshness(_, :not_evaluated), do: :not_evaluated

  defp freshness(params, policy) do
    now = callback(policy.clock, :invalid_clock, :freshness)

    ensure(
      is_integer(now) and now >= 0 and now <= 253_402_300_799,
      :invalid_clock,
      :freshness
    )

    created = params["created"]
    expires = params["expires"]
    ensure(policy.max_age == nil or created != nil, :missing_created, :freshness)
    ensure(not policy.require_expires or expires != nil, :missing_expires, :freshness)
    ensure(created == nil or created <= now + policy.skew, :created_in_future, :freshness)
    earliest = max(now - policy.skew, created || now - policy.skew)
    ensure(expires == nil or expires > earliest, :expired, :freshness)
    ensure(policy.max_age == nil or earliest <= created + policy.max_age, :too_old, :freshness)
    %{now: now, created: created, expires: expires, max_age: policy.max_age, skew: policy.skew}
  end

  defp replay(:not_required, _, _, _, _), do: :not_required

  defp replay(policy, params, algorithm, freshness, profile) do
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

    # Expiration is exclusive; max-age accepts its final second.
    bounds = if freshness.expires, do: [freshness.expires + freshness.skew], else: []

    bounds =
      if freshness.max_age,
        do: [freshness.created + freshness.max_age + freshness.skew + 1 | bounds],
        else: bounds

    retain_until = Enum.min(bounds)
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
        Digest.check_stream(opts.digest_state, message, section: policy.section)
      else
        check_opts = [section: policy.section]

        check_opts =
          if policy.kind == :representation,
            do: Keyword.put(check_opts, :representation, Map.get(opts, :representation)),
            else: check_opts

        Digest.check(message, policy.kind, check_opts)
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
    {:ok, field} =
      FieldOccurrence.new(%{name: name, value: value, section: :headers, provenance: :caller})

    field
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

  defp fail(reason, layer, detail \\ nil),
    do: throw({:authentication_error, reason, layer, detail})

  defp protect(fun) do
    fun.()
  catch
    {:authentication_error, reason, layer, detail} -> {:error, Error.new(reason, layer, detail)}
  end
end
