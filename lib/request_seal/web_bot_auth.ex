defmodule RequestSeal.WebBotAuth do
  @moduledoc """
  Source-bound HTTP request signing and verification for
  [draft-ietf-webbotauth-httpsig-protocol-00](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html).

  Caller clocks range from 0 through 253,402,300,799 Unix seconds.

  `verify/3` validates every `web-bot-auth` signature independently. It requires
  created/expires, a SHA-256 JWK thumbprint key ID, authority or target URI coverage,
  and a matching dictionary Signature-Agent member when present. Legacy strings
  reject. Caller trust resolves the (URL, key) pair before agent attribution.
  Nested signature coverage includes the inner input and every inner component.
  One replay claim follows validation of the entire envelope.

  Options are `:representation`, `:digest_state` (generic digest contracts), and
  `:timeout` (1..300,000 ms, default 5,000, one discovery/trust deadline).
  Unresolved associations return `:agent_unresolved` with a bounded detail;
  they never imply invalid cryptography or populate a URL principal. Policy
  explicitly permits held keys when desired. No network or store is started.

  `sign/4` accepts `label`, `agent` (`location`, `type`), public `key`, `algorithm`,
  `created`, `expires`, and `nonce` (string or nil); optional `components` adds
  identifiers to authority and the matching agent member. The key supplies its thumbprint;
  private material remains behind the arity-two signer. Lifetimes are positive
  and at most 86,400 seconds. The only option is `:field_schemas`.
  Signing adds a dictionary member without replacing other agent members.
  Authorization always remains unevaluated. See `RequestSeal.Error` for reasons.
  """
  alias RequestSeal.{
    Authentication,
    Error,
    FieldOccurrence,
    Message,
    PublicKey,
    Replay,
    SignatureFields
  }

  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.Value
  alias RequestSeal.Discovery.{Cache, KeySet, Resolution, Source, Support}
  alias RequestSeal.WebBotAuth.{Policy, Verification}
  @revision "draft-ietf-webbotauth-httpsig-protocol-00"
  @profile %{name: :web_bot_auth, revision: @revision}
  # RFC 9421 Appendix B.1 public test keys, identified by RFC 7638/8037 thumbprints.
  @test_keys ~w(BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U)
  @doc "Verify all selected request signatures, then commit replay once."
  @spec verify(Message.t(), Policy.t(), keyword()) ::
          {:ok, Verification.t()} | {:error, Error.t()}
  def verify(message, policy, opts \\ []) do
    protect(fn ->
      ensure(Policy.valid?(policy), :invalid_policy, :input)
      options(opts, [:representation, :digest_state, :timeout])
      timeout = Keyword.get(opts, :timeout, 5000)
      ensure(is_integer(timeout) and timeout in 1..300_000, :invalid_options, :input)

      ensure(
        Message.validate(message) == :ok and message.kind == :request,
        :invalid_message,
        :input
      )

      {entries, _signatures} = unwrap(Authentication.dictionaries(message, policy.max_signatures))

      {selected, ignored} =
        Enum.split_with(entries, fn {_, v} ->
          SignatureFields.parameters(v)["tag"] == "web-bot-auth"
        end)

      ensure(policy.untagged != :reject or ignored == [], :unexpected_signature, :policy)
      ensure(selected != [], :no_web_bot_auth_signature, :fields)
      agents = agents(message)

      agent_field_present? =
        Enum.any?(message.fields, &(String.downcase(&1.name) == "signature-agent"))

      deadline = System.monotonic_time(:millisecond) + timeout
      generic_opts = Keyword.drop(opts, [:timeout])

      results =
        Enum.map(selected, fn {label, input} ->
          ensure(SignatureFields.valid_inner?(input), :invalid_signature_input, :fields)
          params = SignatureFields.parameters(input)
          ensure(Source.thumbprint?(params["keyid"]), :invalid_keyid, :policy)

          ensure(
            policy.test_keys == :allow or params["keyid"] not in @test_keys,
            :test_key_rejected,
            :policy
          )

          ids = SignatureFields.identities(input.value)

          ensure(
            {"@authority", []} in ids or {"@target-uri", []} in ids,
            :missing_required_component,
            :policy
          )

          agent = Map.get(agents, label)
          # Presence binds this label even when another member covers the same URL.
          ensure(
            agent != nil or not agent_field_present?,
            :agent_unresolved,
            :key,
            :missing_member
          )

          if agent != nil do
            ensure(
              {"signature-agent", [{"key", {:string, label}}]} in ids,
              :missing_required_component,
              :policy
            )
          end

          ensure(is_integer(params["created"]), :missing_created, :freshness)
          ensure(is_integer(params["expires"]), :missing_expires, :freshness)

          ensure(
            params["expires"] > params["created"] and
              params["expires"] - params["created"] <= policy.max_lifetime,
            :lifetime_exceeded,
            :freshness
          )

          now = clock(policy.freshness.clock)
          ensure(params["created"] <= now + policy.freshness.skew, :created_in_future, :freshness)
          ensure(now < params["expires"] + policy.freshness.skew, :expired, :freshness)

          ensure(
            policy.freshness.max_age == nil or
              now - policy.freshness.skew <= params["created"] + policy.freshness.max_age,
            :too_old,
            :freshness
          )

          {algorithm, key, principal} = resolve(agent, label, params, policy, deadline)

          components =
            required(
              policy.components,
              if(agent, do: [component("signature-agent", [{"key", {:string, label}}])], else: [])
            )

          p =
            unwrap(
              RequestSeal.Policy.new(%{
                algorithms: policy.algorithms,
                components: components,
                key_resolver: fn _ -> {:ok, %{algorithm: algorithm, key: key}} end,
                freshness: Map.put(policy.freshness, :require_expires, true),
                content: policy.content,
                replay: :not_required,
                max_signatures: policy.max_signatures,
                field_schemas: schemas(policy.field_schemas)
              })
            )

          verification = unwrap(RequestSeal.verify(message, p, [label: label] ++ generic_opts))

          {label, %{verification | profile: @profile, principal: principal}}
        end)

      evidence = nested(selected, entries)
      replay = replay(policy.replay, results)

      {:ok,
       %Verification{
         profile: @profile,
         signatures: Map.new(results, fn {l, v} -> {l, %{v | replay: replay}} end),
         evidence: evidence,
         ignored: Enum.map(ignored, &elem(&1, 0)),
         replay: replay
       }}
    end)
  end

  defp agents(message) do
    fields = Enum.filter(message.fields, &(String.downcase(&1.name) == "signature-agent"))

    if fields == [] do
      %{}
    else
      ensure(
        not Enum.any?(fields, &String.starts_with?(String.trim_leading(&1.value), "\"")),
        :invalid_signature_agent,
        :fields,
        :legacy_string
      )

      case SF.parse_field(message, "signature-agent", agent_schema(), :headers,
             unique_keys: :all,
             unique_parameters: true
           ) do
        {:ok, value} ->
          Map.new(value.value, fn {label, member} -> {label, agent_member(member)} end)

        {:error, %{reason: :duplicate_key}} ->
          fail(:invalid_signature_agent, :fields, :duplicate_member)

        {:error, %{reason: :limit}} ->
          fail(:limit, :input)

        _ ->
          fail(:invalid_signature_agent, :fields, :invalid_dictionary)
      end
    end
  end

  defp agent_member(%Value{type: :item, value: {:string, location}, parameters: params}) do
    ensure(
      Enum.all?(params, fn {_, {type, _}} -> type == :token end),
      :invalid_signature_agent,
      :fields,
      :invalid_member
    )

    uri = URI.parse(location)

    ensure(
      byte_size(location) in 1..2048 and Regex.match?(~r/\A[\x21-\x7e]+\z/, location) and
        String.downcase(uri.scheme || "") == "https" and is_binary(uri.host) and uri.host != "" and
        uri.userinfo == nil and uri.port in 1..65535 and not String.contains?(location, "\\") and
        not Regex.match?(~r/%(?![a-fA-F0-9]{2})/, location),
      :invalid_signature_agent,
      :fields,
      :invalid_member
    )

    type =
      case List.keyfind(params, "type", 0) do
        nil -> :directory
        {_, {:token, "directory"}} -> :directory
        {_, {:token, "jwks_uri"}} -> :jwks_uri
        {_, {:token, "cimd"}} -> :cimd
        _ -> :unsupported
      end

    %{location: location, type: type}
  end

  defp agent_member(_), do: fail(:invalid_signature_agent, :fields, :invalid_member)

  defp resolve(agent, label, params, policy, deadline) do
    association = protect(fn -> associated(agent, params, policy, deadline) end)

    case association do
      {:ok, result} ->
        result

      {:error, %Error{reason: :agent_unresolved, detail: detail} = error} ->
        case policy.unresolved do
          {:held_keys, resolver}
          when detail not in [:revoked_key, :source_mismatch, :not_an_origin] ->
            held(resolver, label, params, policy, deadline)

          _ ->
            throw({:web_bot_auth_error, error})
        end

      {:error, error} ->
        throw({:web_bot_auth_error, error})
    end
  end

  defp associated(nil, _, _, _), do: fail(:agent_unresolved, :key, :missing_member)

  defp associated(%{type: :unsupported}, _, _, _),
    do: fail(:agent_unresolved, :key, :unsupported_type)

  defp associated(agent, params, policy, deadline) do
    uri = URI.parse(agent.location)

    if agent.type == :directory do
      ensure(
        uri.path in [nil, ""] and uri.query == nil and uri.fragment == nil and
          agent.location == ascii_origin(uri),
        :agent_unresolved,
        :key,
        :not_an_origin
      )
    end

    identifier =
      if agent.type == :directory,
        do: Source.origin(uri) <> "/.well-known/http-message-signatures-directory",
        else: normalize(agent.location)

    request = %{identifier: identifier, location: agent.location, type: agent.type}
    configured = bounded(fn -> policy.agents.(request) end, deadline)

    source =
      case configured do
        {:ok, %Source{} = s} -> s
        {:ok, %KeySet{source: s}} -> s
        _ -> fail(:agent_unresolved, :key, :untrusted_agent)
      end

    ensure(match?(%Source{}, source), :agent_unresolved, :key, :source_mismatch)

    ensure(
      source.type == agent.type and source_identifier(source) == identifier and
        (agent.type == :directory or
           source.location == hd(String.split(agent.location, "#", parts: 2))),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    # Revalidate caller structs, including redirect controls, before any network.
    case Source.new(Map.from_struct(source)) do
      {:ok, ^source} -> :ok
      _ -> fail(:agent_unresolved, :key, :source_mismatch)
    end

    ensure(source.max_redirects == 0, :agent_unresolved, :key, :source_mismatch)
    ensure(params["keyid"] not in source.revoked, :agent_unresolved, :key, :revoked_key)
    now = clock(policy.freshness.clock)

    {resolution, revision} =
      case configured do
        {:ok, %KeySet{} = set} ->
          case KeySet.lookup_at(set, params["keyid"], policy.algorithms, now) do
            {:ok, resolution} -> {resolution, set.revision}
            _ -> fail(:agent_unresolved, :key, :unknown_key)
          end

        _ ->
          ensure(is_pid(policy.cache), :agent_unresolved, :key, :source_unavailable)

          case Cache.resolve(policy.cache, source, params["keyid"],
                 algorithms: policy.algorithms,
                 clock: fn -> now end,
                 timeout: remaining(deadline)
               ) do
            {:ok, resolution} -> {resolution, resolution.revision}
            {:error, %{reason: reason}} -> discovery_error(reason)
          end
      end

    ensure(
      match?(%Resolution{}, resolution) and resolution.source_type == source.type and
        resolution.location == source.location and
        resolution.origin == Source.origin(URI.parse(source.location)),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    # Wire-key checks for test keys and revocation apply to this actual key too.
    ensure(
      PublicKey.thumbprint(resolution.key) == {:ok, params["keyid"]},
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    ensure(
      source.type != :directory or not source.require_signed_directory or
        resolution.proof == :signed,
      :agent_unresolved,
      :key,
      :source_unavailable
    )

    {:ok,
     {resolution.algorithm, resolution.key,
      %{
        kind: :agent,
        identifier:
          if(agent.type == :directory,
            do: identifier,
            else: hd(String.split(agent.location, "#", parts: 2))
          ),
        type: agent.type,
        origin: resolution.origin,
        thumbprint: params["keyid"],
        provenance: %{
          source_type: resolution.source_type,
          proof: resolution.proof,
          fetched_at: resolution.fetched_at,
          revision: revision
        }
      }}}
  end

  defp held(resolver, label, params, policy, deadline) do
    result =
      bounded(
        fn -> resolver.(%{label: label, keyid: params["keyid"], tag: params["tag"]}) end,
        deadline
      )

    case result do
      {:ok, %{algorithm: algorithm, key: %PublicKey{} = key}} ->
        ensure(
          algorithm in policy.algorithms and PublicKey.thumbprint(key) == {:ok, params["keyid"]},
          :agent_unresolved,
          :key,
          :unknown_key
        )

        {algorithm, key, %{kind: :key, thumbprint: params["keyid"]}}

      _ ->
        fail(:agent_unresolved, :key, :unknown_key)
    end
  end

  defp bounded(fun, deadline) do
    case Support.run(remaining(deadline), fn _ -> fun.() end) do
      {:error, %{reason: :deadline_exceeded}} -> fail(:agent_unresolved, :key, :timeout)
      {:error, _} -> fail(:agent_unresolved, :key, :source_unavailable)
      result -> result
    end
  end

  defp discovery_error(reason) when reason in [:unknown_key, :revoked_key],
    do: fail(:agent_unresolved, :key, reason)

  defp discovery_error(:deadline_exceeded), do: fail(:agent_unresolved, :key, :timeout)
  defp discovery_error(_), do: fail(:agent_unresolved, :key, :source_unavailable)

  defp remaining(deadline) do
    left = deadline - System.monotonic_time(:millisecond)
    ensure(left > 0, :agent_unresolved, :key, :timeout)
    min(left, 300_000)
  end

  defp clock(fun) do
    value =
      try do
        fun.()
      catch
        _, _ -> nil
      end

    ensure(is_integer(value) and value in 0..253_402_300_799, :invalid_clock, :freshness)
    value
  end

  # RFC 6454 Sections 4 and 6.2 serialize the origin tuple's host, retaining
  # its trailing dot. Identifier comparison separately normalizes that spelling.
  defp ascii_origin(uri) do
    host = String.downcase(uri.host)
    host = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host

    String.downcase(uri.scheme) <>
      "://" <>
      host <>
      if(uri.port == 443, do: "", else: ":" <> Integer.to_string(uri.port))
  end

  defp source_identifier(%Source{type: :directory, location: location}),
    do: Source.origin(URI.parse(location)) <> "/.well-known/http-message-signatures-directory"

  defp source_identifier(source), do: normalize(source.location)

  defp normalize(location) do
    uri = URI.parse(location)
    path = percent_normalize(uri.path || "") |> remove_dot_segments()
    Source.origin(uri) <> if(path == "", do: "/", else: path)
  end

  defp percent_normalize(path),
    do:
      Regex.replace(~r/%[a-fA-F0-9]{2}/, path, fn escape ->
        <<c>> = Base.decode16!(String.slice(escape, 1, 2), case: :mixed)

        if c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?-, ?., ?_, ?~],
          do: <<c>>,
          else: String.upcase(escape)
      end)

  defp remove_dot_segments(path) do
    parts =
      Enum.reduce(String.split(path, "/"), [], fn
        ".", acc -> acc
        "..", [""] -> [""]
        "..", acc -> Enum.drop(acc, -1)
        part, acc -> acc ++ [part]
      end)

    result = Enum.join(parts, "/")

    if String.ends_with?(path, ["/.", "/.."]) and not String.ends_with?(result, "/"),
      do: result <> "/",
      else: result
  end

  defp nested(selected, entries) do
    all = Map.new(entries)

    Map.new(selected, fn {label, input} ->
      ids = MapSet.new(SignatureFields.identities(input.value))

      inner_labels =
        for {"signature", params} <- ids, {"key", {:string, key}} <- params, do: {key, params}

      covered =
        Enum.map(inner_labels, fn {inner, params} ->
          ensure(
            params == [{"key", {:string, inner}}] and Map.has_key?(all, inner) and
              MapSet.member?(ids, {"signature-input", params}) and
              MapSet.subset?(MapSet.new(SignatureFields.identities(all[inner].value)), ids),
            :nested_coverage_incomplete,
            :policy
          )

          inner
        end)

      {label, Enum.sort(covered)}
    end)
  end

  defp replay(:not_required, _), do: :not_required

  defp replay(policy, results) do
    facts =
      Enum.map(results, fn {label, v} ->
        p = v.signature.parameters

        ensure(
          is_binary(p["nonce"]) and byte_size(p["nonce"]) > 0,
          :missing_replay_identifier,
          :replay
        )

        %{
          label: label,
          identifier: p["nonce"],
          algorithm: v.signature.algorithm,
          keyid: p["keyid"],
          agent: Map.take(v.principal, [:kind, :identifier, :type, :origin, :thumbprint]),
          created: p["created"],
          expires: p["expires"]
        }
      end)

    retain =
      results
      |> Enum.map(fn {_, v} ->
        f = v.freshness

        min(
          f.expires + f.skew,
          if(f.max_age, do: f.created + f.max_age + f.skew + 1, else: f.expires + f.skew)
        )
      end)
      |> Enum.min()

    ensure(retain <= 253_402_300_799, :retention_exceeded, :replay)
    unwrap(Replay.commit(policy, %{profile: @profile, signatures: facts}, retain))
  end

  @doc "Sign an explicit protocol-00 request with caller-owned signing authority."
  @spec sign(Message.t(), map(), Policy.signer(), keyword()) ::
          {:ok, Message.t()} | {:error, Error.t()}
  def sign(message, spec, signer, opts \\ []) do
    protect(fn ->
      options(opts, [:field_schemas])

      ensure(
        Message.validate(message) == :ok and message.kind == :request,
        :invalid_message,
        :input
      )

      ensure(
        is_map(spec) and not is_struct(spec) and
          Enum.all?(
            [:label, :agent, :key, :algorithm, :created, :expires, :nonce],
            &Map.has_key?(spec, &1)
          ) and
          Enum.all?(
            Map.keys(spec),
            &(&1 in [:label, :agent, :key, :algorithm, :created, :expires, :nonce, :components])
          ),
        :invalid_options,
        :input
      )

      ensure(
        SignatureFields.label?(spec.label) and SignatureFields.algorithm?(spec.algorithm) and
          spec.algorithm not in ["hmac-sha256", {:jws, "HS256"}] and is_function(signer, 2),
        :invalid_options,
        :input
      )

      ensure(
        is_integer(spec.created) and is_integer(spec.expires) and
          spec.created in 0..999_999_999_999_999 and spec.expires in 0..999_999_999_999_999 and
          spec.expires > spec.created and spec.expires - spec.created <= 86_400 and
          (spec.nonce == nil or (is_binary(spec.nonce) and byte_size(spec.nonce) in 1..1024)),
        :invalid_options,
        :input
      )

      keyid =
        case PublicKey.thumbprint(spec.key) do
          {:ok, kid} -> kid
          _ -> fail(:invalid_options, :input)
        end

      PublicKey.bind!(spec.key, RequestSeal.Crypto.Algorithm.resolve(spec.algorithm))
      {message, extra} = signing_agent(message, spec)

      items =
        required(Map.get(spec, :components, "()"), [component("@authority") | extra])
        |> SignatureFields.inner()
        |> unwrap()

      params =
        [{"created", {:integer, spec.created}}, {"keyid", {:string, keyid}}] ++
          if(is_binary(spec.algorithm), do: [{"alg", {:string, spec.algorithm}}], else: []) ++
          [{"expires", {:integer, spec.expires}}] ++
          if(spec.nonce, do: [{"nonce", {:string, spec.nonce}}], else: []) ++
          [{"tag", {:string, "web-bot-auth"}}]

      existing =
        if Enum.any?(
             message.fields,
             &(String.downcase(&1.name) in ["signature-input", "signature"])
           ) do
          {entries, _} = unwrap(Authentication.dictionaries(message, 16))
          entries
        else
          []
        end

      nested([{spec.label, %{items | parameters: params}}], existing)

      RequestSeal.sign(
        message,
        %{
          label: spec.label,
          signature_input: %{items | parameters: params},
          algorithm: spec.algorithm
        },
        signer,
        field_schemas: schemas(Keyword.get(opts, :field_schemas, %{}))
      )
    end)
  end

  defp signing_agent(message, spec) do
    ensure(
      is_map(spec.agent) and map_size(spec.agent) == 2 and Map.has_key?(spec.agent, :location) and
        Map.has_key?(spec.agent, :type) and spec.agent.type in [:directory, :jwks_uri, :cimd],
      :invalid_options,
      :input
    )

    member = %Value{
      type: :item,
      value: {:string, spec.agent.location},
      parameters: [{"type", {:token, Atom.to_string(spec.agent.type)}}]
    }

    parsed = agent_member(member)

    if parsed.type == :directory,
      do:
        ensure(
          parsed.location == ascii_origin(URI.parse(parsed.location)),
          :invalid_options,
          :input
        )

    existing = agents(message)

    ensure(
      not Map.has_key?(existing, spec.label) or existing[spec.label] == parsed,
      :invalid_options,
      :input
    )

    if Map.has_key?(existing, spec.label) do
      {message, [component("signature-agent", [{"key", {:string, spec.label}}])]}
    else
      wire =
        unwrap(
          SF.serialize(%Value{type: :dictionary, value: [{spec.label, member}]}, agent_schema())
        )

      field =
        unwrap(FieldOccurrence.new(%{name: "Signature-Agent", value: wire, section: :headers}))

      {%{message | fields: message.fields ++ [field]},
       [component("signature-agent", [{"key", {:string, spec.label}}])]}
    end
  end

  defp required(bytes, added) do
    value =
      case SignatureFields.inner(bytes) do
        {:ok, v} -> v
        _ -> fail(:invalid_options, :input)
      end

    ensure(value.parameters == [], :invalid_options, :input)
    items = Enum.uniq_by(added ++ value.value, &SignatureFields.identities([&1]))

    unwrap(
      SF.serialize(
        %Value{type: :list, value: [%Value{type: :inner_list, value: items}]},
        SignatureFields.schema(:list)
      )
    )
  end

  defp component(name, params \\ []),
    do: %Value{type: :item, value: {:string, name}, parameters: params}

  defp agent_schema, do: SignatureFields.schema(:dictionary, [:string], false)

  defp schemas(extra),
    do:
      Map.merge(extra, %{
        "signature-agent" => agent_schema(),
        "signature-input" => SignatureFields.schema(:dictionary),
        "signature" => SignatureFields.schema(:dictionary, [:bytes], false)
      })

  defp options(opts, allowed) do
    ensure(
      is_list(opts) and Keyword.keyword?(opts) and
        length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) and
        Enum.all?(Keyword.keys(opts), &(&1 in allowed)),
      :invalid_options,
      :input
    )
  end

  defp unwrap({:ok, value}), do: value
  defp unwrap({:error, %Error{} = error}), do: throw({:web_bot_auth_error, error})
  defp unwrap(_), do: fail(:invalid_options, :input)
  defp ensure(value, reason, layer, detail \\ nil)
  defp ensure(true, _, _, _), do: :ok
  defp ensure(_, reason, layer, detail), do: fail(reason, layer, detail)

  defp fail(reason, layer, detail \\ nil),
    do: throw({:web_bot_auth_error, Error.new(reason, layer, detail)})

  defp protect(fun) do
    fun.()
  rescue
    _ -> {:error, Error.new(:invalid_options, :input)}
  catch
    {:web_bot_auth_error, error} -> {:error, error}
    _, _ -> {:error, Error.new(:invalid_options, :input)}
  end
end
