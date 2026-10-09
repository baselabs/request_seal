defmodule RequestSeal.Conformance.Surfaces do
  @moduledoc false
  alias RequestSeal.{
    Body,
    Crypto,
    FieldOccurrence,
    Message,
    Policy,
    Profile,
    PublicKey,
    TransportFacts
  }

  alias RequestSeal.Conformance, as: C
  alias RequestSeal.Conformance.StructuredFields, as: F
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.Value
  alias RequestSeal.JOSE.{JWS, JWE, Nested, KeyManagement}
  alias RequestSeal.JOSEVectors, as: V

  # One dispatch function per public surface, and one adapter per named batch
  # format. No case-specific expected value is used to produce an actual result.
  @registry %{
    "structured_fields.parse" => :parse,
    "structured_fields.serialize" => :serialize,
    "message.validate" => :validate_message,
    "signature_base.build" => :signature_base,
    "sign" => :sign,
    "verify" => :verify,
    "quorum.verify" => :quorum,
    "accept_signature.parse" => :accept_signature,
    "digest.content" => :digest,
    "crypto.verify" => :crypto_verify,
    "key.import" => :key_import,
    "jws.sign" => :jws_sign,
    "jws.verify" => :jws_verify,
    "jwe.decrypt" => :jwe_decrypt,
    "nested.decrypt" => :nested_decrypt,
    "web_bot_auth.verify" => :web_bot_auth,
    "discovery.body" => :discovery_body,
    "replay.claim" => :replay_claim,
    "profile.name" => :profile_name
  }
  def run(root, case_),
    do: apply(__MODULE__, Map.fetch!(@registry, case_["surface"]), [root, case_])

  def message(root, value) do
    value = C.load(root, value)

    fields =
      Enum.map(value["fields"] || [], fn [name, bytes] ->
        {:ok, f} = FieldOccurrence.new(%{name: name, value: C.bytes(bytes), section: :headers})
        f
      end)

    trailers =
      case value["trailers"] do
        nil ->
          :unavailable

        v when v in ["pending", "unavailable"] ->
          String.to_existing_atom(v)

        list ->
          Enum.map(list, fn [name, bytes] ->
            {:ok, f} =
              FieldOccurrence.new(%{name: name, value: C.bytes(bytes), section: :trailers})

            f
          end)
      end

    {:ok, body} =
      case value["body"] do
        nil -> Body.new(%{state: :unavailable})
        "unavailable" -> Body.new(%{state: :unavailable})
        bytes -> Body.new(%{state: :retained, bytes: C.bytes(bytes)})
      end

    {:ok, transport} = TransportFacts.new(%{})

    attrs = %{
      kind: String.to_existing_atom(value["kind"]),
      fields: fields,
      trailers: trailers,
      body: body,
      transport: transport
    }

    attrs =
      Enum.reduce(~w(method raw_target scheme authority), attrs, fn key, acc ->
        if Map.has_key?(value, key),
          do: Map.put(acc, String.to_existing_atom(key), value[key]),
          else: acc
      end)

    attrs =
      if value["target_form"],
        do: Map.put(attrs, :target_form, String.to_existing_atom(value["target_form"])),
        else: attrs

    attrs =
      if value["status"],
        do:
          Map.put(
            attrs,
            :status,
            if(is_map(value["status"]), do: C.int(value["status"]), else: value["status"])
          ),
        else: attrs

    attrs =
      if value["related_request"],
        do: Map.put(attrs, :related_request, message(root, value["related_request"])),
        else: attrs

    {:ok, m} = Message.new(attrs)
    m
  end

  defp case_message(root, i) do
    m = message(root, i["message"])

    fields =
      Enum.map(i["append_fields"] || [], fn [name, v] ->
        {:ok, f} = FieldOccurrence.new(%{name: name, value: C.bytes(v), section: :headers})
        f
      end)

    m = %{m | fields: m.fields ++ fields}

    Enum.reduce(i["message_override"] || %{}, m, fn {key, value}, m ->
      Map.put(m, String.to_existing_atom(key), value)
    end)
  end

  def parse(root, c) do
    i = c["inputs"]
    s = F.schema(i["field_type"], i["schema"])
    fun = if i["mode"] == "unique", do: :parse_unique, else: :parse

    with {:ok, v} <- apply(SF, fun, [C.bytes(C.load(root, i["raw"])), s]),
         {:ok, wire} <- SF.serialize(v, s),
         do: {:ok, %{"bytes" => C.b64(wire)}}
  end

  def serialize(root, c) do
    i = c["inputs"]
    value = C.load(root, i["value"])

    with {:ok, wire} <- SF.serialize(typed(value), F.schema(i["field_type"], i["schema"])),
         do: {:ok, %{"bytes" => C.b64(wire)}}
  end

  defp typed(%{"type" => type, "value" => value} = v),
    do: %Value{
      type: String.to_existing_atom(type),
      value: value,
      parameters: v["parameters"] || []
    }

  def validate_message(root, c) do
    case Message.validate(case_message(root, c["inputs"])) do
      :ok -> {:ok, %{"valid" => true}}
      error -> error
    end
  end

  def signature_base(root, c) do
    i = c["inputs"]

    with {:ok, base} <-
           RequestSeal.SignatureBase.build(
             case_message(root, i),
             C.bytes(C.load(root, i["parameters"])),
             field_schemas: schemas(i["field_schemas"] || %{})
           ),
         do: {:ok, %{"base" => C.b64(base)}}
  end

  def signature_base_item(root, item) do
    with {:ok, base} <-
           RequestSeal.SignatureBase.build(message(root, item["message"]), item["parameters"]) do
      base == item["base"] == Map.get(item, "same_base", true)
    else
      _ -> false
    end
  end

  defp schemas(values),
    do: Map.new(values, fn {name, type} -> {name, F.schema(type, "rfc8941")} end)

  defp public(root, name) do
    keyname =
      %{
        "rsa-pss-sha512" => "rsa_pss",
        "rsa-v1_5-sha256" => "rsa",
        "ed25519" => "ed25519",
        "ecdsa-p256-sha256" => "p256"
      }[name] || name

    {:ok, key} =
      PublicKey.import(
        C.read_file(root, "sources/rfc9421/keys/" <> keyname <> "_public.pem"),
        :pem
      )

    key
  end

  defp material(root, "hmac-sha256"),
    do:
      {:hmac,
       C.read_file(root, "sources/rfc9421/keys/hmac.txt") |> String.trim() |> Base.decode64!()}

  defp material(root, name) do
    keyname =
      %{"rsa-pss-sha512" => "rsa_pss", "rsa-v1_5-sha256" => "rsa", "ecdsa-p256-sha256" => "p256"}[
        name
      ] || name

    [entry] =
      :public_key.pem_decode(
        C.read_file(root, "sources/rfc9421/keys/" <> keyname <> "_private.pem")
      )

    k = :public_key.pem_entry_decode(entry)

    case keyname do
      "rsa" -> {:rsa, k}
      "rsa_pss" -> {:rsa, elem(k, 0)}
      "p256" -> {:ec, "P-256", elem(k, 2)}
      "ed25519" -> {:ed25519, elem(k, 2)}
    end
  end

  defp resolver(root, descriptor) do
    name = descriptor["key"]

    cond do
      descriptor["behavior"] == "raise" ->
        fn _ ->
          {:ok,
           %{algorithm: "ed25519", key: fn _, _, _ -> raise "verification callback fault" end}}
        end

      descriptor["behavior"] == "unknown" ->
        fn _ -> :error end

      name == "hmac-sha256" ->
        key = material(root, name)
        fn _ -> {:ok, %{algorithm: name, key: fn a, b, s -> Crypto.verify(a, b, s, key) end}} end

      true ->
        key = public(root, name)
        fn _ -> {:ok, %{algorithm: name, key: key}} end
    end
  end

  defp policy(root, attrs, now \\ nil, replay \\ nil) do
    # Standalone consumers must load the atom-owning contract before converting
    # its keys and enumerated values; a test suite may already have loaded it.
    Code.ensure_loaded!(Policy)

    attrs =
      Enum.reduce(attrs, %{}, fn {k, v}, acc ->
        value =
          case k do
            "key_resolver" ->
              resolver(root, v)

            "freshness" when is_map(v) ->
              %{
                clock: fn -> C.int(now) end,
                skew: C.int(v["skew"]),
                max_age: if(v["max_age"], do: C.int(v["max_age"])),
                require_expires: v["require_expires"]
              }

            "field_schemas" ->
              schemas(v)

            "max_signatures" ->
              C.int(v)

            k when k in ["content", "freshness", "replay", "extra_components"] and is_binary(v) ->
              String.to_existing_atom(v)

            _ ->
              v
          end

        Map.put(acc, String.to_existing_atom(k), value)
      end)

    attrs = if replay, do: Map.put(attrs, :replay, replay), else: attrs
    Policy.new(attrs)
  end

  def verify(root, c) do
    case c["policy"]["replay"] do
      %{} = descriptor ->
        C.require!(
          descriptor["store"] == "ets" and descriptor["identifier"] == "nonce" and
            descriptor["commitment"] == "identifier",
          :replay_descriptor
        )

        {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 16)

        try do
          replay = %{
            identifier: :nonce,
            namespace: C.bytes(descriptor["namespace"]),
            commitment: fn facts -> {:ok, facts.identifier} end,
            timeout: C.int(descriptor["timeout"]),
            store: RequestSeal.Replay.ETS.store(pid)
          }

          verify_with_store(root, c, replay)
        after
          GenServer.stop(pid)
        end

      _ ->
        verify_with_store(root, c, nil)
    end
  end

  defp verify_with_store(root, c, replay) do
    i = c["inputs"]
    m = case_message(root, i)

    with {:ok, p} <- policy(root, c["policy"], c["now"], replay),
         {:ok, v} <- RequestSeal.verify(m, p, [label: i["label"]] ++ options(i["options"] || %{})) do
      {:ok, %{"verification" => verification(v, m)}}
    end
  end

  def verification(v, m) do
    {:ok, {inputs, _}} = Profile.dictionaries(m, 64)
    input = Map.new(inputs)[v.label]

    C.require!(
      Map.new(input.parameters, fn {k, {_, value}} -> {k, value} end) == v.signature.parameters,
      :verification_parameters
    )

    covered_wires =
      Enum.map(input.value, fn item ->
        {:ok, wire} = SF.serialize(item, F.schema("item", "rfc8941"))
        wire
      end)

    C.require!(covered_wires == v.signature.covered, :verification_coverage)
    params = Enum.map(input.parameters, fn {k, value} -> [k, bare(value)] end)

    covered =
      Enum.map(input.value, fn %Value{value: {:string, name}, parameters: ps} ->
        [name, Enum.map(ps, fn {k, val} -> [k, bare(val)] end)]
      end)

    profile = Map.new(v.profile, fn {k, value} -> {to_string(k), atom_value(value)} end)

    content =
      case v.content do
        :not_required ->
          "not_required"

        c ->
          %{
            "kind" => to_string(c.kind),
            "checked" => c.checked,
            "bytes" => C.number(c.bytes),
            "unsupported" => c.unsupported
          }
      end

    freshness =
      case v.freshness do
        :not_evaluated ->
          "not_evaluated"

        f ->
          Map.new(f, fn {k, value} ->
            {to_string(k), if(value == nil, do: nil, else: C.number(value))}
          end)
      end

    principal =
      case v.principal do
        :unattributed ->
          "unattributed"

        p ->
          %{"agent" => p.origin, "source" => to_string(p.type), "thumbprint" => p.thumbprint}
      end

    %{
      "label" => v.label,
      "signature" => %{
        "algorithm" => atom_value(v.signature.algorithm),
        "covered" => covered,
        "parameters" => params,
        "keyid" => v.signature.keyid,
        "crypto" => to_string(v.signature.crypto)
      },
      "profile" => profile,
      "content" => content,
      "freshness" => freshness,
      "replay" => atom_value(v.replay),
      "principal" => principal,
      "authorization" => to_string(v.authorization)
    }
  end

  defp bare({:integer, v}), do: C.number(v)
  defp bare({:bytes, v}), do: C.b64(v)

  defp bare({:decimal, {v, scale}}),
    do: %{"dec" => Integer.to_string(v), "scale" => C.number(scale)}

  defp bare({_, v}), do: v
  defp atom_value(v) when is_atom(v), do: to_string(v)
  defp atom_value({a, b}), do: [to_string(a), to_string(b)]
  defp atom_value(v), do: v
  defp options(map), do: Enum.map(map, fn {k, v} -> {String.to_atom(k), v} end)

  def sign(root, c) do
    i = c["inputs"]
    m = case_message(root, i)
    alg = i["spec"]["algorithm"]
    spec = signing_spec(i["spec"])

    opts =
      Enum.map(i["options"] || %{}, fn
        {"clock", v} -> {:clock, fn -> C.int(v) end}
        {"nonce", v} -> {:nonce, C.bytes(v)}
      end)

    key = material(root, i["key"] || alg)

    signer =
      case i["signer"] do
        "raise" -> fn _, _ -> raise "signing callback fault" end
        _ -> fn a, b -> Crypto.sign(a, b, key) end
      end

    with {:ok, signed} <- RequestSeal.sign(m, spec, signer, opts) do
      if c["class"] == "byte_exact" do
        fields = Enum.take(signed.fields, -2) |> Enum.map(fn f -> [f.name, C.b64(f.value)] end)
        {:ok, %{"bytes" => fields}}
      else
        pk =
          if alg == "hmac-sha256",
            do: fn a, b, s -> Crypto.verify(a, b, s, key) end,
            else: public(root, alg)

        {:ok, p} =
          Policy.new(%{
            algorithms: [alg],
            components: "()",
            key_resolver: fn _ -> {:ok, %{algorithm: alg, key: pk}} end,
            freshness: :not_evaluated,
            content: :not_required,
            replay: :not_required
          })

        with {:ok, _} <- RequestSeal.verify(signed, p, label: spec.label),
             do: {:ok, %{"valid" => true}}
      end
    end
  end

  defp signing_spec(%{"signature_input" => _} = s),
    do: %{
      label: s["label"],
      algorithm: s["algorithm"],
      signature_input: C.bytes(s["signature_input"])
    }

  defp signing_spec(s) do
    Code.ensure_loaded!(RequestSeal.Signing)

    Map.new(s, fn {k, v} ->
      value =
        case k do
          "parameters" ->
            Map.new(v, fn {pk, pv} ->
              {String.to_existing_atom(pk),
               if(is_map(pv) and Map.has_key?(pv, "int"), do: C.int(pv), else: pv)}
            end)

          "expires_in" ->
            C.int(v)

          "field_schemas" ->
            schemas(v)

          _ ->
            v
        end

      {String.to_existing_atom(k), value}
    end)
  end

  def quorum(root, c) do
    i = c["inputs"]
    m = case_message(root, i)
    q = i["quorum"]

    with {:ok, p} <- policy(root, c["policy"]),
         {:ok, quorum} <-
           RequestSeal.Quorum.new(%{
             mode: String.to_atom(q["mode"]),
             unit: :principal,
             slots: [
               %{
                 id: :signer,
                 label: i["label"],
                 policy: p,
                 required: true,
                 principal: "published",
                 role: nil
               }
             ],
             unexpected: :reject,
             invalid: :reject,
             bindings: []
           }),
         {:ok, _} <- RequestSeal.verify_quorum(m, quorum, []),
         do: {:ok, %{"valid" => true}}
  end

  def accept_signature(_, c) do
    with {:ok, value} <-
           RequestSeal.AcceptSignature.parse(C.bytes(c["inputs"]["raw"]), target: :request),
         {:ok, bytes} <- RequestSeal.AcceptSignature.serialize(value),
         do: {:ok, %{"bytes" => C.b64(bytes)}}
  end

  def digest(_, c) do
    i = c["inputs"]
    {:ok, body} = Body.new(%{state: :retained, bytes: C.bytes(i["content"])})

    with {:ok, v} <- RequestSeal.Digest.compute(body, i["algorithms"]),
         {:ok, wire} <- RequestSeal.Digest.serialize(v),
         do: {:ok, %{"bytes" => C.b64(wire)}}
  end

  def crypto_verify(root, c) do
    i = c["inputs"]
    descriptor = C.load(root, i["key"])

    key =
      case descriptor do
        %{"raw" => raw, "curve" => "Ed25519"} -> PublicKey.import({:ed25519, C.bytes(raw)}, :raw)
        %{"raw" => raw, "curve" => curve} -> PublicKey.import({:ec, curve, C.bytes(raw)}, :raw)
        %{"file" => file} -> PublicKey.import(C.read_file(root, file), :pem)
        _ -> PublicKey.import(descriptor, :jwk)
      end

    with {:ok, key} <- key,
         :ok <- Crypto.verify(i["algorithm"], C.bytes(i["data"]), C.bytes(i["signature"]), key),
         do: {:ok, %{"valid" => true}}
  end

  def key_import(root, c) do
    i = c["inputs"]
    value = C.load(root, i["material"])
    value = if i["public_only"], do: Map.drop(value, ~w(d p q dp dq qi k)), else: value

    with {:ok, key} <- PublicKey.import(value, String.to_existing_atom(i["format"])),
         {:ok, thumbprint} <- PublicKey.thumbprint(key),
         do: {:ok, %{"valid" => true, "public" => %{"thumbprint" => thumbprint}}}
  end

  def jws_sign(root, c) do
    i = c["inputs"]
    j = C.load(root, i["key"])

    {:ok, h} =
      RequestSeal.Custody.Local.new({:jws, c["policy"]["algorithms"] |> hd()}, V.material(j))

    try do
      with {:ok, compact} <-
             if(i["protected"],
               do: JWS.sign_protected(C.bytes(i["protected"]), C.bytes(i["payload"]), h),
               else:
                 JWS.sign(
                   Enum.map(i["protected_pairs"], &List.to_tuple/1),
                   C.bytes(i["payload"]),
                   h
                 )
             ),
           do: jws_signed_result(c, compact, j)
    after
      RequestSeal.Custody.Local.release(h)
    end
  end

  defp jws_signed_result(%{"class" => "byte_exact"}, compact, _),
    do: {:ok, %{"bytes" => C.b64(compact)}}

  defp jws_signed_result(c, compact, key) do
    with {:ok, result} <- JWS.verify(compact, V.jws_policy(key, hd(c["policy"]["algorithms"]))),
         do: {:ok, %{"valid" => true, "payload" => C.b64(result.payload)}}
  end

  def jws_verify(root, c) do
    i = c["inputs"]
    p = c["policy"]

    resolver = fn facts ->
      j = C.load(root, i["key"])
      V.jws_policy(j, facts.algorithm).key_resolver.(facts)
    end

    policy = %{algorithms: p["algorithms"], timeout: C.int(p["timeout"]), key_resolver: resolver}

    with {:ok, result} <- JWS.verify(C.bytes(i["compact"]), policy),
         do: {:ok, %{"valid" => true, "payload" => C.b64(result.payload)}}
  end

  def jwe_decrypt(root, c) do
    i = c["inputs"]
    j = C.load(root, i["key"])
    p = c["policy"]

    with {:ok, result} <-
           JWE.decrypt(
             C.bytes(i["compact"]),
             V.jwe_policy(j, hd(p["algorithms"]), hd(p["encryption"]))
           ),
         do: {:ok, %{"valid" => true, "payload" => C.b64(result.plaintext)}}
  end

  def nested_decrypt(root, c) do
    i = c["inputs"]
    j = C.load(root, i["key"])
    s = C.load(root, i["signing_key"])
    p = c["policy"]

    with {:ok, result} <-
           Nested.verify(
             C.bytes(i["compact"]),
             V.jwe_policy(j, p["algorithm"], p["encryption"]),
             V.jws_policy(s, p["signing_algorithm"]),
             content_types: i["content_types"]
           ),
         do: {:ok, %{"valid" => true, "payload" => C.b64(result.jws.payload)}}
  end

  def web_bot_auth(root, c) do
    i = c["inputs"]
    m = case_message(root, i)
    now = C.int(c["now"])
    p = c["policy"]
    # The injected directory body is real captured source data, consumed by the
    # same bounded key importer. It performs no HTTP request or invented reply.
    directory = C.bytes(C.load(root, i["directory"]))

    agents = fn agent ->
      if RequestSeal.Discovery.Source.origin(URI.parse(agent.location)) in i["agents"] do
        {:ok, source} =
          RequestSeal.Discovery.Source.new(%{
            type: agent.type,
            location: agent.location,
            require_signed_directory: false
          })

        with {:ok, keys} <- RequestSeal.Discovery.parse_body(directory, source, now) do
          {:ok,
           %RequestSeal.Discovery.KeySet{
             source: source,
             origin: RequestSeal.Discovery.Source.origin(URI.parse(agent.location)),
             keys: keys,
             fetched_at: now,
             expires_at: now + 7200,
             revision: C.sha(directory),
             proof: :unsigned
           }}
        end
      else
        :error
      end
    end

    with {:ok, policy} <-
           RequestSeal.WebBotAuth.Policy.new(%{
             algorithms: p["algorithms"],
             agents: agents,
             cache: nil,
             freshness: %{clock: fn -> now end, skew: C.int(p["freshness"]["skew"]), max_age: nil},
             content: :not_required,
             replay: :not_required,
             test_keys: String.to_existing_atom(p["test_keys"]),
             untagged: String.to_existing_atom(p["untagged"] || "ignore")
           }),
         {:ok, result} <- RequestSeal.WebBotAuth.verify(m, policy) do
      {:ok,
       %{
         "verification" =>
           Map.new(result.signatures, fn {label, v} -> {label, verification(v, m)} end)
       }}
    end
  end

  def discovery_body(root, c) do
    i = c["inputs"]
    kind = %{"jwks" => :jwks_uri, "directory" => :directory, "cimd" => :cimd}[i["kind"]]

    {:ok, s} =
      RequestSeal.Discovery.Source.new(
        Map.merge(
          %{type: kind, location: i["location"], require_signed_directory: false},
          Map.new(i["limits"], fn {k, v} -> {String.to_existing_atom(k), C.int(v)} end)
        )
      )

    with {:ok, keys} <-
           RequestSeal.Discovery.parse_body(C.bytes(C.load(root, i["body"])), s, C.int(c["now"])),
         do: {:ok, %{"keys" => Map.values(keys) |> Enum.map(& &1.thumbprint) |> Enum.sort()}}
  end

  def replay_claim(root, c) do
    i = c["inputs"]
    {:ok, pid} = RequestSeal.Replay.ETS.start_link(max_entries: 16)

    try do
      if i["operation"] == "sweep" do
        case RequestSeal.Replay.ETS.sweep(pid, C.int(i["now"])) do
          {:ok, 0} -> {:ok, %{"valid" => true}}
          {:error, :failure} -> {:error, RequestSeal.Replay.Error.new(:invalid_options)}
        end
      else
        ns = C.bytes(i["namespace"])
        key = C.bytes(i["key"])
        created = C.int(i["created"])
        expires = if i["expires"], do: C.int(i["expires"])
        age = if i["max_age"], do: C.int(i["max_age"])
        skew = C.int(i["skew"])
        {:ok, m} = Message.request("GET", "https://example.com/", [], nil)

        input =
          ~s[("@method");created=#{created};nonce="corpus"] <>
            if(expires, do: ";expires=#{expires}", else: "")

        material = material(root, "ed25519")

        {:ok, m} =
          RequestSeal.sign(m, %{label: "s", algorithm: "ed25519", signature_input: input}, fn a,
                                                                                              b ->
            Crypto.sign(a, b, material)
          end)

        replay = %{
          identifier: :nonce,
          namespace: ns,
          commitment: fn _ -> {:ok, key} end,
          store: RequestSeal.Replay.ETS.store(pid),
          timeout: 5000
        }

        {:ok, p} =
          Policy.new(%{
            algorithms: ["ed25519"],
            components: "()",
            key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public(root, "ed25519")}} end,
            freshness: %{
              clock: fn -> C.int(c["now"]) end,
              skew: skew,
              max_age: age,
              require_expires: expires != nil
            },
            content: :not_required,
            replay: replay
          })

        with {:ok, v} <- RequestSeal.verify(m, p, label: "s") do
          actual = %{"retain_until" => C.number(v.replay.retain_until)}

          if i["row"] do
            table = :sys.get_state(pid).table
            [{{:claim, ^ns, ^key}, until}] = :ets.lookup(table, {:claim, ns, key})

            {:ok,
             Map.put(actual, "row", [
               Base.encode16(ns, case: :lower),
               Base.encode16(key, case: :lower),
               Integer.to_string(until)
             ])}
          else
            {:ok, actual}
          end
        end
      end
    after
      GenServer.stop(pid)
    end
  end

  def profile_name(root, c) do
    i = c["inputs"]

    name =
      case i["name"] do
        [p, k] -> {String.to_atom(p), String.to_atom(k)}
        v when is_binary(v) -> String.to_atom(v)
      end

    profile =
      Map.merge(
        %{name: name},
        Map.new(i["metadata"] || %{}, fn {k, v} -> {String.to_atom(k), v} end)
      )

    vectors = C.read_file(root, "sources/rfc9421/verification/rfc9421.json") |> C.json()
    v = Enum.find(vectors, &(&1["label"] == "sig-b26"))
    bases = C.read_file(root, "sources/rfc9421/rfc9421.json") |> C.json()
    base = Enum.find(bases, &(&1["section"] == "B.2.6"))

    m =
      case_message(root, %{
        "message" => base["message"],
        "append_fields" => [
          ["Signature-Input", v["signature_input"]],
          ["Signature", v["signature"]]
        ]
      })

    {:ok, {inputs, sigs}} = Profile.dictionaries(m, 16)

    {:ok, p} =
      policy(root, %{
        "algorithms" => ["ed25519"],
        "components" => "()",
        "key_resolver" => %{"key" => "ed25519"},
        "freshness" => "not_evaluated",
        "content" => "not_required",
        "replay" => "not_required"
      })

    with {:ok, _} <-
           Profile.verify_label(
             m,
             p,
             v["label"],
             Map.new(inputs)[v["label"]],
             sigs[v["label"]],
             profile
           ),
         do: {:ok, %{"valid" => true}}
  end

  def aes_gcm_item(g, t, override \\ nil) do
    item_shape!(t, override, g["keySize"] in [128, 256] and t["aad"] == "")
    key = V.hex(t["key"])
    iv = V.hex(t["iv"])
    tag = V.hex(t["tag"])
    alg = if g["keySize"] == 256, do: "A256GCMKW", else: "A128GCMKW"

    actual =
      KeyManagement.unwrap(
        alg,
        V.hex(t["ct"]),
        %{"iv" => V.enc(iv), "tag" => V.enc(tag)},
        {:aes, key}
      )

    batch_result(actual, t, override)
  end

  def rsa_oaep_item(g, t, override \\ nil) do
    item_shape!(t, override, t["label"] == "")
    actual = KeyManagement.unwrap("RSA-OAEP-256", V.hex(t["ct"]), %{}, V.rsa(g["privateKeyJwk"]))

    batch_result(actual, t, override)
  end

  defp batch_result({:error, error}, _, %{"outcome" => "reject", "rule_id" => rule}),
    do: C.rule_id(error) == rule

  defp batch_result(_, _, %{"outcome" => "reject"}), do: false

  defp batch_result(actual, t, nil) do
    C.require!(t["result"] in ["valid", "invalid"], :upstream_verdict)

    if t["result"] == "valid",
      do: actual == {:ok, V.hex(t["msg"])},
      else: match?({:error, _}, actual)
  end

  def ed25519_item(g, t, override \\ nil) do
    item_shape!(t, override, true)

    actual =
      with {:ok, key} <- PublicKey.import({:ed25519, V.hex(g["publicKey"]["pk"])}, :raw),
           do: Crypto.verify("ed25519", V.hex(t["msg"]), V.hex(t["sig"]), key)

    signature_result(actual, t, override)
  end

  def ecdsa_item(g, t, override \\ nil) do
    item_shape!(t, override, true)
    curve = g["publicKey"]["curve"]
    curve = if curve == "secp256r1", do: "P-256", else: "P-384"
    algorithm = if curve == "P-256", do: "ecdsa-p256-sha256", else: "ecdsa-p384-sha384"

    actual =
      with {:ok, key} <-
             PublicKey.import({:ec, curve, V.hex(g["publicKey"]["uncompressed"])}, :raw),
           do: Crypto.verify(algorithm, V.hex(t["msg"]), V.hex(t["sig"]), key)

    signature_result(actual, t, override)
  end

  defp signature_result(actual, t, nil), do: actual == :ok == (t["result"] == "valid")

  defp signature_result({:error, error}, _, %{"outcome" => "reject", "rule_id" => rule}),
    do: C.rule_id(error) == rule

  defp signature_result(_, _, _), do: false

  defp item_shape!(t, nil, supported) do
    C.require!(
      supported and Map.get(t, "aad", "") == "" and Map.get(t, "label", "") == "" and
        t["result"] in ["valid", "invalid"],
      {:unexpected_item_shape, Integer.to_string(t["tcId"])}
    )
  end

  defp item_shape!(_, _, _), do: :ok
end
