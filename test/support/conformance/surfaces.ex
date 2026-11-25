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
    "signature_base.parse" => :parse_signature_base,
    "sign" => :sign,
    "verify" => :verify,
    "verification_record.capture/v1" => :verification_record,
    "verification_record.reverify/v1" => :verification_record_recheck,
    "accept_signature.parse" => :accept_signature,
    "digest.content" => :digest,
    "crypto.verify" => :crypto_verify,
    "key.import" => :key_import,
    "custody.seed_check/v1" => :seed_check,
    "fingerprint.digest/v1" => :framed_fingerprint,
    "custody.mac/v1" => :framed_mac,
    "hpke.derive_key_pair/v1" => :hpke_derive_key_pair,
    "custody.derive/v1" => :custody_derive,
    "custody.purpose/v1" => :custody_purpose,
    "custody.admission_commitment/v1" => :admission_commitment,
    "key_management.aes_kw/v1" => :aes_kw,
    "key_management.ecdh_kdf/v1" => :ecdh_kdf,
    "key_management.agree/v1" => :agree,
    "jose.decode_object/v1" => :decode_object,
    "jws.sign" => :jws_sign,
    "jws.verify" => :jws_verify,
    "jwe.decrypt" => :jwe_decrypt,
    "jwe.protected/v1" => :jwe_protected,
    "jwe.decrypt_many/v1" => :jwe_decrypt_many,
    "nested.decrypt" => :nested_decrypt,
    "web_bot_auth.verify" => :web_bot_auth,
    "discovery.body" => :discovery_body,
    "replay.claim" => :replay_claim,
    "replay.pair/v1" => :replay_pair,
    "plug.signed_path/v1" => :signed_path,
    "profile.name" => :profile_name
  }
  def run(root, case_),
    do: apply(__MODULE__, Map.fetch!(@registry, case_["surface"]), [root, case_])

  def custody_purpose(root, %{"inputs" => inputs}) do
    alias RequestSeal.Custody
    alias RequestSeal.Custody.Local

    key = C.read_file(root, inputs["key_file"])
    message = C.load(root, inputs["message"])

    with {:ok, handle} <-
           Local.import("ed25519", key, :pem, issued_for: purpose(inputs["issued_for"])) do
      try do
        requested_handle = %{
          handle
          | issued_for: purpose(inputs["handle_purpose"]),
            operation_family: purpose_family(inputs["operation_family"])
        }

        options = [operation: purpose_operation(inputs["operation"])]

        options =
          if Map.has_key?(inputs, "required"),
            do: Keyword.put(options, :issued_for, purpose(inputs["required"])),
            else: options

        case Custody.sign(requested_handle, message, options) do
          {:ok, signature} -> {:ok, %{"signature" => C.b64(signature)}}
          {:error, _} = error -> error
        end
      after
        :ok = Local.release(handle)
      end
    end
  end

  def signed_path(_root, %{"inputs" => inputs}) do
    alias RequestSeal.Plug.Scope

    body = if inputs["body"] == nil, do: "", else: Jason.encode!(inputs["body"])

    conn =
      RequestSeal.SignedPathTestSupport.verified(
        C.bytes(inputs["target"]),
        inputs["components"],
        body: body,
        parse_body: Map.get(inputs, "parse_body", body != "")
      )

    conn =
      Enum.reduce(inputs["headers"], conn, fn [name, value], conn ->
        Plug.Conn.put_req_header(conn, name, C.bytes(value))
      end)

    options =
      Scope.init(
        template: inputs["template"],
        tenant: inputs["capture"],
        principal_tenant: fn _ -> {:ok, C.bytes(inputs["principal_tenant"])} end,
        on_reject: :continue
      )

    conn = Scope.call(conn, options)

    case conn.private.request_seal.scope do
      {:ok, %{tenant: tenant}} -> {:ok, %{"tenant" => C.b64(tenant)}}
      {:error, _} = error -> error
    end
  end

  def admission_commitment(_root, %{"inputs" => inputs}) do
    alias RequestSeal.Custody.{Context, Gate}
    alias RequestSeal.Replay.ETS

    now = C.int(inputs["now"])
    identifiers = inputs["identifiers"]
    components = "(" <> Enum.join(identifiers, " ") <> ")"

    admission = %Gate.Admission{
      decision: "corpus",
      commitment: C.bytes(inputs["approved"]),
      not_after: C.int(inputs["not_after"])
    }

    {:ok, store} = ETS.start_link(max_entries: 16)

    try do
      config = %{
        algorithm: "ed25519",
        port: fn _, _ -> {:allow, admission} end,
        once: {:store, ETS.store(store), "corpus"},
        required_components: identifiers,
        max_lifetime: 30,
        clock: fn -> now end,
        skew: 0,
        tag: "corpus"
      }

      context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}
      {:ok, message} = Message.request(inputs["method"], inputs["url"], [], nil)
      {:ok, base} = RequestSeal.SignatureBase.build(message, inputs["signature_input"])

      with {:ok, commitment} <- Gate.commitment(message, components),
           {:ok, _} <- Gate.check(base, config, context) do
        {:ok, %{"commitment" => C.b64(commitment)}}
      end
    after
      GenServer.stop(store)
    end
  end

  def replay_pair(_root, %{"inputs" => inputs}) do
    alias RequestSeal.Replay
    alias RequestSeal.Replay.{Claim, ETS, Pair}

    until = C.int(inputs["retain_until"])
    claim = %Claim{
      namespace: C.bytes(inputs["namespace"]),
      key: C.bytes(inputs["key"]),
      retain_until: until
    }

    {:ok, destination} = ETS.start_link(max_entries: 16)
    {:ok, retiring} = ETS.start_link(max_entries: 16)
    left = ETS.store(destination)
    right = if inputs["same_store"], do: left, else: ETS.store(retiring)

    try do
      with {:ok, pair} <- Pair.store(left, right) do
        if inputs["destination_seeded"], do: :claimed = Replay.claim(left, claim, timeout: 5_000)
        if inputs["retiring_seeded"], do: :claimed = Replay.claim(right, claim, timeout: 5_000)

        with outcome when outcome in [:claimed, :already_claimed] <-
               Replay.claim(pair, claim, timeout: 5_000),
             {:ok, left_count} <- ETS.sweep(destination, until),
             {:ok, right_count} <- ETS.sweep(retiring, until) do
          {:ok,
           %{
             "outcome" => Atom.to_string(outcome),
             "destination" => left_count == 1,
             "retiring" => right_count == 1
           }}
        end
      end
    after
      GenServer.stop(destination)
      GenServer.stop(retiring)
    end
  end

  defp purpose(nil), do: nil
  defp purpose("build"), do: :build
  defp purpose("audit"), do: :audit
  defp purpose(true), do: true

  defp purpose_family("http"), do: :http
  defp purpose_family("jws"), do: :jws
  defp purpose_operation("http"), do: :http
  defp purpose_operation("jws"), do: :jws
  defp purpose_operation("raw"), do: :raw

  def parse_signature_base(root, case_) do
    bytes = root |> C.load(case_["inputs"]["base"]) |> C.bytes()

    with {:ok, parsed} <- RequestSeal.SignatureBase.parse(bytes) do
      {:ok,
       %{
         "components" => Enum.map(parsed.components, fn {id, value} -> [id, C.b64(value)] end),
         "signature_params" => C.b64(parsed.signature_params)
       }}
    end
  end

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

  def case_message(root, i) do
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
        handle = V.local("ed25519", material(root, "ed25519"))
        refused = %{handle | ref: fn -> raise "verification custody fault" end}
        fn _ -> {:ok, %{algorithm: "ed25519", key: refused}} end

      descriptor["behavior"] == "unknown" ->
        fn _ -> :error end

      name == "hmac-sha256" ->
        key = material(root, name)
        handle = V.local(name, key)
        fn _ -> {:ok, %{algorithm: name, key: handle}} end

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

            "deny" ->
              {:ok, set} = RequestSeal.DenySet.new(v)
              set

            "freshness" when is_map(v) ->
              %{
                clock: fn -> freshness_clock(now) end,
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

  defp freshness_clock([lower, upper]), do: {C.int(lower), C.int(upper)}
  defp freshness_clock(now), do: C.int(now)

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

  def verification_record(root, c) do
    i = c["inputs"]
    message = case_message(root, i)

    with {:ok, p} <- policy(root, c["policy"]),
         {:ok, result} <- RequestSeal.verify(message, p, label: i["label"], capture: true),
         {:ok, record} <- RequestSeal.VerificationRecord.from_verification(result),
         {:ok, bytes} <- RequestSeal.VerificationRecord.encode(record) do
      {:ok, %{"bytes" => C.b64(bytes)}}
    end
  end

  def verification_record_recheck(_root, c) do
    case RequestSeal.VerificationRecord.reverify(C.bytes(c["inputs"]["record"])) do
      :ok -> {:ok, %{"valid" => true}}
      {:error, :invalid_record} -> {:error, "verification_record/invalid_record"}
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

    handle = V.local(alg, key)

    signer =
      if i["signer"] == "raise",
        do: %{handle | ref: fn -> raise "signing custody fault" end},
        else: handle

    with {:ok, signed} <- RequestSeal.sign(m, spec, signer, opts) do
      if c["class"] == "byte_exact" do
        fields = Enum.take(signed.fields, -2) |> Enum.map(fn f -> [f.name, C.b64(f.value)] end)
        {:ok, %{"bytes" => fields}}
      else
        pk =
          if alg == "hmac-sha256",
            do: handle,
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

  def framed_fingerprint(_root, c) do
    i = c["inputs"]

    case RequestSeal.Fingerprint.digest(i["domain"], Enum.map(i["fields"], &C.bytes/1)) do
      {:ok, digest} -> {:ok, %{"digest" => C.b64(digest)}}
      {:error, :invalid_input} -> {:error, "fingerprint/invalid_input"}
    end
  end

  def framed_mac(_root, c) do
    i = c["inputs"]

    with {:ok, handle} <-
           RequestSeal.Custody.Local.new("hmac-sha256", {:hmac, C.bytes(i["key"])},
             capabilities: [:mac]
           ) do
      try do
        with {:ok, tag} <-
               RequestSeal.Custody.mac(handle, i["label"], Enum.map(i["fields"], &C.bytes/1)),
             do: {:ok, %{"tag" => C.b64(tag)}}
      after
        RequestSeal.Custody.release(handle)
      end
    end
  end

  def seed_check(root, c) do
    i = c["inputs"]
    jwk = C.load(root, i["jwk"])
    {:ok, deny} = RequestSeal.DenySet.new(i["deny"])

    with {:ok, handle} <-
           RequestSeal.Custody.Local.import("ed25519", jwk, :jwk,
             deny: deny,
             expected_thumbprint: i["expected_thumbprint"]
           ) do
      try do
        with {:ok, key} <- RequestSeal.Custody.public_key(handle),
             {:ok, thumbprint} <- PublicKey.thumbprint(key),
             do: {:ok, %{"thumbprint" => thumbprint}}
      after
        RequestSeal.Custody.release(handle)
      end
    end
  end

  def key_import(root, c) do
    i = c["inputs"]
    value = C.load(root, i["material"])
    value = if i["public_only"], do: Map.drop(value, ~w(d p q dp dq qi k)), else: value

    with {:ok, key} <- PublicKey.import(value, String.to_existing_atom(i["format"])),
         {:ok, thumbprint} <- PublicKey.thumbprint(key),
         do: {:ok, %{"valid" => true, "public" => %{"thumbprint" => thumbprint}}}
  end

  def decode_object(root, c) do
    i = c["inputs"]

    with {:ok, object} <-
           RequestSeal.JOSE.decode_object(C.bytes(C.load(root, i["bytes"])),
             max_bytes: C.int(i["max_bytes"])
           ) do
      {:ok, %{"object" => object_value(object)}}
    end
  end

  defp object_value(v) when is_integer(v), do: C.number(v)

  defp object_value(v) when is_map(v),
    do: Map.new(v, fn {k, value} -> {k, object_value(value)} end)

  defp object_value(v) when is_list(v), do: Enum.map(v, &object_value/1)
  defp object_value(v), do: v

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

    if p["protected"] do
      protected = p["protected"]

      mode =
        case protected["embedded_key"] do
          "refuse" -> :refuse
          "require" -> :require
        end

      # Resolver descriptors select real keys or explicit caller-boundary faults.
      # A handle is real custody, released in this case's own finalizer.
      fixture = V.fixture("rfc7515.json")["A.2"]["key"]

      handle =
        if i["resolver"] == "handle" do
          {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "RS256"}, V.rsa(fixture))
          handle
        end

      try do
        policy = %{
          algorithms: p["algorithms"],
          timeout: C.int(p["timeout"]),
          protected: %{
            expected: json_pairs(root, protected["expected"]),
            permitted: protected["permitted"],
            embedded_key: mode
          },
          key_resolver: fn request ->
            key =
              case i["resolver"] do
                "embedded" -> :embedded
                "public" -> Map.get(request, :embedded_key) || V.public(C.load(root, i["key"]))
                "handle" -> handle
                "closure" -> fn _, _, _ -> :ok end
                "null" -> nil
              end

            {:ok, %{algorithm: request.algorithm, key: key}}
          end
        }

        with {:ok, result} <- JWS.verify(C.bytes(i["compact"]), policy),
             do: {:ok, %{"valid" => true, "payload" => C.b64(result.payload)}}
      after
        if handle, do: RequestSeal.Custody.release(handle)
      end
    else
      base = V.jws_policy(C.load(root, i["key"]), hd(p["algorithms"]))
      policy = %{base | algorithms: p["algorithms"], timeout: C.int(p["timeout"])}

      with {:ok, result} <- JWS.verify(C.bytes(i["compact"]), policy),
           do: {:ok, %{"valid" => true, "payload" => C.b64(result.payload)}}
    end
  end

  defp json_pairs(root, value) do
    %{"pairs" => pairs} = C.load(root, value)
    C.require!(length(Enum.uniq_by(pairs, &hd/1)) == length(pairs), :duplicate_json_pair)
    Map.new(pairs, fn [key, value] -> {key, json_value(value)} end)
  end

  defp json_value(%{"int" => _} = value) when map_size(value) == 1, do: C.int(value)

  defp json_value(value) when is_map(value),
    do: Map.new(value, fn {k, v} -> {k, json_value(v)} end)

  defp json_value(value) when is_list(value), do: Enum.map(value, &json_value/1)
  defp json_value(value), do: value

  defp open_policy(resolver) do
    %{
      algorithms: RequestSeal.JOSE.Support.algorithms(:jwe),
      encryption: RequestSeal.JOSE.Support.encryption(),
      max_plaintext: 1_048_576,
      timeout: 30_000,
      resolve_timeout: 10_000,
      unwrap_timeout: 10_000,
      protected: %{expected: %{}, permitted: []},
      key_resolver: resolver
    }
  end

  def jwe_protected(root, c) do
    i = c["inputs"]
    p = i["policy"]

    policy = %{
      open_policy(fn _ -> :error end)
      | protected: %{expected: json_pairs(root, p["expected"]), permitted: p["permitted"]}
    }

    case JWE.decrypt(i["token"], policy) do
      # An unknown key is past all protected admission checks. A width-failed
      # admitted token follows the real fallback AEAD path instead.
      {:error, %{reason: reason}} when reason in [:unknown_key, :decryption_failed] ->
        {:ok, %{"accepted" => true}}

      error ->
        error
    end
  end

  # A single explicit algorithm table is shared by every named custody key.
  @key_algorithms Map.new(
                    for(
                      name <-
                        ~w(RSA-OAEP RSA-OAEP-256 A128KW A256KW A128GCMKW A256GCMKW dir ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW),
                      do: {{"jwe", name}, {:jwe, name}}
                    ) ++
                      for(
                        name <- ~w(RS256 PS256 PS384 PS512 HS256 ES256 ES384 EdDSA),
                        do: {{"jws", name}, {:jws, name}}
                      ) ++
                      for(
                        name <-
                          ~w(rsa-pss-sha512 rsa-v1_5-sha256 hmac-sha256 ecdsa-p256-sha256 ecdsa-p384-sha384 ed25519),
                        do: {{"http", name}, name}
                      ) ++
                      [{{"derive", "hkdf-sha256"}, {:derive, "hkdf-sha256"}}]
                  )

  defp native_key(root, entry) do
    C.require!(entry["state"] in ["live", "released"], :key_state)
    %{"kind" => kind, "name" => name} = entry["algorithm"]
    algorithm = Map.fetch!(@key_algorithms, {kind, name})

    capabilities =
      Enum.map(entry["capabilities"], fn
        "unwrap" -> :unwrap
        "wrap" -> :wrap
        "sign" -> :sign
        "verify" -> :verify
        "derive" -> :derive
      end)

    material = entry["material"]

    result =
      case material["format"] do
        "jwk" ->
          RequestSeal.Custody.Local.import(algorithm, native_jwk(root, material["value"]), :jwk,
            capabilities: capabilities
          )

        "raw" ->
          bytes = C.bytes(C.load(root, material["value"]))

          descriptor =
            case algorithm do
              {:jwe, "dir"} -> {:cek, bytes}
              {:derive, "hkdf-sha256"} -> {:ikm, bytes}
              {:jwe, _} -> {:aes, bytes}
            end

          RequestSeal.Custody.Local.new(algorithm, descriptor, capabilities: capabilities)
      end

    {:ok, handle} = result

    case entry["state"] do
      "live" -> :ok
      "released" -> :ok = RequestSeal.Custody.release(handle)
    end

    handle
  end

  defp native_jwk(root, value) do
    case C.load(root, value) do
      %{"pairs" => pairs} -> Map.new(pairs, &List.to_tuple/1)
      jwk -> jwk
    end
  end

  def jwe_decrypt_many(root, c) do
    i = c["inputs"]
    # The callback API carries public header facts, not batch positions. Reject
    # ambiguous descriptors rather than guessing callback order on concurrent
    # execution. Repeated requests with identical outcomes are countable.
    calls = :ets.new(:conformance_resolver, [:public])

    handles =
      Enum.reduce(i["keys"], %{}, fn {name, entry}, acc ->
        try do
          Map.put(acc, name, native_key(root, entry))
        catch
          kind, reason ->
            for {_, handle} <- acc, do: RequestSeal.Custody.release(handle)
            :ets.delete(calls)
            :erlang.raise(kind, reason, __STACKTRACE__)
        end
      end)

    try do
      outcomes = Enum.map(i["resolver"], &{C.int(&1["index"]), &1["outcome"]})

      C.require!(
        length(Enum.uniq_by(outcomes, &elem(&1, 0))) == length(outcomes),
        :duplicate_resolver_index
      )

      requests =
        outcomes
        |> Enum.map(fn {index, outcome} ->
          C.require!(index >= 0 and index < length(i["items"]), :resolver_index)
          item = Enum.fetch!(i["items"], index)
          [header | _] = String.split(item["token"], ".")
          {C.json(RequestSeal.JOSE.Support.decode(header)), outcome}
        end)
        |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
        |> Map.new(fn {header, outcomes} ->
          # Identical requests may repeat when their outcomes are identical.
          # Different indexed outcomes cannot be selected from header facts.
          C.require!(length(Enum.uniq(outcomes)) == 1, :ambiguous_resolver_index)
          {header, {length(outcomes), hd(outcomes)}}
        end)

      resolver = fn request ->
        case Map.fetch(requests, request.header) do
          :error ->
            :ets.insert(calls, {:unexpected, true})
            :error

          {:ok, {count, outcome}} ->
            actual = :ets.update_counter(calls, request.header, {2, 1}, {request.header, 0})

            if actual > count do
              :ets.insert(calls, {:unexpected, true})
              :error
            else
              case outcome do
                %{"key" => name} ->
                  {:ok, %{algorithm: request.algorithm, key: Map.fetch!(handles, name)}}

                "error" ->
                  :error

                "raise" ->
                  raise "conformance resolver exception"
              end
            end
        end
      end

      items =
        Enum.map(i["items"], &%{token: &1["token"], expected: json_pairs(root, &1["expected"])})

      policy =
        open_policy(resolver)
        |> Map.put(:protected, %{permitted: []})
        |> Map.merge(%{
          max_tokens: 10_000,
          max_total_input: 67_108_864,
          max_total_plaintext: 67_108_864
        })

      result = JWE.decrypt_many(items, policy)
      C.require!(not :ets.member(calls, :unexpected), :unexpected_resolver_call)

      for {header, {count, _}} <- requests do
        C.require!(:ets.lookup(calls, header) == [{header, count}], :missing_resolver_call)
      end

      with {:ok, results} <- result do
        {:ok,
         %{
           "results" =>
             results
             |> Enum.with_index()
             |> Enum.map(fn {result, index} ->
               base = %{"index" => C.number(index)}

               case result do
                 {:ok, value} -> Map.put(base, "plaintext", C.b64(value.plaintext))
                 {:error, error} -> Map.put(base, "rule_id", C.rule_id(error))
               end
             end)
         }}
      end
    after
      for {_, handle} <- handles, do: RequestSeal.Custody.release(handle)
      :ets.delete(calls)
    end
  end

  def hpke_derive_key_pair(root, c) do
    inputs = c["inputs"]

    {sk, pk} =
      RequestSeal.Custody.Derivation.key_pair(
        C.int(inputs["kem_id"]),
        root |> C.load(inputs["ikm"]) |> C.bytes()
      )

    {:ok, %{"sk" => C.b64(sk), "pk" => C.b64(pk)}}
  end

  def custody_derive(root, c) do
    alias RequestSeal.Custody
    inputs = c["inputs"]
    %{"kind" => kind, "name" => name} = inputs["target"]["algorithm"]
    algorithm = Map.fetch!(@key_algorithms, {kind, name})
    curve = inputs["target"]["curve"]
    opts = if curve == nil, do: [timeout: 5000], else: [timeout: 5000, curve: curve]

    {:ok, parent} =
      Custody.Local.new(
        {:derive, "hkdf-sha256"},
        {:ikm, root |> C.load(inputs["parent_ikm"]) |> C.bytes()}
      )

    try do
      case Custody.derive(parent, algorithm, C.bytes(inputs["domain"]), opts) do
        {:ok, child} ->
          try do
            case inputs["probe"] do
              %{"message" => message} ->
                with {:ok, tag} <- Custody.sign(child, C.bytes(message)) do
                  {:ok, %{"tag" => C.b64(tag)}}
                end

              %{"cek" => cek} ->
                with {:ok, result} <- Custody.wrap(child, C.bytes(cek)) do
                  {:ok, %{"wrapped" => C.b64(result.encrypted_key)}}
                end

              nil ->
                with {:ok, public} <- Custody.public_key(child),
                     {:ok, jwk} <- PublicKey.export(public, :jwk) do
                  pairs = jwk |> Enum.sort() |> Enum.map(fn {k, v} -> [k, v] end)
                  {:ok, %{"public_key" => %{"pairs" => pairs}}}
                end
            end
          after
            :ok = Custody.release(child)
          end

        error ->
          error
      end
    after
      :ok = Custody.release(parent)
    end
  end

  def aes_kw(_root, c) do
    i = c["inputs"]

    case i["operation"] do
      "wrap" ->
        with {:ok, result} <-
               KeyManagement.wrap(
                 i["alg"],
                 C.bytes(i["key_data"]),
                 %{},
                 {:aes, C.bytes(i["kek"])}
               ),
             do: {:ok, %{"wrapped" => C.b64(result.encrypted_key)}}

      "unwrap" ->
        with {:ok, key} <-
               KeyManagement.unwrap(
                 i["alg"],
                 C.bytes(i["wrapped"]),
                 %{},
                 {:aes, C.bytes(i["kek"])}
               ),
             do: {:ok, %{"key_data" => C.b64(key)}}

      _ ->
        C.require!(false, :aes_kw_operation)
    end
  end

  def ecdh_kdf(_root, c) do
    i = c["inputs"]

    with {:ok, output} <-
           KeyManagement.Agreement.kdf(
             C.bytes(i["z"]),
             i["algorithm_id"],
             C.bytes(i["apu"]),
             C.bytes(i["apv"]),
             C.int(i["keydatalen"])
           ),
         do: {:ok, %{"output" => C.b64(output)}}
  end

  def agree(root, c) do
    i = c["inputs"]

    with {:ok, recipient} <- PublicKey.import(jwk(root, i["recipient"]), :jwk),
         {:ok, result} <-
           KeyManagement.Agreement.run(
             i["alg"],
             i["enc"],
             recipient,
             %{apu: C.bytes(i["apu"]), apv: C.bytes(i["apv"])},
             C.bytes(i["ephemeral_private"]),
             if(i["cek"], do: C.bytes(i["cek"]))
           ) do
      private = jwk(root, i["recipient_private"])

      params =
        KeyManagement.Agreement.header_params!(
          i["alg"],
          Map.merge(result.header, %{"enc" => i["enc"], "apu" => V.enc(C.bytes(i["apu"]))})
        )

      # Empty absent parties are not added as equal empty header members.
      params = %{params | apu: C.bytes(i["apu"]), apv: C.bytes(i["apv"])}

      material =
        case private do
          %{"kty" => "EC", "crv" => crv, "d" => d} -> {:ec, crv, V.b64(d)}
          %{"kty" => "OKP", "crv" => "X25519", "d" => d} -> {:x25519, V.b64(d)}
        end

      C.require!(
        KeyManagement.unwrap(i["alg"], result.encrypted_key, params, {:ecdh, material}) ==
          {:ok, result.cek},
        :agreement_inverse
      )

      {:ok,
       %{
         "cek" => C.b64(result.cek),
         "encrypted_key" => C.b64(result.encrypted_key),
         "epk" => %{"pairs" => Enum.map(Enum.sort(result.header["epk"]), fn {k, v} -> [k, v] end)}
       }}
    end
  end

  defp jwk(root, value) do
    case C.load(root, value) do
      %{"pairs" => pairs} -> Map.new(pairs, &List.to_tuple/1)
      key -> key
    end
  end

  def aes_kw_item(g, t, override) do
    alg = if g["keySize"] == 128, do: "A128KW", else: "A256KW"
    result = KeyManagement.unwrap(alg, V.hex(t["ct"]), %{}, {:aes, V.hex(t["key"])})
    batch_result(result, t, override)
  end

  def ecdh_item(g, t, override) do
    # SPKI is the published Wycheproof input, not an invented JWK. Canonical
    # named-curve, uncompressed points pass the same PublicKey importer.
    result =
      RequestSeal.JOSE.Support.safe(
        fn ->
          case PublicKey.import(V.hex(t["public"]), :der) do
            {:ok, public} ->
              crv = if g["curve"] == "secp256r1", do: "P-256", else: "P-384"
              width = if crv == "P-256", do: 32, else: 48
              scalar = V.hex(t["private"])
              # Upstream unsigned scalars sometimes include a DER sign octet.
              scalar = :binary.encode_unsigned(:binary.decode_unsigned(scalar))
              C.require!(byte_size(scalar) <= width, :scalar_width)
              scalar = :binary.copy(<<0>>, width - byte_size(scalar)) <> scalar
              {:ok, KeyManagement.Agreement.shared_secret(public, {:ec, crv, scalar})}

            _ ->
              RequestSeal.JOSE.Support.fail(:decryption_failed, :crypto)
          end
        end,
        :decryption_failed,
        :crypto
      )

    agreement_result(result, t, override)
  end

  def x25519_item(_g, t, override) do
    result =
      RequestSeal.JOSE.Support.safe(
        fn ->
          {:ok, public} = PublicKey.import({:x25519, V.hex(t["public"])}, :raw)
          {:ok, KeyManagement.Agreement.shared_secret(public, {:x25519, V.hex(t["private"])})}
        end,
        :decryption_failed,
        :crypto
      )

    agreement_result(result, t, override)
  end

  defp agreement_result(result, t, nil) do
    C.require!(t["result"] in ["valid", "invalid", "acceptable"], :upstream_verdict)

    if t["result"] == "invalid",
      do: match?({:error, _}, result),
      else: result == {:ok, V.hex(t["shared"])}
  end

  defp agreement_result({:error, error}, _, %{"outcome" => "reject", "rule_id" => rule}),
    do: C.rule_id(error) == rule

  defp agreement_result(_, _, _), do: false

  def rfc8037_epk(t) do
    {:ok, public} = PublicKey.import({:x25519, V.hex(t["public"])}, :raw)

    with {:ok, result} <-
           KeyManagement.Agreement.run(
             "ECDH-ES+A128KW",
             "A128GCM",
             public,
             %{},
             V.hex(t["private"]),
             <<0::128>>
           ) do
      result.header["epk"] == t["epk"] and x25519_item(nil, t, nil)
    end
  end

  def rfc7520_gcmkw(v) do
    actual =
      KeyManagement.unwrap(
        v["input"]["alg"],
        V.b64(v["encrypting_key"]["encrypted_key"]),
        %{iv: V.b64(v["encrypting_key"]["iv"]), tag: V.b64(v["encrypting_key"]["tag"])},
        {:aes, V.b64(v["input"]["key"]["k"])}
      )

    actual == {:ok, V.b64(v["generated"]["cek"])}
  end

  def jwe_decrypt(root, c) do
    i = c["inputs"]
    j = C.load(root, i["key"])
    p = c["policy"]

    # Every asymmetric agreement envelope exercises real custody, including
    # the RFC 7520 P-384 published message; lifecycle ends with this case.
    if j["kty"] in ["EC", "OKP"] do
      alg = hd(p["algorithms"])

      with {:ok, handle} <- RequestSeal.Custody.Local.import({:jwe, alg}, j, :jwk) do
        try do
          policy = %{
            algorithms: p["algorithms"],
            encryption: p["encryption"],
            max_plaintext: 1_048_576,
            timeout: 5000,
            resolve_timeout: 1000,
            unwrap_timeout: 1000,
            protected: %{expected: %{}, permitted: ~w(kid typ cty)},
            key_resolver: fn _ -> {:ok, %{algorithm: alg, key: handle}} end
          }

          with {:ok, result} <- JWE.decrypt(C.bytes(i["compact"]), policy),
               do: {:ok, %{"valid" => true, "payload" => C.b64(result.plaintext)}}
        after
          RequestSeal.Custody.release(handle)
        end
      end
    else
      with {:ok, result} <-
             JWE.decrypt(
               C.bytes(i["compact"]),
               V.jwe_policy(j, hd(p["algorithms"]), hd(p["encryption"]))
             ),
           do: {:ok, %{"valid" => true, "payload" => C.b64(result.plaintext)}}
    end
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
           RequestSeal.Discovery.parse_body(
             C.bytes(C.load(root, i["body"])),
             s,
             freshness_clock(c["now"])
           ),
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
          RequestSeal.sign(
            m,
            %{label: "s", algorithm: "ed25519", signature_input: input},
            V.local("ed25519", material)
          )

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
        %{iv: iv, tag: tag},
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
