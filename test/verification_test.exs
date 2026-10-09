defmodule RequestSeal.VerificationTest do
  use ExUnit.Case, async: false

  alias RequestSeal.{
    Body,
    Crypto,
    Digest,
    FieldOccurrence,
    Message,
    Policy,
    PublicKey,
    TransportFacts
  }

  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.{Schema, Value}
  @root Path.join(__DIR__, "fixtures")
  @vectors :json.decode(File.read!(Path.join(@root, "verification/rfc9421.json")))
  @bases :json.decode(File.read!(Path.join(@root, "signature_base/rfc9421.json")))
  @crypto :json.decode(File.read!(Path.join(@root, "crypto/rfc9421.json")))

  test "inspection hides principal data for every HTTP signature profile" do
    for profile <- [
          %{name: :rfc9421},
          %{
            name: {:test_pkg, :synthetic},
            source: "public-source",
            revision: 1
          },
          %{
            name: {:test_pkg, :synthetic},
            source: "public-source",
            revision: 2
          },
          %{name: :web_bot_auth, revision: "draft-ietf-webbotauth-httpsig-protocol-00"}
        ] do
      value = %RequestSeal.Verification{
        label: "agent",
        profile: profile,
        principal: %{identifier: "PRINCIPAL-CANARY"}
      }

      assert value.principal.identifier == "PRINCIPAL-CANARY"
      rendered = inspect(value)
      assert rendered =~ "profile:"
      refute rendered =~ "principal:"
      refute rendered =~ "PRINCIPAL-CANARY"
    end
  end

  test "base cache never reuses bytes across labels with the same field schemas" do
    alias RequestSeal.{Authentication, SignatureBase}
    alias RequestSeal.MultiSignatureSupport, as: S

    m = S.signed(["sig-b21", "sig-b26"])
    p = S.policy()
    {:ok, {entries, signatures}} = Authentication.dictionaries(m, p.max_signatures)
    inputs = Map.new(entries)

    {{:ok, first, _}, cache} =
      Authentication.verify_label(
        m,
        p,
        "sig-b21",
        inputs["sig-b21"],
        signatures["sig-b21"],
        %{},
        %{}
      )

    assert first.label == "sig-b21"

    {result, cache} =
      Authentication.verify_label(
        m,
        p,
        "sig-b26",
        inputs["sig-b26"],
        signatures["sig-b26"],
        %{},
        cache
      )

    assert {:ok, %{label: "sig-b26"}, _} = result
    {:ok, first_base} = SignatureBase.build(m, inputs["sig-b21"], field_schemas: p.field_schemas)
    {:ok, second_base} = SignatureBase.build(m, inputs["sig-b26"], field_schemas: p.field_schemas)
    refute first_base == second_base
    assert map_size(cache) == 2
    assert cache[{"sig-b21", p.field_schemas}] == {:ok, first_base}
    assert cache[{"sig-b26", p.field_schemas}] == {:ok, second_base}
  end

  test "F5 duplicate labels fail closed in verify across and within field occurrences" do
    alias RequestSeal.MultiSignatureSupport, as: S
    m = S.signed(["sig-b26"])
    assert {:ok, _} = RequestSeal.verify(m, S.policy(), label: "sig-b26")

    for name <- ["signature-input", "signature"], across <- [true, false] do
      f = Enum.find(m.fields, &(String.downcase(&1.name) == name))

      duplicate =
        if across,
          do: %{m | fields: m.fields ++ [f]},
          else: S.rewrite(m, fn n, v -> if n == name, do: v <> ", " <> v, else: v end)

      S.error(
        RequestSeal.verify(duplicate, S.policy(), label: "sig-b26"),
        :duplicate_label,
        :fields
      )
    end

    S.error(
      RequestSeal.verify(S.append(m, S.vector("sig-b26")), S.policy(), label: "sig-b26"),
      :duplicate_label,
      :fields
    )
  end

  for {first, last} <- [{"a", "fresh"}, {"fresh", "a"}],
      name <- ["signature-input", "signature", "component"],
      entry <- [:single, :quorum] do
    @first first
    @last last
    @name name
    @entry entry
    test "N3 duplicate parameters #{entry} #{name} #{first} then #{last}" do
      alias RequestSeal.MultiSignatureSupport, as: S

      input =
        if @name == "component",
          do: ~s[("signature-input";key="sig-b26")],
          else: ~s[("@method");nonce="#{@last}"]

      base = if @name == "component", do: S.signed(["sig-b26"]), else: S.unsigned()
      m = S.local_sign(base, "s", input)

      wire =
        S.rewrite(m, fn
          "signature-input", "s=" <> v when @name == "signature-input" ->
            "s=" <>
              String.replace(v, ~s[;nonce="#{@last}"], ~s[;nonce="#{@first}";nonce="#{@last}"])

          "signature", "s=" <> v when @name == "signature" ->
            "s=" <> v <> ~s[;nonce="#{@first}";nonce="#{@last}"]

          "signature-input", "s=" <> v when @name == "component" ->
            keys =
              if @first == "a",
                do: ~s[;key="other";key="sig-b26"],
                else: ~s[;key="sig-b26";key="other"]

            "s=" <> String.replace(v, ~s[;key="sig-b26"], keys)

          _, v ->
            v
        end)

      result =
        case @entry do
          :single -> RequestSeal.verify(wire, S.policy(), label: "s")
          :quorum -> S.verify_quorum(wire, S.quorum([S.slot(:s, label: "s")]))
        end

      S.error(result, :duplicate_parameter, :fields)
    end
  end

  test "all eight published signatures return exactly the complete layered result" do
    assert length(@vectors) == 8

    for v <- @vectors do
      message = message(v)
      assert {:ok, result} = RequestSeal.verify(message, policy(v), label: v["label"])
      assert result == expected(v)
      rendered = inspect(result)
      refute rendered =~ "test-key"
      refute rendered =~ "test-shared-secret"
      refute rendered =~ "b3k2pp5k7z"
    end

    [hash, name] =
      File.read!(Path.join(@root, "verification/SHA256SUMS"))
      |> String.trim()
      |> String.split("  ")

    assert name == "rfc9421.json"

    assert hash ==
             Base.encode16(
               :crypto.hash(:sha256, File.read!(Path.join(@root, "verification/" <> name))),
               case: :lower
             )
  end

  test "published transformations preserve or invalidate the complete result as specified" do
    v = vector("B.4")
    b = base(v)
    assert length(b["transformations"]) == 5

    for t <- b["transformations"] do
      m = from_public(t["message"], "") |> signed(v)

      if t["same_base"] do
        assert RequestSeal.verify(m, policy(v), label: v["label"]) == {:ok, expected(v)}
      else
        error(RequestSeal.verify(m, policy(v), label: v["label"]), :invalid_signature, :crypto)
      end
    end
  end

  test "algorithm and exact component policies reject otherwise valid signatures" do
    v = vector("B.2.6")

    error(
      RequestSeal.verify(message(v), policy(v, algorithms: ["rsa-pss-sha512"]),
        label: v["label"]
      ),
      :algorithm_not_permitted,
      :policy
    )

    for components <- [~s[("@query")], ~s[("content-type";sf)]] do
      error(
        RequestSeal.verify(message(v), policy(v, components: components), label: v["label"]),
        :missing_required_component,
        :policy
      )
    end

    error(
      RequestSeal.verify(message(v), policy(v, components: "()", extra_components: :reject),
        label: v["label"]
      ),
      :unexpected_component,
      :policy
    )

    assert RequestSeal.verify(message(v), policy(v, extra_components: :reject), label: v["label"]) ==
             {:ok, expected(v)}

    m =
      rewrite(
        message(v),
        "signature-input",
        String.replace(v["signature_input"], ";created=", ";alg=\"rsa-pss-sha512\";created=")
      )

    error(
      RequestSeal.verify(m, policy(v, algorithms: ["ed25519", "rsa-pss-sha512"]),
        label: v["label"]
      ),
      :algorithm_mismatch,
      :policy
    )
  end

  test "sender alg outside the allowlist rejects before calling the real key resolver" do
    v = vector("B.2.6")
    owner = self()

    resolver = fn metadata ->
      send(owner, {:resolved, metadata})
      {:ok, %{algorithm: v["algorithm"], key: public(v["key"])}}
    end

    p = policy(v, key_resolver: resolver)
    m = message(v)

    for alg <- ["rsa-pss-sha512", "Ed25519", "none", "EdDSA"] do
      rejected = rewrite(m, "signature-input", v["signature_input"] <> ";alg=\"#{alg}\"")
      result = RequestSeal.verify(rejected, p, label: v["label"])
      refute_received {:resolved, _}
      error(result, :algorithm_not_permitted, :policy)
    end

    # The same resolver really imports the public key and verifies the published signature.
    assert RequestSeal.verify(m, p, label: v["label"]) == {:ok, expected(v)}
    assert_received {:resolved, %{label: "sig-b26", keyid: "test-key-ed25519", tag: nil}}
  end

  test "resolver algorithm checks remain authoritative with and without sender alg" do
    v = vector("B.2.6")
    m = message(v)

    for {input, allowed, reason} <- [
          {m, ["rsa-pss-sha512"], :algorithm_not_permitted},
          {rewrite(m, "signature-input", v["signature_input"] <> ";alg=\"rsa-pss-sha512\""),
           ["ed25519", "rsa-pss-sha512"], :algorithm_mismatch}
        ] do
      error(
        RequestSeal.verify(
          input,
          policy(v,
            algorithms: allowed,
            key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public("ed25519")}} end
          ),
          label: v["label"]
        ),
        reason,
        :policy
      )
    end
  end

  test "content digest is covered, recomputed and algorithm constrained" do
    v = vector("B.2.3")
    p = policy(v, content: content())
    assert {:ok, result} = RequestSeal.verify(message(v), p, label: v["label"])

    assert result == %{
             expected(v)
             | content: %{kind: :content, bytes: 18, checked: ["sha-512"], unsupported: 0}
           }

    error(
      RequestSeal.verify(%{message(v) | body: body(~s[{"hello": "World"}])}, p,
        label: v["label"]
      ),
      :digest_mismatch,
      :content
    )

    error(
      RequestSeal.verify(%{message(v) | body: unavailable()}, p, label: v["label"]),
      :body_unavailable,
      :content
    )

    error(
      RequestSeal.verify(message(v), policy(v, content: %{content() | algorithms: ["sha-256"]}),
        label: v["label"]
      ),
      :digest_unsupported,
      :content
    )

    h = vector("B.2.5")

    error(
      RequestSeal.verify(message(h), policy(h, content: content()), label: h["label"]),
      :digest_not_covered,
      :content
    )

    {:ok, state} = Digest.init(:content, ["sha-512"])
    {:ok, state} = Digest.update(state, message(v).body.bytes)

    assert RequestSeal.verify(%{message(v) | body: unavailable()}, p,
             label: v["label"],
             digest_state: state
           ) == {:ok, result}

    p = policy(v, content: %{content() | kind: :representation})

    error(
      RequestSeal.verify(message(v), p, label: v["label"], representation: message(v).body),
      :digest_not_covered,
      :content
    )

    error(
      RequestSeal.verify(message(v), policy(v, content: content()),
        label: v["label"],
        digest_state: %{state | kind: :representation}
      ),
      :invalid_options,
      :input
    )
  end

  test "Section 4.3 freshness uses exact expiration, age and skew inequalities" do
    {v, m} = proxy()

    for {now, age, skew, outcome} <- [
          {1_618_884_539, nil, 0, :ok},
          {1_618_884_540, nil, 0, :expired},
          {1_618_884_540, nil, 1, :ok},
          {1_618_884_541, nil, 1, :expired},
          {1_618_884_540, 60, 0, :ok},
          {1_618_884_541, 60, 0, :too_old},
          {1_618_884_479, nil, 0, :created_in_future},
          {1_618_884_479, nil, 1, :ok},
          {1_618_884_478, nil, 1, :created_in_future},
          {1_618_884_541, 60, 1, :ok}
        ] do
      # Age tests omit expires so expiration cannot mask the max-age boundary.
      {v, m} =
        if age,
          do: resign(m, v, String.replace(parameters(v), ";expires=1618884540", "")),
          else: {v, m}

      fresh = %{clock: fn -> now end, max_age: age, skew: skew, require_expires: age == nil}
      result = RequestSeal.verify(m, policy(v, freshness: fresh), label: v["label"])

      if outcome == :ok do
        assert result ==
                 {:ok,
                  %{
                    expected(v)
                    | freshness: %{
                        now: now,
                        created: 1_618_884_480,
                        expires: if(age, do: nil, else: 1_618_884_540),
                        max_age: age,
                        skew: skew
                      }
                  }}
      else
        error(result, outcome, :freshness)
      end
    end

    error(
      RequestSeal.verify(
        m,
        policy(v,
          key_resolver: fn _ -> {:ok, %{algorithm: "rsa-pss-sha512", key: public("rsa_pss")}} end
        ),
        label: v["label"]
      ),
      :algorithm_mismatch,
      :policy
    )
  end

  test "freshness parameter requirements and clock boundary fail closed" do
    v = vector("B.2.6")
    fresh = %{clock: fn -> 1_618_884_473 end, max_age: 60, skew: 0, require_expires: false}
    {without, m} = resign(message(v), v, String.replace(parameters(v), ";created=1618884473", ""))

    error(
      RequestSeal.verify(m, policy(without, freshness: fresh), label: v["label"]),
      :missing_created,
      :freshness
    )

    error(
      RequestSeal.verify(message(v), policy(v, freshness: %{fresh | require_expires: true}),
        label: v["label"]
      ),
      :missing_expires,
      :freshness
    )

    for clock <- [
          fn -> 1.5 end,
          fn -> raise "CLOCK_CANARY" end,
          fn -> throw(:clock_canary) end,
          fn -> 1_000_000_000_000_000 end,
          fn -> -1_000_000_000_000_000 end
        ] do
      error(
        RequestSeal.verify(message(v), policy(v, freshness: %{fresh | clock: clock}),
          label: v["label"]
        ),
        :invalid_clock,
        :freshness
      )
    end
  end

  test "explicit labels, both dictionaries and parameter types are mandatory" do
    v = vector("B.2.6")
    m = message(v)
    p = policy(v)
    error(RequestSeal.verify(m, p, []), :invalid_options, :input)
    error(RequestSeal.verify(m, p, label: "other"), :unknown_label, :fields)

    error(
      RequestSeal.verify(
        rewrite(m, "signature", String.replace(v["signature"], v["label"], "other")),
        p,
        label: v["label"]
      ),
      :label_mismatch,
      :fields
    )

    for {name, reason} <- [
          {"signature-input", :missing_signature_input},
          {"signature", :missing_signature}
        ] do
      error(RequestSeal.verify(remove(m, name), p, label: v["label"]), reason, :fields)
    end

    for wire <- ["oops", "sig-b26=:AA==:", "sig-b26=();created=1.5", "sig-b26=();keyid=token"] do
      error(
        RequestSeal.verify(rewrite(m, "signature-input", wire), p, label: v["label"]),
        :invalid_signature_input,
        :fields
      )
    end

    for wire <- ["oops", "sig-b26=()", "sig-b26=token"] do
      error(
        RequestSeal.verify(rewrite(m, "signature", wire), p, label: v["label"]),
        :invalid_signature_field,
        :fields
      )
    end

    assert RequestSeal.verify(rewrite(m, "signature", v["signature"] <> ";ignored=123"), p,
             label: v["label"]
           ) == {:ok, expected(v)}
  end

  test "signature and covered fields tamper but uncovered date remains editable" do
    v = vector("B.2.3")
    <<b, rest::binary>> = signature(v)

    m =
      rewrite(
        message(v),
        "signature",
        v["label"] <> "=:" <> Base.encode64(<<Bitwise.bxor(b, 1), rest::binary>>) <> ":"
      )

    error(RequestSeal.verify(m, policy(v), label: v["label"]), :invalid_signature, :crypto)

    error(
      RequestSeal.verify(rewrite(message(v), "content-length", "19"), policy(v),
        label: v["label"]
      ),
      :invalid_signature,
      :crypto
    )

    v = vector("B.2.1")

    assert RequestSeal.verify(
             rewrite(message(v), "date", "Tue, 20 Apr 2021 02:07:56 GMT"),
             policy(v),
             label: v["label"]
           ) == {:ok, expected(v)}
  end

  test "caller signers reproduce deterministic published signatures and round trip randomized algorithms" do
    for section <- ["B.2.5", "B.2.6", "B.2.3", "B.2.4"] do
      v = vector(section)
      m = message(v) |> remove("signature") |> remove("signature-input")

      assert {:ok, signed} =
               RequestSeal.sign(
                 m,
                 %{label: v["label"], signature_input: parameters(v), algorithm: v["algorithm"]},
                 signer(v)
               )

      assert Message.validate(signed) == :ok
      assert RequestSeal.verify(signed, policy(v), label: v["label"]) == {:ok, expected(v)}

      if section in ["B.2.5", "B.2.6"] do
        assert field(signed, "signature") == v["signature"]
        assert field(signed, "signature-input") == v["signature_input"]
      end

      error(
        RequestSeal.sign(
          signed,
          %{label: v["label"], signature_input: parameters(v), algorithm: v["algorithm"]},
          signer(v)
        ),
        :label_in_use,
        :fields
      )

      {:ok, %Value{value: [input]}} = SF.parse(parameters(v), schema(:list))

      assert {:ok, _} =
               RequestSeal.sign(
                 m,
                 %{label: v["label"], signature_input: input, algorithm: v["algorithm"]},
                 signer(v),
                 field_schemas: %{}
               )
    end
  end

  test "Section 2.4 response signs and verifies req components with real local Ed25519" do
    v = vector("B.2.6")
    b = Enum.find(@bases, &(&1["section"] == "2.4"))
    m = from_public(b["message"], "")
    v = %{v | "signature_input" => v["label"] <> "=" <> b["parameters"]}

    assert {:ok, signed} =
             RequestSeal.sign(
               m,
               %{label: v["label"], signature_input: parameters(v), algorithm: v["algorithm"]},
               signer(v)
             )

    assert RequestSeal.verify(signed, policy(v), label: v["label"]) == {:ok, expected(v)}
  end

  test "JWS selection is explicit and excludes an HTTP alg parameter" do
    v = vector("B.2.6")
    m = message(v) |> remove("signature") |> remove("signature-input")

    p =
      policy(v,
        algorithms: [{:jws, "EdDSA"}],
        key_resolver: fn _ -> {:ok, %{algorithm: {:jws, "EdDSA"}, key: public("ed25519")}} end
      )

    assert {:ok, signed} =
             RequestSeal.sign(
               m,
               %{label: v["label"], signature_input: parameters(v), algorithm: {:jws, "EdDSA"}},
               signer(v)
             )

    assert RequestSeal.verify(signed, p, label: v["label"]) ==
             {:ok,
              put_in(
                expected(v),
                [Access.key!(:signature), Access.key!(:algorithm)],
                {:jws, "EdDSA"}
              )}

    assert RequestSeal.verify(message(v), p, label: v["label"]) ==
             {:ok,
              put_in(
                expected(v),
                [Access.key!(:signature), Access.key!(:algorithm)],
                {:jws, "EdDSA"}
              )}

    params = parameters(v) <> ";alg=\"ed25519\""

    error(
      RequestSeal.sign(
        m,
        %{label: v["label"], signature_input: params, algorithm: {:jws, "EdDSA"}},
        signer(v)
      ),
      :algorithm_mismatch,
      :input
    )
  end

  test "signing reports an HTTP alg mismatch at the input layer" do
    v = vector("B.2.5")
    m = message(v) |> remove("signature") |> remove("signature-input")

    error(
      RequestSeal.sign(
        m,
        %{
          label: v["label"],
          signature_input: ~s[("date");alg="ed25519"],
          algorithm: v["algorithm"]
        },
        signer(v)
      ),
      :algorithm_mismatch,
      :input
    )
  end

  test "resolver, verifier and signer boundaries discard throws, exceptions and malformed results" do
    v = vector("B.2.6")
    m = message(v)

    error(
      RequestSeal.verify(m, policy(v, key_resolver: fn _ -> :error end), label: v["label"]),
      :unknown_key,
      :key
    )

    for resolver <- [
          fn _ -> raise "KEY_CANARY" end,
          fn _ -> throw(:key_canary) end,
          fn _ -> nil end,
          fn _ -> {:ok, %{algorithm: "ed25519", key: "private"}} end
        ] do
      error(
        RequestSeal.verify(m, policy(v, key_resolver: resolver), label: v["label"]),
        :key_resolver_failed,
        :key
      )
    end

    for verifier <- [
          fn _, _, _ -> raise "VERIFIER_CANARY" end,
          fn _, _, _ -> throw(:verifier_canary) end,
          fn _, _, _ -> :wrong end
        ] do
      error(
        RequestSeal.verify(
          m,
          policy(v, key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: verifier}} end),
          label: v["label"]
        ),
        :verifier_failed,
        :crypto
      )
    end

    # Actual cryptography returns an error for a tampered signature through the closure too.
    h = vector("B.2.5")
    hm = rewrite(message(h), "signature", h["label"] <> "=:" <> Base.encode64(<<0::256>>) <> ":")
    error(RequestSeal.verify(hm, policy(h), label: h["label"]), :invalid_signature, :crypto)
    m = m |> remove("signature-input") |> remove("signature")
    spec = %{label: v["label"], signature_input: parameters(v), algorithm: v["algorithm"]}

    for signer <- [
          fn _, _ -> raise "SIGNER_CANARY" end,
          fn _, _ -> throw(:signer_canary) end,
          fn _, _ -> {:error, "PRIVATE_CANARY"} end,
          fn _, _ -> {:ok, nil} end,
          fn _, _ -> {:ok, :binary.copy(<<0>>, 1025)} end
        ] do
      error(RequestSeal.sign(m, spec, signer), :signer_failed, :crypto)
    end

    error(
      RequestSeal.verify(remove(message(v), "content-type"), policy(v), label: v["label"]),
      :signature_base_failed,
      :crypto,
      :missing_field
    )
  end

  test "signature dictionaries bound encounters and decoded signature bytes" do
    v = vector("B.2.6")
    m = message(v)
    p = policy(v)

    error(
      RequestSeal.verify(
        rewrite(
          m,
          "signature",
          v["label"] <> "=:" <> Base.encode64(:binary.copy(<<0>>, 1025)) <> ":"
        ),
        p,
        label: v["label"]
      ),
      :limit,
      :input
    )

    wire = Enum.map_join(1..17, ", ", &"sig#{&1}=:AA==:")
    error(RequestSeal.verify(rewrite(m, "signature", wire), p, label: v["label"]), :limit, :input)
    input = Enum.map_join(1..17, ", ", &"sig#{&1}=()")

    error(
      RequestSeal.verify(rewrite(m, "signature-input", input), p, label: v["label"]),
      :limit,
      :input
    )

    # Repeated keys count toward the ceiling before SF's documented merge.
    wire = Enum.map_join(1..17, ", ", fn _ -> v["signature"] end)
    error(RequestSeal.verify(rewrite(m, "signature", wire), p, label: v["label"]), :limit, :input)

    error(
      RequestSeal.verify(m, policy(v, max_signatures: 1), label: v["label"], label: v["label"]),
      :invalid_options,
      :input
    )

    error(RequestSeal.verify(%{m | method: nil}, p, label: v["label"]), :invalid_message, :input)
  end

  test "policy requires six choices and validates every optional default and bound" do
    v = vector("B.2.6")
    attrs = attrs(v)
    assert {:ok, p} = Policy.new(attrs)
    assert p.field_schemas == %{} and p.extra_components == :allow and p.max_signatures == 16

    for key <- [:algorithms, :components, :key_resolver, :freshness, :content, :replay] do
      error(Policy.new(Map.delete(attrs, key)), :invalid_policy, :input)
    end

    {:ok, field_schema} =
      Schema.new(%{revision: :rfc8941, type: :dictionary, item_types: [:bytes]})

    field_schemas = Map.new(1..1024, fn index -> {"x-field-#{index}", field_schema} end)
    assert map_size(field_schemas) == 1024
    assert {:ok, bounded} = Policy.new(Map.put(attrs, :field_schemas, field_schemas))
    assert bounded.field_schemas == field_schemas

    oversized_schemas = Map.put(field_schemas, "x-field-1025", field_schema)
    assert map_size(oversized_schemas) == 1025

    error(
      Policy.new(Map.put(attrs, :field_schemas, oversized_schemas)),
      :invalid_policy,
      :input
    )

    for changes <- [
          %{components: "(" <> Enum.map_join(1..257, " ", fn _ -> ~s["@path"] end) <> ")"},
          %{components: ~s[("@path" "@path")]},
          %{components: ~s[("@path";sf)]},
          %{components: ~s[("Content-Type")]},
          %{components: "();created=1"},
          %{algorithms: []},
          %{algorithms: ["ed25519", "ed25519"]},
          %{algorithms: ["Ed25519"]},
          %{replay: :required},
          %{extra_components: :other},
          %{field_schemas: %{"content-type" => :wrong}},
          %{max_signatures: 0},
          %{max_signatures: 65},
          %{key_resolver: fn -> :error end},
          %{
            freshness: %{
              clock: fn -> 0 end,
              max_age: nil,
              skew: 86_401,
              require_expires: false
            }
          },
          %{freshness: %{clock: fn -> 0 end, max_age: 0, skew: 0, require_expires: false}},
          %{content: %{content() | algorithms: []}},
          %{content: %{content() | section: :unknown}},
          %{unknown: true}
        ] do
      error(Policy.new(Map.merge(attrs, changes)), :invalid_policy, :input)
    end

    assert {:ok, _} =
             Policy.new(
               Map.merge(attrs, %{
                 max_signatures: 64,
                 freshness: %{
                   clock: fn -> 0 end,
                   max_age: nil,
                   skew: 86_400,
                   require_expires: false
                 }
               })
             )

    error(
      RequestSeal.verify(message(v), %{p | replay: :required}, label: v["label"]),
      :invalid_policy,
      :input
    )

    error(RequestSeal.verify(message(v), p, label: "BAD"), :invalid_options, :input)

    error(
      RequestSeal.verify(message(v), p, label: v["label"], unknown: true),
      :invalid_options,
      :input
    )

    error(RequestSeal.sign(message(v), %{}, signer(v)), :invalid_options, :input)

    error(
      RequestSeal.sign(
        message(v),
        %{label: "BAD", algorithm: "ed25519", signature_input: "()"},
        signer(v)
      ),
      :invalid_options,
      :input
    )
  end

  for field <- [:policy, :content], path <- [:new, :verify] do
    test "improper #{field} algorithms return invalid_policy through #{path}" do
      v = vector("B.2.6")

      for tail <- [:tail, "tail", nil, %{}] do
        changes =
          case unquote(field) do
            :policy -> %{algorithms: [v["algorithm"] | tail]}
            :content -> %{content: %{content() | algorithms: ["sha-512" | tail]}}
          end

        result =
          case unquote(path) do
            :new ->
              Policy.new(Map.merge(attrs(v), changes))

            :verify ->
              RequestSeal.verify(message(v), struct(policy(v), changes), label: v["label"])
          end

        error(result, :invalid_policy, :input)
      end
    end
  end

  test "dictionary syntax precedes selected metadata and all caller work" do
    v = vector("B.2.6")

    m =
      rewrite(message(v), "signature-input", v["label"] <> "=();created=1.5")
      |> rewrite("signature", "broken")

    error(RequestSeal.verify(m, policy(v), label: v["label"]), :invalid_signature_field, :fields)
    owner = self()

    resolver = fn metadata ->
      send(owner, {:resolved, metadata})
      {:ok, %{algorithm: v["algorithm"], key: public(v["key"])}}
    end

    error(
      RequestSeal.verify(
        message(v),
        policy(v, components: ~s[("@query")], key_resolver: resolver),
        label: v["label"]
      ),
      :missing_required_component,
      :policy
    )

    refute_received {:resolved, _}

    assert RequestSeal.verify(message(v), policy(v, key_resolver: resolver), label: v["label"]) ==
             {:ok, expected(v)}

    assert_received {:resolved, %{label: "sig-b26", keyid: "test-key-ed25519", tag: nil}}
    {v, m} = proxy()

    error(
      RequestSeal.verify(
        m,
        policy(v,
          algorithms: ["rsa-v1_5-sha256", "rsa-pss-sha512"],
          key_resolver: fn _ -> {:ok, %{algorithm: "rsa-pss-sha512", key: public("rsa_pss")}} end
        ),
        label: v["label"]
      ),
      :algorithm_mismatch,
      :policy
    )

    error(
      RequestSeal.verify(m, policy(v, algorithms: ["rsa-pss-sha512"]), label: v["label"]),
      :algorithm_not_permitted,
      :policy
    )
  end

  test "digest coverage is exact across sf, trailers, representation and req" do
    v = vector("B.2.3")
    original = message(v)

    {:ok, digest_schema} =
      Schema.new(%{revision: :rfc8941, type: :dictionary, item_types: [:bytes]})

    for {kind, section, marker} <- [
          {:content, :headers, ""},
          {:content, :headers, ";sf"},
          {:content, :trailers, ";tr"},
          {:content, :trailers, ";sf;tr"},
          {:representation, :headers, ""}
        ] do
      name = if kind == :content, do: "content-digest", else: "repr-digest"
      wire = field(original, "content-digest")
      m = remove(original, "content-digest")

      m =
        if section == :headers do
          %{m | fields: m.fields ++ [occurrence(name, wire)]}
        else
          %{m | trailers: [%{occurrence(name, wire) | section: :trailers}]}
        end

      params = String.replace(parameters(v), ~s["content-digest"], "\"" <> name <> "\"" <> marker)
      schemas = %{name => digest_schema}
      unsigned = m |> remove("signature") |> remove("signature-input")

      assert {:ok, signed} =
               RequestSeal.sign(
                 unsigned,
                 %{label: v["label"], signature_input: params, algorithm: v["algorithm"]},
                 signer(v),
                 field_schemas: schemas
               )

      v = %{v | "signature_input" => v["label"] <> "=" <> params}

      p =
        policy(v,
          field_schemas: schemas,
          content: %{kind: kind, section: section, algorithms: ["sha-512"]}
        )

      opts =
        if kind == :representation,
          do: [label: v["label"], representation: original.body],
          else: [label: v["label"]]

      assert RequestSeal.verify(signed, p, opts) ==
               {:ok,
                %{
                  expected(v)
                  | content: %{kind: kind, bytes: 18, checked: ["sha-512"], unsupported: 0}
                }}

      opposite = if section == :headers, do: :trailers, else: :headers

      error(
        RequestSeal.verify(signed, %{p | content: %{p.content | section: opposite}}, opts),
        :digest_not_covered,
        :content
      )

      if kind == :representation do
        error(RequestSeal.verify(signed, p, label: v["label"]), :body_unavailable, :content)
      end
    end

    assert {:ok, response} =
             Message.new(%{
               kind: :response,
               status: 503,
               fields: [occurrence("content-digest", field(original, "content-digest"))],
               trailers: :unavailable,
               body: original.body,
               related_request: original,
               transport: original.transport
             })

    for {m, marker} <- [{response, ";req"}, {original, ";bs"}] do
      # Real signatures authenticate only the related-request field or binary wrap.
      {case_vector, signed} = resign(m, vector("B.2.6"), ~s[("content-digest"#{marker})])

      assert RequestSeal.verify(signed, policy(case_vector), label: case_vector["label"]) ==
               {:ok, expected(case_vector)}

      error(
        RequestSeal.verify(signed, policy(case_vector, content: content()),
          label: case_vector["label"]
        ),
        :digest_not_covered,
        :content
      )
    end

    params =
      String.replace(parameters(v), ~s["content-digest"], ~s["content-digest";key="sha-512"])

    schemas = %{"content-digest" => digest_schema}

    assert {:ok, signed} =
             RequestSeal.sign(
               original |> remove("signature") |> remove("signature-input"),
               %{label: v["label"], signature_input: params, algorithm: v["algorithm"]},
               signer(v),
               field_schemas: schemas
             )

    v = %{v | "signature_input" => v["label"] <> "=" <> params}

    error(
      RequestSeal.verify(signed, policy(v, content: content(), field_schemas: schemas),
        label: v["label"]
      ),
      :digest_not_covered,
      :content
    )
  end

  test "all invalid signing options and closure exits produce safe bounded errors" do
    v = vector("B.2.6")
    m = message(v) |> remove("signature") |> remove("signature-input")
    spec = %{label: v["label"], signature_input: parameters(v), algorithm: v["algorithm"]}

    error(
      RequestSeal.sign(m, %{spec | signature_input: "bad"}, signer(v)),
      :invalid_signature_input,
      :fields
    )

    error(RequestSeal.sign(m, spec, signer(v), field_schemas: :bad), :invalid_options, :input)
    error(RequestSeal.sign(%{m | method: nil}, spec, signer(v)), :invalid_message, :input)
    error(RequestSeal.sign(m, spec, fn _, _ -> exit(:signer_canary) end), :signer_failed, :crypto)

    error(
      RequestSeal.verify(message(v), policy(v, key_resolver: fn _ -> exit(:key_canary) end),
        label: v["label"]
      ),
      :key_resolver_failed,
      :key
    )

    for bad <- [nil, %{}, [], %{__struct__: Policy}] do
      error(RequestSeal.verify(message(v), bad, label: v["label"]), :invalid_policy, :input)
    end

    {:error, a} = RequestSeal.verify(message(v), policy(v), [])
    {:error, b} = RequestSeal.verify(message(v), policy(v), [])
    assert a.correlation != b.correlation
  end

  test "real digest calls occur only after cryptography and full digest coverage" do
    owner = self()
    tracer = spawn(fn -> digest_trace(owner, 0) end)
    Code.ensure_loaded!(Digest)
    assert :erlang.trace_pattern({Digest, :check, 3}, true, [:local]) == 1
    assert :erlang.trace_pattern({Digest, :check_stream, 3}, true, [:local]) == 1
    :erlang.trace(self(), true, [:call, {:tracer, tracer}])

    try do
      v = vector("B.2.3")
      m = rewrite(message(v), "signature", v["label"] <> "=:AA==:")

      error(
        RequestSeal.verify(m, policy(v, content: content()), label: v["label"]),
        :invalid_signature,
        :crypto
      )

      assert digest_calls(tracer) == 0
      h = vector("B.2.5")

      error(
        RequestSeal.verify(message(h), policy(h, content: content()), label: h["label"]),
        :digest_not_covered,
        :content
      )

      assert digest_calls(tracer) == 0

      assert {:ok, result} =
               RequestSeal.verify(message(v), policy(v, content: content()), label: v["label"])

      assert result == %{
               expected(v)
               | content: %{kind: :content, bytes: 18, checked: ["sha-512"], unsupported: 0}
             }

      assert digest_calls(tracer) == 1
    after
      :erlang.trace(self(), false, [:call])
      :erlang.trace_pattern({Digest, :check, 3}, false, [:local])
      :erlang.trace_pattern({Digest, :check_stream, 3}, false, [:local])
      send(tracer, :stop)
    end
  end

  defp digest_trace(owner, count) do
    receive do
      {:trace, _, :call, {Digest, _, _}} ->
        digest_trace(owner, count + 1)

      :count ->
        send(owner, {:digest_calls, count})
        digest_trace(owner, count)

      :stop ->
        :ok
    end
  end

  defp digest_calls(tracer) do
    ref = :erlang.trace_delivered(self())
    assert_receive {:trace_delivered, _, ^ref}
    send(tracer, :count)
    assert_receive {:digest_calls, count}
    count
  end

  test "signing revalidates appended messages and rejects unmatched existing labels" do
    v = vector("B.2.6")
    spec = %{label: "another", signature_input: parameters(v), algorithm: v["algorithm"]}

    error(
      RequestSeal.sign(remove(message(v), "signature"), spec, signer(v)),
      :label_mismatch,
      :fields
    )

    unsigned = message(v) |> remove("signature") |> remove("signature-input")

    repeated = %{
      unsigned
      | fields: List.duplicate(occurrence("Date", field(unsigned, "date")), 1023)
    }

    assert Message.validate(repeated) == :ok

    error(
      RequestSeal.sign(repeated, %{spec | signature_input: "()"}, signer(v)),
      :invalid_message,
      :input
    )

    for opts <- [:wrong, %{}, [{:label, "another"}, :invalid]] do
      error(RequestSeal.verify(message(v), policy(v), opts), :invalid_options, :input)
      error(RequestSeal.sign(unsigned, spec, signer(v), opts), :invalid_options, :input)
    end

    error(
      RequestSeal.verify(message(v), policy(v), label: v["label"], representation: unsigned.body),
      :invalid_options,
      :input
    )

    error(
      RequestSeal.verify(message(v), policy(v), label: String.duplicate("a", 257)),
      :invalid_options,
      :input
    )

    wire = Enum.map_join(1..16, ", ", &"label#{&1}=()")
    sigs = Enum.map_join(1..16, ", ", &"label#{&1}=:AA==:")
    full = unsigned |> rewrite("signature-input", wire) |> rewrite("signature", sigs)
    error(RequestSeal.sign(full, spec, signer(v)), :limit, :input)

    malformed =
      rewrite(message(v), "signature-input", v["signature_input"] <> ", other=\"not a list\"")
      |> rewrite("signature", v["signature"] <> ", other=:AA==:")

    error(
      RequestSeal.verify(malformed, policy(v), label: v["label"]),
      :invalid_signature_input,
      :fields
    )

    error(
      RequestSeal.verify(
        message(v),
        policy(v,
          key_resolver: fn _ -> {:ok, %{algorithm: "unknown", key: public(v["key"])}} end
        ),
        label: v["label"]
      ),
      :key_resolver_failed,
      :key
    )

    h = vector("B.2.5")

    error(
      RequestSeal.verify(
        message(h),
        policy(h,
          key_resolver: fn _ -> {:ok, %{algorithm: "hmac-sha256", key: public("ed25519")}} end
        ),
        label: h["label"]
      ),
      :key_resolver_failed,
      :key
    )

    error(
      RequestSeal.verify(
        message(v),
        policy(v, key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public("p256")}} end),
        label: v["label"]
      ),
      :verifier_failed,
      :crypto
    )

    error(
      RequestSeal.verify(message(v), Map.put(policy(v), :unexpected, true), label: v["label"]),
      :invalid_policy,
      :input
    )

    for changes <- [
          %{freshness: %{clock: fn -> 0 end, max_age: nil, skew: 0}},
          %{content: %{content() | kind: :unknown}},
          %{field_schemas: %{"Content-Digest" => schema(:dictionary)}}
        ] do
      error(Policy.new(Map.merge(attrs(v), changes)), :invalid_policy, :input)
    end
  end

  test "representation and streamed options are mutually exclusive" do
    v = vector("B.2.3")

    m =
      rewrite(
        remove(message(v), "content-digest"),
        "repr-digest",
        field(message(v), "content-digest")
      )

    params = String.replace(parameters(v), "content-digest", "repr-digest")
    {v, m} = resign(m, v, params)
    {:ok, state} = Digest.init(:representation, ["sha-512"])
    {:ok, state} = Digest.update(state, m.body.bytes)
    p = policy(v, content: %{content() | kind: :representation})

    error(
      RequestSeal.verify(m, p, label: v["label"], representation: m.body, digest_state: state),
      :invalid_options,
      :input
    )
  end

  test "malformed and uncomputed digest data reject after actual cryptography" do
    v = vector("B.2.3")
    original = message(v)
    m = rewrite(original, "content-digest", "sha-512=token")
    {v, m} = resign(m, v, parameters(v))

    error(
      RequestSeal.verify(m, policy(v, content: content()), label: v["label"]),
      :digest_unsupported,
      :content
    )

    {:ok, state} = Digest.init(:content, ["sha-256"])
    {:ok, state} = Digest.update(state, original.body.bytes)

    error(
      RequestSeal.verify(original, policy(v, content: content()),
        label: v["label"],
        digest_state: state
      ),
      :digest_unsupported,
      :content
    )
  end

  test "aggregate field limits reject before the Structured Fields parser" do
    v = vector("B.2.6")

    padded =
      String.duplicate(" ", 65_536 - byte_size(v["signature_input"])) <> v["signature_input"]

    m = rewrite(message(v), "signature-input", padded)
    assert RequestSeal.verify(m, policy(v), label: v["label"]) == {:ok, expected(v)}
    m = %{m | fields: m.fields ++ [occurrence("Signature-Input", " ")]}
    error(RequestSeal.verify(m, policy(v), label: v["label"]), :limit, :input)
    v = vector("B.2.3")
    original = message(v)
    wire = field(original, "content-digest")

    m =
      rewrite(original, "content-digest", wire <> String.duplicate(" ", 65_536 - byte_size(wire)))

    m = %{m | fields: m.fields ++ [occurrence("Content-Digest", " ")]}
    {v, m} = resign(m, v, parameters(v))
    error(RequestSeal.verify(m, policy(v, content: content()), label: v["label"]), :limit, :input)
  end

  test "caller-selected signature ceilings apply to both dictionaries" do
    v = vector("B.2.6")

    m =
      rewrite(message(v), "signature-input", v["signature_input"] <> ", other=" <> parameters(v))

    m = rewrite(m, "signature", v["signature"] <> ", other=:AA==:")
    error(RequestSeal.verify(m, policy(v, max_signatures: 1), label: v["label"]), :limit, :input)

    assert RequestSeal.verify(m, policy(v, max_signatures: 2), label: v["label"]) ==
             {:ok, expected(v)}
  end

  defp vector(section), do: Enum.find(@vectors, &(&1["section"] == section))
  defp base(v), do: Enum.find(@bases, &(&1["section"] == v["section"]))
  defp parameters(v), do: v["signature_input"] |> String.split("=", parts: 2) |> List.last()

  defp signature(v),
    do:
      v["signature"]
      |> String.split("=:", parts: 2)
      |> List.last()
      |> String.trim_trailing(":")
      |> Base.decode64!()

  defp components(v) do
    {:ok, %Value{value: [p]}} = SF.parse(parameters(v), schema(:list))
    {:ok, wire} = SF.serialize(%Value{type: :list, value: [%{p | parameters: []}]}, schema(:list))
    wire
  end

  defp schema(type),
    do: %Schema{
      revision: :rfc8941,
      type: type,
      item_types: [:string],
      parameter_types: Schema.types(:rfc8941),
      inner_lists: true
    }

  defp attrs(v),
    do: %{
      algorithms: [v["algorithm"]],
      components: components(v),
      key_resolver: fn _ -> {:ok, %{algorithm: v["algorithm"], key: public(v["key"])}} end,
      freshness: :not_evaluated,
      content: :not_required,
      replay: :not_required
    }

  defp policy(v, changes \\ []) do
    {:ok, p} = Policy.new(Map.merge(attrs(v), Map.new(changes)))
    p
  end

  defp content, do: %{kind: :content, algorithms: ["sha-512"], section: :headers}

  defp public("hmac") do
    secret = File.read!(Path.join(@root, "crypto/hmac.txt")) |> String.trim() |> Base.decode64!()
    fn algorithm, bytes, sig -> Crypto.verify(algorithm, bytes, sig, {:hmac, secret}) end
  end

  defp public(key) do
    {:ok, key} =
      PublicKey.import(File.read!(Path.join(@root, "crypto/" <> key <> "_public.pem")), :pem)

    key
  end

  defp signer(v) do
    material = material(v["key"])
    fn alg, bytes -> Crypto.sign(alg, bytes, material) end
  end

  defp material("hmac"),
    do:
      {:hmac,
       File.read!(Path.join(@root, "crypto/hmac.txt")) |> String.trim() |> Base.decode64!()}

  defp material(key) do
    [entry] =
      :public_key.pem_decode(File.read!(Path.join(@root, "crypto/" <> key <> "_private.pem")))

    k = :public_key.pem_entry_decode(entry)

    case key do
      "rsa" -> {:rsa, k}
      "rsa_pss" -> {:rsa, elem(k, 0)}
      "p256" -> {:ec, "P-256", elem(k, 2)}
      "ed25519" -> {:ed25519, elem(k, 2)}
    end
  end

  defp expected(v) do
    {:ok, %Value{value: [input]}} = SF.parse(parameters(v), schema(:list))

    covered =
      Enum.map(input.value, fn item ->
        {:ok, wire} = SF.serialize(item, %{schema(:item) | inner_lists: false})
        wire
      end)

    params = Map.new(input.parameters, fn {name, {_, value}} -> {name, value} end)

    %{
      __struct__: RequestSeal.Verification,
      label: v["label"],
      profile: %{name: :rfc9421},
      signature: %{
        algorithm: v["algorithm"],
        covered: covered,
        parameters: params,
        keyid: params["keyid"],
        crypto: :valid
      },
      content: :not_required,
      freshness: :not_evaluated,
      replay: :not_required,
      principal: :unattributed,
      authorization: :not_evaluated
    }
  end

  defp body(bytes) do
    {:ok, body} = Body.new(%{state: :retained, bytes: bytes})
    body
  end

  defp unavailable do
    {:ok, b} = Body.new(%{state: :unavailable})
    b
  end

  defp from_public(p, bytes) do
    {:ok, transport} = TransportFacts.new(%{})

    attrs = %{
      kind: String.to_existing_atom(p["kind"]),
      fields:
        Enum.reject(p["fields"], fn [name, _] ->
          String.downcase(name) in ["signature", "signature-input"]
        end)
        |> Enum.map(fn [n, v] -> occurrence(n, v) end),
      body: body(bytes),
      transport: transport,
      trailers: :unavailable
    }

    attrs =
      if p["kind"] == "request",
        do:
          Map.merge(attrs, %{
            method: p["method"],
            raw_target: p["raw_target"],
            target_form: :origin,
            scheme: p["scheme"],
            authority: p["authority"]
          }),
        else:
          Map.merge(attrs, %{
            status: p["status"],
            related_request:
              if(p["related_request"],
                do: from_public(p["related_request"], ~s[{"hello": "world"}]),
                else: nil
              )
          })

    {:ok, m} = Message.new(attrs)
    m
  end

  defp message(v),
    do:
      from_public(
        base(v)["message"],
        if(v["section"] == "B.2.4", do: ~s[{"message": "good dog"}], else: ~s[{"hello": "world"}])
      )
      |> signed(v)

  defp signed(m, v),
    do: %{
      m
      | fields:
          m.fields ++
            [
              occurrence("Signature-Input", v["signature_input"]),
              occurrence("Signature", v["signature"])
            ]
    }

  defp occurrence(n, v) do
    {:ok, f} = FieldOccurrence.new(%{name: n, value: v, section: :headers, provenance: :caller})
    f
  end

  defp remove(m, name),
    do: %{m | fields: Enum.reject(m.fields, &(String.downcase(&1.name) == name))}

  defp rewrite(m, name, wire),
    do: %{remove(m, name) | fields: remove(m, name).fields ++ [occurrence(name, wire)]}

  defp field(m, name), do: Enum.find(m.fields, &(String.downcase(&1.name) == name)).value

  defp resign(m, v, params) do
    v = %{v | "signature_input" => v["label"] <> "=" <> params}

    {:ok, m} =
      RequestSeal.sign(
        m |> remove("signature") |> remove("signature-input"),
        %{label: v["label"], signature_input: params, algorithm: v["algorithm"]},
        signer(v)
      )

    {v, m}
  end

  defp proxy do
    c = Enum.find(@crypto, &(&1["section"] == "4.3"))
    params = c["base"] |> String.split("\"@signature-params\": ") |> List.last()

    v = %{
      "section" => "4.3",
      "label" => "proxy_sig",
      "key" => "rsa",
      "algorithm" => c["algorithm"],
      "signature_input" => "proxy_sig=" <> params,
      "signature" => "proxy_sig=:" <> c["signature"] <> ":"
    }

    p = base(vector("B.2.3"))["message"]

    p = %{
      p
      | "authority" => "origin.host.internal.example",
        "fields" =>
          Enum.map(p["fields"], fn [n, value] ->
            [n, if(n == "Date", do: "Tue, 20 Apr 2021 02:07:56 GMT", else: value)]
          end) ++ [["Forwarded", "for=192.0.2.123;host=example.com;proto=https"]]
    }

    {v, from_public(p, ~s[{"hello": "world"}]) |> signed(v)}
  end

  defp error(result, reason, layer, detail \\ nil) do
    assert {:error,
            %{
              __struct__: RequestSeal.Error,
              reason: ^reason,
              layer: ^layer,
              retryable: false,
              detail: ^detail,
              correlation: correlation
            } = e} = result

    assert Regex.match?(~r/\A[0-9a-f]{16}\z/, correlation)
    assert map_size(e) == 6
    refute match?({:ok, _}, result)

    for canary <- ["CANARY", "test-key", "b3k2pp5k7z", "private"] do
      refute inspect(e) =~ canary
    end
  end
end
