defmodule RequestSeal.QuorumTest do
  use ExUnit.Case, async: false
  import RequestSeal.MultiSignatureSupport
  alias RequestSeal.{Custody, KeyIdentity, PublicKey, Quorum}
  alias RequestSeal.Custody.Local

  test "the public quorum entry point requires the specified explicit options arity" do
    Code.ensure_loaded!(RequestSeal)
    assert function_exported?(RequestSeal, :verify_quorum, 3)
    refute function_exported?(RequestSeal, :verify_quorum, 2)
  end

  test "quorum rejects required replay in every slot before callbacks or claims" do
    alias RequestSeal.Replay.ETS
    pid = start_supervised!({ETS, max_entries: 16})
    owner = self()

    p =
      policy(
        key_resolver: fn request ->
          send(owner, :resolved)
          resolver(request)
        end,
        freshness: %{
          clock: fn ->
            send(owner, :clock_read)
            1_618_884_473
          end,
          max_age: 60,
          skew: 0,
          require_expires: false
        },
        replay: %{
          identifier: :nonce,
          namespace: "quorum-replay",
          commitment: fn facts ->
            send(owner, :committed)
            {:ok, facts.identifier}
          end,
          store: ETS.store(pid),
          timeout: 1000
        }
      )

    m = signed(["sig-b21"])

    for replay_slot <- [
          slot(:replay, policy: p, label: "sig-b21"),
          slot(:replay, policy: p, label: "sig-b21", required: false),
          slot(:replay, policy: p, label: "absent", required: false)
        ] do
      q = quorum([slot(:valid, label: "sig-b21"), replay_slot], mode: :any)
      error(verify_quorum(m, q), :invalid_policy, :input)
      # Direct structs must obey the same rule as constructed composite policies.
      direct = %{q | slots: Enum.map(q.slots, &Map.take(&1, [:id, :policy, :required, :label]))}
      error(verify_quorum(m, direct), :invalid_policy, :input)
      refute_received :resolved
      refute_received :clock_read
      refute_received :committed
      assert {:ok, 0} = ETS.sweep(pid, 1_618_885_000)
    end
  end

  test "quorum rejects representation digest policies in every slot before callbacks" do
    owner = self()
    base = quorum([slot(:valid, label: "sig-b23")], mode: :any)

    for section <- [:headers, :trailers],
        algorithms <- [["sha-256"], ["sha-512"], ["sha-256", "sha-512"]],
        {required, label} <- [{true, "sig-b23"}, {false, "sig-b23"}, {false, "absent"}] do
      p =
        policy(
          content: %{kind: :representation, algorithms: algorithms, section: section},
          key_resolver: fn request ->
            send(owner, :resolved)
            resolver(request)
          end
        )

      assert RequestSeal.Policy.valid?(p)
      unsupported = slot(:representation, policy: p, required: required, label: label)

      for slots <- [[unsupported | base.slots], base.slots ++ [unsupported]] do
        direct = %{base | slots: slots}
        error(Quorum.new(Map.from_struct(direct)), :invalid_quorum, :input)
        error(verify_quorum(signed(["sig-b23"]), direct), :invalid_quorum, :input)
        refute_received :resolved
      end
    end
  end

  test "quorum supports retained content digests and rejects caller-fed digest state" do
    alias RequestSeal.{Body, Digest}
    message = signed(["sig-b23"])
    content = %{kind: :content, algorithms: ["sha-512"], section: :headers}
    p = policy(content: content)
    q = quorum([slot(:content, policy: p, label: "sig-b23")], invalid: :reject)

    assert {:ok, result} = verify_quorum(message, q)

    assert result.signatures["sig-b23"].content == %{
             kind: :content,
             bytes: 18,
             checked: ["sha-512"],
             unsupported: 0
           }

    {:ok, state} = Digest.init(:content, ["sha-512"])
    {:ok, state} = Digest.update(state, message.body.bytes)
    {:ok, streaming} = Body.new(%{state: :streaming, source: self()})
    streamed_message = %{message | body: streaming}

    # The published signature verifies with real caller-fed state on the
    # single-label API; that input cannot enter quorum verification.
    assert {:ok, _} =
             RequestSeal.verify(streamed_message, p, label: "sig-b23", digest_state: state)

    assert %{detail: :body_unavailable} =
             error(verify_quorum(streamed_message, q), :nonqualifying_signature)

    for opts <- [[digest_state: state], [representation: message.body]] do
      error(verify_quorum(streamed_message, q, opts), :invalid_options, :input)
    end

    for unsupported <- [state, Map.put(content, :digest_state, state)],
        {required, label} <- [{true, "sig-b23"}, {false, "sig-b23"}, {false, "absent"}] do
      direct = %{
        q
        | slots: [
            slot(:state, policy: %{p | content: unsupported}, required: required, label: label)
          ]
      }

      error(Quorum.new(Map.from_struct(direct)), :invalid_quorum, :input)
      error(verify_quorum(message, direct), :invalid_quorum, :input)
    end

    {:ok, altered} = Body.new(%{state: :retained, bytes: ~s[{"hello": "World"}]})

    assert %{detail: :digest_mismatch} =
             error(verify_quorum(%{message | body: altered}, q), :nonqualifying_signature)
  end

  test "published labels count three keys, two principals, and disjoint roles" do
    slots = [
      slot(:rsa, label: "sig-b21", principal: "asymmetric", role: :agent),
      slot(:hmac, label: "sig-b25", principal: "symmetric", role: :consumer),
      slot(:ed, label: "sig-b26", principal: "asymmetric", role: :agent)
    ]

    for {unit, n} <- [
          {:key, 3},
          {:principal, 2},
          {{:role, shared_principal: false}, 2},
          {{:role, shared_principal: true}, 2}
        ] do
      assert {:ok, r} =
               verify_quorum(
                 signed(),
                 quorum(slots, mode: {:threshold, n}, unit: unit)
               )

      assert r.count == n
      assert r.principal == :unattributed
      assert r.authorization == :not_evaluated

      error(
        verify_quorum(signed(), quorum(slots, mode: {:threshold, n + 1}, unit: unit)),
        :quorum_not_met
      )
    end

    q = quorum([slot(:rsa), slot(:ed)], mode: {:threshold, 4})
    error(verify_quorum(signed(), q), :quorum_not_met)

    roles = [
      slot(:agent, label: "sig-b21", principal: "one", role: :agent),
      slot(:consumer, label: "sig-b26", principal: "one", role: :consumer)
    ]

    assert {:ok, %{count: 1}} =
             verify_quorum(
               signed(),
               quorum(roles, mode: :any, unit: {:role, shared_principal: false})
             )

    error(
      verify_quorum(
        signed(),
        quorum(roles, mode: {:threshold, 2}, unit: {:role, shared_principal: false})
      ),
      :quorum_not_met
    )

    assert {:ok, %{count: 2}} =
             verify_quorum(
               signed(),
               quorum(roles, mode: {:threshold, 2}, unit: {:role, shared_principal: true})
             )
  end

  test "five published signatures yield three matched keys and retain independent coverage" do
    slots = [
      slot(:rsa, label: "sig-b21"),
      slot(:hmac, label: "sig-b25"),
      slot(:ed, label: "sig-b26")
    ]

    assert {:ok, r} = verify_quorum(signed(), quorum(slots, mode: {:threshold, 3}))
    assert r.count == 3
    assert map_size(r.signatures) == 3
    assert Enum.map(r.qualifying, & &1.label) == ~w(sig-b21 sig-b25 sig-b26)
    assert r.signatures["sig-b21"].signature.covered == []

    for label <- ~w(sig-b21 sig-b22 sig-b23 sig-b25 sig-b26) do
      assert {:ok, _} = RequestSeal.verify(signed(), policy(), label: label)
    end

    assert {:ok, independent} = RequestSeal.verify(signed(), policy(), label: "sig-b23")
    assert ~s["content-digest"] in independent.signature.covered
    error(verify_quorum(signed(), quorum(slots, mode: {:threshold, 4})), :quorum_not_met)

    error(
      verify_quorum(signed(), quorum([slot(:signer)], mode: {:threshold, 3})),
      :quorum_not_met
    )

    [hash, name] =
      File.read!(Path.join(__DIR__, "fixtures/multi_signature/SHA256SUMS"))
      |> String.trim()
      |> String.split("  ")

    assert hash ==
             Base.encode16(
               :crypto.hash(
                 :sha256,
                 File.read!(Path.join(__DIR__, "fixtures/multi_signature/" <> name))
               ),
               case: :lower
             )
  end

  test "raw RSA and PSS PEM aliases deduplicate by same? rather than struct equality" do
    {:rsa, n, e} = public("rsa_pss").material
    {:ok, raw} = PublicKey.import({:rsa, n, e}, :raw)
    p = policy(key_resolver: fn _ -> {:ok, %{algorithm: "rsa-pss-sha512", key: raw}} end)
    {:ok, pss} = PublicKey.import({:rsa_pss, n, e}, :raw)
    pss_policy = policy(key_resolver: fn _ -> {:ok, %{algorithm: "rsa-pss-sha512", key: pss}} end)

    slots = [
      slot(:pem, label: "sig-b21"),
      slot(:raw, label: "sig-b22", policy: p),
      slot(:pss, label: "sig-b23", policy: pss_policy)
    ]

    error(verify_quorum(signed(), quorum(slots)), :quorum_not_met)
    optional = Enum.map(slots, &%{&1 | required: false})

    assert {:ok, %{count: 1, satisfied: [:pem]}} =
             verify_quorum(signed(), quorum(optional, mode: :any))

    error(verify_quorum(signed(), quorum(optional, mode: {:threshold, 2})), :quorum_not_met)
  end

  test "real HMAC custody imports use trusted equivalence and reject unknown identity" do
    {:hmac, secret} = material("hmac")
    first = hmac("trusted-equivalence")

    for {equivalence, count} <- [
          {"trusted-equivalence", 1},
          {"distinct-equivalence", 2},
          {nil, nil}
        ] do
      {:ok, second} =
        Local.import(
          {:jws, "HS256"},
          %{"kty" => "oct", "k" => Base.url_encode64(secret, padding: false)},
          :jwk,
          if(equivalence, do: [equivalence: equivalence], else: [])
        )

      {:ok, second_id} = Custody.identity(second)
      {:ok, first_id} = Custody.identity(first)
      assert KeyIdentity.same?(first_id, second_id) == (count == 1)
      # A JWS HS256 handle verifies the same HMAC primitive under its own bound algorithm.
      p =
        policy(
          key_resolver: fn _ ->
            {:ok,
             %{
               algorithm: "hmac-sha256",
               identity: second_id,
               key: fn _, b, s -> Custody.verify(second, b, s) end
             }}
          end
        )

      m =
        signed(["sig-b25"])
        |> append(
          Map.new(vector("sig-b25"), fn {k, v} ->
            {k, if(is_binary(v), do: String.replace(v, "sig-b25", "alias"), else: v)}
          end)
        )

      q =
        quorum([
          slot(:first, label: "sig-b25", policy: policy(key_resolver: handle_resolver(first))),
          slot(:import, label: "alias", policy: p)
        ])

      case count do
        1 ->
          error(verify_quorum(m, q), :quorum_not_met)
          optional = %{q | mode: :any, slots: Enum.map(q.slots, &%{&1 | required: false})}
          assert {:ok, %{count: 1}} = verify_quorum(m, optional)

        2 ->
          assert {:ok, %{count: 2}} = verify_quorum(m, q)

        nil ->
          error(verify_quorum(m, q), :ambiguous_key_identity)
      end
    end
  end

  test "coverage is independent for every signer and never pooled" do
    q = quorum([slot(:complete, policy: policy(components: ~s[("@method" "content-digest")]))])
    error(verify_quorum(signed(~w(sig-b21 sig-b22)), q), :quorum_not_met)

    assert {:ok, %{satisfied: [:complete], signatures: %{"sig-b23" => _}}} =
             verify_quorum(signed(~w(sig-b21 sig-b22 sig-b23)), q)
  end

  test "published pre-proxy and forwarded signatures preserve mixed validity facts" do
    forwarded = message(corpus()["proxy"])

    original =
      rewrite(forwarded, fn
        "host", _ -> "example.com"
        "date", _ -> "Tue, 20 Apr 2021 02:07:55 GMT"
        _, v -> v
      end)
      |> Map.put(:authority, "example.com")

    assert {:ok, _} = RequestSeal.verify(original, policy(), label: "sig1")
    error(RequestSeal.verify(forwarded, policy(), label: "sig1"), :invalid_signature, :crypto)
    assert {:ok, _} = RequestSeal.verify(forwarded, policy(), label: "proxy_sig")
    slots = [slot(:client, label: "sig1", required: false), slot(:proxy, label: "proxy_sig")]
    assert {:ok, r} = verify_quorum(forwarded, quorum(slots, mode: :any))

    assert r.nonqualifying == [
             %{label: "sig1", slot: :client, reason: :invalid_signature, layer: :crypto}
           ]

    assert r.satisfied == [:proxy]

    error(
      verify_quorum(forwarded, quorum([%{hd(slots) | required: true}, List.last(slots)])),
      :quorum_not_met
    )

    e =
      error(
        verify_quorum(forwarded, quorum(slots, mode: :any, invalid: :reject)),
        :nonqualifying_signature
      )

    assert e.detail == :invalid_signature

    unknown =
      policy(
        key_resolver: fn %{keyid: id} = meta ->
          if id == "test-key-ed25519", do: :error, else: resolver(meta)
        end
      )

    assert {:ok, r} =
             verify_quorum(
               signed(),
               quorum(
                 [
                   slot(:rsa, label: "sig-b21"),
                   slot(:ed, label: "sig-b26", policy: unknown, required: false)
                 ],
                 mode: :any
               )
             )

    assert Enum.any?(r.nonqualifying, &(&1.reason == :unknown_key))
  end

  test "optional valid and invalid labels cannot alter selected signers or fill required slots" do
    slots = [slot(:rsa, label: "sig-b23"), slot(:hmac, label: "sig-b25")]

    for mode <- [:any, {:threshold, 2}] do
      q = quorum(slots, mode: mode)
      assert {:ok, r} = verify_quorum(signed(~w(sig-b23 sig-b25)), q)

      for labels <- [
            ~w(sig-b26 sig-b23 sig-b25),
            ~w(sig-b25 sig-b23 sig-b26),
            ~w(sig-b21 sig-b23 sig-b25)
          ] do
        m =
          signed(labels)
          |> rewrite(fn
            "signature", "sig-b21=:" <> rest -> "sig-b21=:" <> flip(rest)
            _, v -> v
          end)

        assert {:ok, changed} = verify_quorum(m, q)

        assert Map.take(changed, [:satisfied, :count, :qualifying]) ==
                 Map.take(r, [:satisfied, :count, :qualifying])
      end
    end

    error(verify_quorum(signed(["sig-b26"]), quorum(slots)), :quorum_not_met)

    error(
      verify_quorum(signed(), quorum(slots, mode: :any, unexpected: :reject)),
      :unexpected_signature
    )
  end

  test "duplicate labels within and across occurrences reject both verification entry points" do
    m = signed(["sig-b26"])

    for name <- ["signature-input", "signature"], across <- [true, false] do
      f = Enum.find(m.fields, &(String.downcase(&1.name) == name))

      duplicate =
        if across,
          do: %{m | fields: m.fields ++ [f]},
          else: rewrite(m, fn n, v -> if n == name, do: v <> ", " <> v, else: v end)

      error(RequestSeal.verify(duplicate, policy(), label: "sig-b26"), :duplicate_label, :fields)
      error(verify_quorum(duplicate, quorum([slot(:ed)])), :duplicate_label, :fields)
    end
  end

  test "nested binding uses the qualifying actual label and same-parameter requires equality" do
    m =
      local_sign(
        signed(["sig-b26"]),
        "outer",
        ~s[("signature-input";key="sig-b26" "signature";key="sig-b26" "@method")],
        "rsa_pss",
        "rsa-pss-sha512"
      )

    slots = [
      slot(:inner, policy: policy(algorithms: ["ed25519"], components: ~s[("date")])),
      slot(:outer, label: "outer")
    ]

    binding = {:nested, outer: :outer, inner: :inner}
    assert {:ok, r} = verify_quorum(m, quorum(slots, bindings: [binding]))
    assert r.bindings == [{binding, :satisfied}]
    # A label is unsigned: retain the old public dictionary member while the
    # configured inner slot now claims the independently relabeled signature.
    renamed =
      append(
        signed(["sig-b26"]),
        Map.new(vector("sig-b26"), fn {k, v} ->
          {k, if(is_binary(v), do: String.replace(v, "sig-b26", "renamed"), else: v)}
        end)
      )
      |> local_sign(
        "outer",
        ~s[("signature-input";key="sig-b26" "signature";key="sig-b26" "@method")],
        "rsa_pss",
        "rsa-pss-sha512"
      )

    relabeled_slots = [slot(:inner, label: "renamed"), slot(:outer, label: "outer")]

    error(
      verify_quorum(renamed, quorum(relabeled_slots, bindings: [binding])),
      :binding_unsatisfied
    )

    nonces =
      unsigned()
      |> local_sign("one", ~s[("@method");nonce="one"])
      |> local_sign("two", ~s[("@method");nonce="two"], "rsa_pss", "rsa-pss-sha512")

    q =
      quorum([slot(:one, label: "one"), slot(:two, label: "two")],
        bindings: [{:same_parameter, "nonce", [:one, :two]}]
      )

    error(verify_quorum(nonces, q), :binding_unsatisfied)

    equal =
      unsigned()
      |> local_sign("one", ~s[("@method");nonce="same"])
      |> local_sign("two", ~s[("@method");nonce="same"], "rsa_pss", "rsa-pss-sha512")

    assert {:ok, _} = verify_quorum(equal, q)
  end

  test "published response linkage verifies both responses and the signed related request" do
    for p <- corpus()["linkage"] do
      m = message(p)
      assert {:ok, _} = verify_quorum(m, quorum([slot(:response, label: "reqres")]))

      error(
        verify_quorum(
          %{m | related_request: nil},
          quorum([slot(:response, label: "reqres")])
        ),
        :quorum_not_met
      )
    end

    m = message(Enum.at(corpus()["linkage"], 1))
    assert {:ok, _} = RequestSeal.verify(m.related_request, policy(), label: "sig1")
    p = policy(components: ~s[("signature-input";req;key="sig1")])
    q = quorum([slot(:response, policy: p)])
    error(verify_quorum(m, q), :quorum_not_met)

    locally_signed =
      local_sign(strip(m), "linked", ~s[("signature-input";req;key="sig1" "@status")])

    assert {:ok, _} = verify_quorum(locally_signed, q)
  end

  test "construction and encounter limits reject before callbacks and results redact bindings" do
    s = slot(:one)

    for attrs <- [
          %{
            slots:
              Enum.map(
                [:a, :b, :c, :d, :e, :f, :g, :h, :i, :j, :k, :l, :m, :n, :o, :p, :q],
                &slot/1
              )
          },
          %{slots: [s, s]},
          %{mode: {:threshold, 65}},
          %{max_signatures: 2, mode: {:threshold, 3}},
          %{unit: :principal},
          %{unit: {:role, shared_principal: false}},
          %{unit: :label},
          %{bindings: List.duplicate({:same_parameter, "nonce", [:one]}, 65)},
          %{bindings: [{:nested, outer: :one, inner: :one}]},
          %{bindings: [{:nested, outer: :one, inner: :missing}]}
        ] do
      error(
        Quorum.new(
          Map.merge(
            %{mode: :all, unit: :key, slots: [s], unexpected: :ignore, invalid: :ignore},
            attrs
          )
        ),
        :invalid_quorum,
        :input
      )
    end

    labels =
      for i <- 1..17,
          do:
            Map.new(vector("sig-b21"), fn {k, v} ->
              {k, if(is_binary(v), do: String.replace(v, "sig-b21", "label#{i}"), else: v)}
            end)

    m = Enum.reduce(labels, unsigned(), &append(&2, &1))
    error(verify_quorum(m, quorum([s])), :limit, :input)

    assert {:ok, r} =
             verify_quorum(
               signed(),
               quorum([slot(:one, principal: "sensitive-principal")], mode: :any)
             )

    refute inspect(r) =~ "sensitive-principal"
    refute inspect(r) =~ "sig-b"
    refute inspect(r) =~ "test-key"
    refute inspect(r) =~ "KeyIdentity"
    assert r.replay == :not_required
    assert r.negotiation == :not_requested
  end

  test "binding count and malformed options reject before the instrumented real resolver" do
    ids = [:a, :b, :c, :d, :e, :f, :g, :h, :i, :j, :k, :l, :m, :n, :o, :p]

    bindings =
      for(outer <- ids, inner <- ids, outer != inner, do: {:nested, outer: outer, inner: inner})
      |> Enum.take(65)

    error(
      Quorum.new(%{
        mode: :all,
        unit: :key,
        slots: Enum.map(ids, &slot/1),
        unexpected: :ignore,
        invalid: :ignore,
        bindings: bindings
      }),
      :invalid_quorum,
      :input
    )

    owner = self()

    p =
      policy(
        key_resolver: fn meta ->
          send(owner, :resolved_real_key)
          resolver(meta)
        end
      )

    q = quorum([slot(:ed, policy: p)])

    for bad <- [%{q | mode: :labels}, %{q | max_signatures: 65}, %{q | unit: :labels}] do
      error(verify_quorum(signed(["sig-b26"]), bad), :invalid_quorum, :input)
      refute_received :resolved_real_key
    end

    for opts <- [
          [label: "sig-b26"],
          [accept_signature: [], accept_signature: []],
          nil,
          [{:accept_signature, []} | :bad]
        ] do
      error(verify_quorum(signed(["sig-b26"]), q, opts), :invalid_options, :input)
      refute_received :resolved_real_key
    end

    assert {:ok, _} = verify_quorum(signed(["sig-b26"]), q)
    assert_received :resolved_real_key
  end

  test "public supplied identity must agree and invalid optional identities stay bounded" do
    k = public("ed25519")
    id = %KeyIdentity{kind: :public, value: k.material}

    for identity <- [
          id,
          %KeyIdentity{kind: :public, value: public("rsa").material},
          "sensitive-identity",
          nil,
          false,
          %KeyIdentity{kind: :unknown, value: "invalid"}
        ] do
      p =
        policy(
          key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: k, identity: identity}} end
        )

      if identity == id do
        assert {:ok, _} = RequestSeal.verify(signed(["sig-b26"]), p, label: "sig-b26")
      else
        error(
          RequestSeal.verify(signed(["sig-b26"]), p, label: "sig-b26"),
          :key_resolver_failed,
          :key
        )
      end
    end

    verifier = fn a, b, s -> RequestSeal.Crypto.verify(a, b, s, k) end
    p = policy(key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: verifier}} end)

    error(
      verify_quorum(signed(["sig-b26"]), quorum([slot(:ed, policy: p)])),
      :ambiguous_key_identity
    )

    assert {:ok, %{count: 1}} =
             verify_quorum(
               signed(["sig-b26"]),
               quorum([slot(:ed, policy: p, principal: "bound")], unit: :principal)
             )
  end

  test "tag selectors restrict eligibility and ignored labels never replace required slots" do
    q = quorum([slot(:tagged, tag: "header-example"), slot(:required, label: "absent")])
    error(verify_quorum(signed(), q), :quorum_not_met)
    error(verify_quorum(signed(), %{q | mode: :any}), :quorum_not_met)
    q = %{q | mode: :any, slots: [hd(q.slots), %{List.last(q.slots) | required: false}]}
    assert {:ok, r} = verify_quorum(signed(), q)
    assert r.satisfied == [:tagged]
    assert [%{label: "sig-b22"}] = r.qualifying
  end

  test "ordered slot attempts parse both dictionaries once and reuse each schema-compatible base" do
    bad_key = policy(key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public("rsa")}} end)
    q = quorum([slot(:wrong, policy: bad_key, required: false), slot(:right)], mode: :any)
    owner = self()
    tracer = spawn_link(fn -> trace_counts(owner, %{}) end)

    patterns = [
      {RequestSeal.StructuredFields, :parse_field, 5},
      {RequestSeal.SignatureBase, :build, 3},
      {RequestSeal.Authentication, :verify_label, 7}
    ]

    Enum.each(patterns, fn {module, _, _} = pattern ->
      Code.ensure_loaded!(module)
      assert :erlang.trace_pattern(pattern, true, []) == 1
    end)

    :erlang.trace(self(), true, [:call, {:tracer, tracer}])

    try do
      assert {:ok, r} = verify_quorum(signed(["sig-b26"]), q)
      assert r.satisfied == [:right]
      ref = :erlang.trace_delivered(self())
      assert_receive {:trace_delivered, _, ^ref}
      send(tracer, {:counts, ref})
      assert_receive {:counts, ^ref, counts}
      assert counts == %{parse_field: 2, build: 1, verify_label: 2}
    after
      :erlang.trace(self(), false, [:call])
      Enum.each(patterns, &:erlang.trace_pattern(&1, false, []))
      send(tracer, :stop)
    end
  end

  test "first successful configured slot claims a label after earlier policy rejection" do
    q =
      quorum(
        [
          slot(:wrong, policy: policy(components: ~s[("@status")]), required: false),
          slot(:right)
        ],
        mode: :any
      )

    assert {:ok, r} = verify_quorum(signed(["sig-b26"]), q)
    assert r.satisfied == [:right]
    assert r.qualifying == [%{label: "sig-b26", slot: :right, principal: nil, role: nil}]
    assert [%{slot: :wrong, reason: :missing_required_component}] = r.nonqualifying
  end

  test "F1 all rejects zero required slots for invalid and unexpected signatures" do
    optional = slot(:a, label: "sig-b26", required: false)
    attrs = %{mode: :all, unit: :key, slots: [optional], unexpected: :ignore, invalid: :ignore}
    error(Quorum.new(attrs), :invalid_quorum, :input)
    q = struct(Quorum, attrs)

    tampered =
      rewrite(signed(["sig-b26"]), fn
        "signature", "sig-b26=:" <> rest -> "sig-b26=:" <> flip(rest)
        _, v -> v
      end)

    for m <- [tampered, signed(["sig-b21"])] do
      error(verify_quorum(m, q), :invalid_quorum, :input)
    end

    for mode <- [:any, {:threshold, 1}] do
      q = quorum([optional], mode: mode)

      for m <- [tampered, signed(["sig-b21"])] do
        error(verify_quorum(m, q), :quorum_not_met)
      end

      assert {:ok, %{count: 1}} = verify_quorum(signed(["sig-b26"]), q)
    end
  end

  for kind <- [:tampered, :unexpected] do
    @kind kind
    test "F1 direct all quorum rejects optional-only wire #{kind}" do
      q = %Quorum{
        mode: :all,
        unit: :key,
        slots: [slot(:a, label: "sig-b26", required: false)],
        unexpected: :ignore,
        invalid: :ignore
      }

      m =
        if @kind == :unexpected,
          do: signed(["sig-b21"]),
          else:
            rewrite(signed(["sig-b26"]), fn
              "signature", "sig-b26=:" <> rest -> "sig-b26=:" <> flip(rest)
              _, v -> v
            end)

      error(verify_quorum(m, q), :invalid_quorum, :input)
    end
  end

  test "F2 threshold cannot substitute an optional signature for a required slot" do
    q =
      quorum([slot(:must, label: "sig-b21"), slot(:opt, label: "sig-b26", required: false)],
        mode: {:threshold, 1}
      )

    error(verify_quorum(signed(["sig-b26"]), q), :quorum_not_met)
  end

  test "F2 every mode enforces required slots even when an optional signer qualifies" do
    slots = [slot(:must, label: "sig-b21"), slot(:opt, label: "sig-b26", required: false)]

    for mode <- [:all, :any, {:threshold, 1}] do
      q = quorum(slots, mode: mode)
      error(verify_quorum(signed(["sig-b26"]), q), :quorum_not_met)
      assert {:ok, %{satisfied: [:must, :opt]}} = verify_quorum(signed(["sig-b21", "sig-b26"]), q)
    end
  end

  for selector <- [:label, :tag],
      unit <- [
        :key,
        :principal,
        {:role, [shared_principal: false]},
        {:role, [shared_principal: true]}
      ],
      mode <- [:all, {:threshold, 2}] do
    @selector selector
    @unit unit
    @mode mode
    test "F3 one key cannot fill two slots #{inspect({selector, unit, mode})}" do
      m =
        unsigned()
        |> local_sign("a1", ~s[("@method");tag="one"])
        |> local_sign("a2", ~s[("@method");tag="two"])

      selectors =
        if @selector == :label,
          do: [[label: "a1"], [label: "a2"]],
          else: [[tag: "one"], [tag: "two"]]

      slots = [
        slot(:a, hd(selectors) ++ [principal: "pa", role: :agent]),
        slot(:b, List.last(selectors) ++ [principal: "pb", role: :consumer])
      ]

      error(verify_quorum(m, quorum(slots, unit: @unit, mode: @mode)), :quorum_not_met)
    end
  end

  test "F3 aliases and two keyids cannot fill distinct principals or roles" do
    p = policy(key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public("ed25519")}} end)

    m =
      unsigned()
      |> local_sign("a1", ~s[("@method");keyid="first"])
      |> local_sign("a2", ~s[("@method");keyid="alias"])

    for unit <- [:key, :principal, {:role, [shared_principal: true]}] do
      slots = [
        slot(:a, label: "a1", policy: p, principal: "pa", role: :agent),
        slot(:b, label: "a2", policy: p, principal: "pb", role: :consumer)
      ]

      error(verify_quorum(m, quorum(slots, unit: unit, mode: {:threshold, 2})), :quorum_not_met)
    end
  end

  test "F3 identity exclusivity guard rejects one key counted as two principals" do
    m = unsigned() |> local_sign("a1", ~s[("@method")]) |> local_sign("a2", ~s[("@method")])

    q =
      quorum([slot(:a, label: "a1", principal: "pa"), slot(:b, label: "a2", principal: "pb")],
        unit: :principal,
        mode: {:threshold, 2}
      )

    error(verify_quorum(m, q), :quorum_not_met)
  end

  test "F4 matching assigns two distinct keys across overlapping slots" do
    m = signed(["sig-b21", "sig-b26"])

    for labels <- [["sig-b21", "sig-b26"], ["sig-b26", "sig-b21"]] do
      assert {:ok, %{count: 2, satisfied: [:a, :b]}} =
               verify_quorum(signed(labels), quorum([slot(:a), slot(:b)]))
    end

    # The RSA key must move from the flexible slot to the RSA-only slot.
    slots = [slot(:flexible), slot(:rsa, label: "sig-b21")]
    assert {:ok, r} = verify_quorum(m, quorum(slots))

    assert Enum.map(r.qualifying, &{&1.slot, &1.label}) == [
             {:flexible, "sig-b26"},
             {:rsa, "sig-b21"}
           ]

    # An earlier optional slot cannot consume the only key for a required slot.
    assert {:ok, %{satisfied: [:required]}} =
             verify_quorum(
               signed(["sig-b26"]),
               quorum([slot(:optional, required: false), slot(:required)])
             )
  end

  test "C4 optional unknown key identities are ignored and required ambiguity rejects" do
    p = policy(key_resolver: handle_resolver(hmac(nil)))

    for mode <- [:all, {:threshold, 1}, :any], invalid <- [:ignore, :reject] do
      q =
        quorum(
          [
            slot(:ed, label: "sig-b26"),
            slot(:optional, label: "sig-b25", policy: p, required: false)
          ],
          mode: mode,
          invalid: invalid
        )

      assert {:ok, base} = verify_quorum(signed(["sig-b26"]), q)
      assert {:ok, extra} = verify_quorum(signed(["sig-b26", "sig-b25"]), q)

      assert Map.take(extra, [:count, :satisfied, :qualifying]) ==
               Map.take(base, [:count, :satisfied, :qualifying])

      error(
        verify_quorum(
          signed(["sig-b26", "sig-b25"]),
          quorum([slot(:ed, label: "sig-b26"), slot(:required, label: "sig-b25", policy: p)],
            mode: mode,
            invalid: invalid
          )
        ),
        :ambiguous_key_identity
      )
    end

    # A known alternative satisfies a required slot even when an unknown key also qualifies.
    assert {:ok, %{count: 1}} =
             verify_quorum(
               signed(["sig-b25", "sig-b26"]),
               quorum([
                 slot(:required,
                   policy:
                     policy(
                       key_resolver: fn %{keyid: id} = meta ->
                         if id == "test-shared-secret",
                           do: handle_resolver(hmac(nil)).(meta),
                           else: resolver(meta)
                       end
                     )
                 )
               ])
             )
  end

  test "K3a nested binding requires both inner dictionary members" do
    slots = [slot(:inner, label: "sig-b26"), slot(:outer, label: "outer")]
    binding = {:nested, outer: :outer, inner: :inner}

    for coverage <- [~s[("signature-input";key="sig-b26")], ~s[("signature";key="sig-b26")]] do
      m = local_sign(signed(["sig-b26"]), "outer", coverage, "rsa_pss", "rsa-pss-sha512")
      error(verify_quorum(m, quorum(slots, bindings: [binding])), :binding_unsatisfied)
    end

    m =
      local_sign(
        signed(["sig-b26"]),
        "outer",
        ~s[("signature-input";key="sig-b26" "signature";key="sig-b26")],
        "rsa_pss",
        "rsa-pss-sha512"
      )

    assert {:ok, %{bindings: [{^binding, :satisfied}]}} =
             verify_quorum(m, quorum(slots, bindings: [binding]))
  end

  test "A2 one label occupies only one slot across identity observations" do
    m = signed(["sig-b25"])

    for {unit, mode} <- [
          {:key, :all},
          {:key, {:threshold, 2}},
          {:principal, {:threshold, 2}},
          {{:role, shared_principal: false}, {:threshold, 2}}
        ] do
      slots =
        for {id, tag, p, role} <- [{:x, "A", "pa", :agent}, {:y, "B", "pb", :consumer}],
            do:
              slot(id,
                policy: policy(key_resolver: handle_resolver(hmac(tag))),
                principal: p,
                role: role
              )

      error(verify_quorum(m, quorum(slots, unit: unit, mode: mode)), :quorum_not_met)
    end

    aliases =
      append(
        m,
        Map.new(vector("sig-b25"), fn {k, v} ->
          {k, if(is_binary(v), do: String.replace(v, "sig-b25", "alias"), else: v)}
        end)
      )

    p = policy(key_resolver: handle_resolver(hmac("A")))

    error(
      verify_quorum(
        aliases,
        quorum([slot(:x, label: "sig-b25", policy: p), slot(:y, label: "alias", policy: p)])
      ),
      :quorum_not_met
    )

    assert {:ok, %{count: 2}} =
             verify_quorum(signed(["sig-b25", "sig-b26"]), quorum([slot(:x), slot(:y)]))
  end

  test "B1 public and verify-function observations share one class" do
    m = local_sign(unsigned(), "a1", ~s[("@method")])
    key = public("ed25519")
    verifier = fn a, b, s -> RequestSeal.Crypto.verify(a, b, s, key) end

    for identity <- [:omitted, %KeyIdentity{kind: :symmetric, value: "ed-alias"}] do
      p =
        policy(
          key_resolver: fn _ ->
            result = %{algorithm: "ed25519", key: verifier}

            {:ok,
             if(identity == :omitted, do: result, else: Map.put(result, :identity, identity))}
          end
        )

      slots = [slot(:x, principal: "pa"), slot(:y, policy: p, principal: "pb")]

      error(
        verify_quorum(m, quorum(slots, unit: :principal, mode: {:threshold, 2})),
        :quorum_not_met
      )

      error(verify_quorum(m, quorum(slots)), :quorum_not_met)
    end

    aliases = local_sign(m, "alias", ~s[("@method")])

    supplied =
      policy(
        key_resolver: fn _ ->
          {:ok,
           %{
             algorithm: "ed25519",
             key: verifier,
             identity: %KeyIdentity{kind: :public, value: key.material}
           }}
        end
      )

    error(
      verify_quorum(
        aliases,
        quorum([slot(:x, label: "a1"), slot(:y, label: "alias", policy: supplied)])
      ),
      :quorum_not_met
    )

    unknown = policy(key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: verifier}} end)
    error(verify_quorum(m, quorum([slot(:y, policy: unknown)])), :ambiguous_key_identity)
  end

  test "A6 unknown observations join the shared POOL class transitively" do
    unknown = policy(key_resolver: handle_resolver(hmac(nil)))
    known = policy(key_resolver: handle_resolver(hmac("published-secret")))
    m = signed(["sig-b25"])

    error(
      verify_quorum(
        m,
        quorum(
          [slot(:x, policy: unknown, principal: "pa"), slot(:y, policy: known, principal: "pb")],
          unit: :principal,
          mode: {:threshold, 2}
        )
      ),
      :quorum_not_met
    )

    # A second, unknown-only label must share the class reached through sig-b25.
    ed = public("ed25519")

    ep =
      policy(
        key_resolver: fn _ ->
          {:ok,
           %{algorithm: "ed25519", key: fn a, b, s -> RequestSeal.Crypto.verify(a, b, s, ed) end}}
        end
      )

    slots = [
      slot(:x, policy: unknown, required: false, principal: "pa"),
      slot(:y, policy: known, required: false, principal: "pb"),
      slot(:z, policy: ep, required: false, principal: "pc")
    ]

    error(
      verify_quorum(
        signed(["sig-b25", "sig-b26"]),
        quorum(slots, unit: :principal, mode: {:threshold, 2})
      ),
      :quorum_not_met
    )
  end

  test "required or fail includes unfilled optional bound slots" do
    q =
      quorum([slot(:x, label: "sig-b26"), slot(:y, label: "absent", required: false)],
        bindings: [{:same_parameter, "created", [:x, :y]}]
      )

    error(verify_quorum(signed(["sig-b26"]), q), :binding_unsatisfied)
  end

  test "M1 maximum units and qualifying pairs are independent of slot and wire order" do
    a = local_sign(unsigned(), "a1", ~s[("@method")])
    b = local_sign(unsigned(), "a2", ~s[("@method")], "p256", "ecdsa-p256-sha256")

    slots = [
      slot(:x, label: "a1", required: false, principal: "pa", role: :agent),
      slot(:y, label: "a2", required: false, principal: "pa", role: :agent),
      slot(:z, required: false, principal: "pb", role: :consumer)
    ]

    for unit <- [:principal, {:role, shared_principal: true}, {:role, shared_principal: false}] do
      results =
        for ss <- permutations(slots), wire <- [a.fields ++ b.fields, b.fields ++ a.fields] do
          m = %{
            unsigned()
            | fields:
                Enum.filter(wire, &(String.downcase(&1.name) in ~w(signature signature-input))) ++
                  unsigned().fields
          }

          assert {:ok, r} = verify_quorum(m, quorum(ss, unit: unit, mode: {:threshold, 2}))
          assert r.count == 2
          {MapSet.new(r.satisfied), MapSet.new(Enum.map(r.qualifying, &{&1.label, &1.slot}))}
        end

      assert length(Enum.uniq(results)) == 1
    end
  end

  test "E1 bindings search all candidates and optional same-key additions preserve success" do
    slots = [slot(:i), slot(:o, label: "outer")]
    q = quorum(slots, bindings: [{:nested, outer: :o, inner: :i}])

    for extra <- [nil, "aother", "zz-other"] do
      m = local_sign(unsigned(), "zin", ~s[("@method")])
      m = if extra, do: local_sign(m, extra, ~s[("@method")]), else: m

      m =
        local_sign(
          m,
          "outer",
          ~s[("signature-input";key="zin" "signature";key="zin")],
          "p256",
          "ecdsa-p256-sha256"
        )

      assert {:ok, r} = verify_quorum(m, q)
      assert Enum.map(r.qualifying, &{&1.label, &1.slot}) == [{"zin", :i}, {"outer", :o}]
    end
  end

  test "D1 a verified challenge need not consume a counted slot" do
    m =
      unsigned()
      |> local_sign("a1", ~s[("@method");created=1618884475])
      |> local_sign("a2", ~s[("@method");created=1618884475])

    q = quorum([slot(:x, label: "a1"), slot(:y, label: "a2", required: false)])

    {:ok, requests} =
      RequestSeal.AcceptSignature.parse(~s[a2=("@method");created], target: :request)

    assert {:ok, r} = verify_quorum(m, q, accept_signature: requests)
    assert r.negotiation == :fulfilled
    assert r.count == 1
    assert Enum.map(r.qualifying, &{&1.label, &1.slot}) == [{"a1", :x}]
    refute Map.has_key?(r.signatures, "a2")

    tampered =
      rewrite(m, fn
        "signature", "a2=:" <> rest -> "a2=:" <> flip(rest)
        _, v -> v
      end)

    error(
      verify_quorum(tampered, q, accept_signature: requests),
      :negotiation_unfulfilled,
      :negotiation
    )
  end

  test "optional unknown-only labels preserve the principal count" do
    p = policy(key_resolver: handle_resolver(hmac(nil)))

    q =
      quorum(
        [
          slot(:x, policy: p, principal: "pa"),
          slot(:y, policy: p, principal: "pb", required: false)
        ],
        unit: :principal
      )

    base = signed(["sig-b25"])
    # Labels are outside the signature base; this is the same published signature.
    extra =
      append(
        base,
        Map.new(vector("sig-b25"), fn {k, v} ->
          {k, if(is_binary(v), do: String.replace(v, "sig-b25", "extra"), else: v)}
        end)
      )

    assert {:ok, before} = verify_quorum(base, q)
    assert {:ok, after_extra} = verify_quorum(extra, q)
    assert before.count == after_extra.count
  end

  test "class-merge exception new bridge evidence can merge previously distinct classes" do
    sign = fn m, label, input ->
      {:ok, one} =
        RequestSeal.sign(
          unsigned(),
          %{
            label: label,
            signature_input: input <> ~s[;keyid="test-shared-secret"],
            algorithm: "hmac-sha256"
          },
          signer("hmac")
        )

      %{
        m
        | fields:
            m.fields ++
              Enum.filter(
                one.fields,
                &(String.downcase(&1.name) in ~w(signature signature-input))
              )
      }
    end

    m = unsigned() |> sign.("a", ~s[("@method")]) |> sign.("b", ~s[("@authority")])

    for {second_identity, unit} <- [{"B", :key}, {nil, :principal}] do
      slots = [
        slot(:x,
          principal: "pa",
          policy: policy(key_resolver: handle_resolver(hmac("A")), components: ~s[("@method")])
        ),
        slot(:y,
          principal: "pb",
          policy:
            policy(
              key_resolver: handle_resolver(hmac(second_identity)),
              components: ~s[("@authority")]
            )
        )
      ]

      q = quorum(slots, unit: unit)
      assert {:ok, %{count: 2}} = verify_quorum(m, q)
      bridge = sign.(m, "bridge", ~s[("@method" "@authority")])
      error(verify_quorum(bridge, q), :quorum_not_met)
    end
  end

  test "T1-T4 64 real keys and 16 slots stay below one second for every unit" do
    {m, p} = generated_pool(64, 16)
    ids = assignment_ids()

    for {name, unit, mode, required} <- [
          {"T1", :key, {:threshold, 16}, false},
          {"T2", :principal, {:threshold, 16}, false},
          {"T3", {:role, shared_principal: false}, {:threshold, 16}, false},
          {"T4", :key, :all, true},
          {"T2-role", {:role, shared_principal: true}, {:threshold, 16}, false}
        ] do
      slots =
        for {id, n} <- Enum.with_index(ids),
            do: slot(id, policy: p, required: required, principal: "p#{n}", role: id)

      {us, result} =
        :timer.tc(fn ->
          verify_quorum(m, quorum(slots, unit: unit, mode: mode, max_signatures: 64))
        end)

      assert {:ok, %{count: 16}} = result
      IO.puts("ASSIGN_TIMING #{name} #{us} us")
      assert us < 1_000_000
    end
  end

  test "T5 the 65th signature fails at the input limit" do
    {m, p} = generated_pool(65, 16)
    error(verify_quorum(m, quorum([slot(:x, policy: p)], max_signatures: 64)), :limit, :input)
  end

  @tag timeout: 30_000
  test "budget 16 selector-free nonce-bound slots fail closed and four slots succeed" do
    # Sixteen distinct nonce values, with 15 keys sharing one value. Early
    # consistency checks cannot fill 16 slots, but the permutations exhaust
    # the node budget. A uniform four-per-value pool ends before exhaustion.
    {m, p} = generated_pool(64, fn n -> if n < 15, do: 0, else: 1 + rem(n - 15, 15) end)
    slots = for id <- assignment_ids(), do: slot(id, policy: p)

    q =
      quorum(slots, max_signatures: 64, bindings: [{:same_parameter, "nonce", assignment_ids()}])

    error(verify_quorum(m, q), :limit, :input)
    four = Enum.take(slots, 4)

    q =
      quorum(four,
        max_signatures: 64,
        bindings: [{:same_parameter, "nonce", Enum.map(four, & &1.id)}]
      )

    assert {:ok, %{count: 4}} = verify_quorum(m, q)
  end

  @tag :differential
  test "assignment agrees with exhaustive enumeration for fixed random seeds" do
    cases =
      for seed <- [11, 29, 47, 71, 101, 131], case_number <- 1..60 do
        :rand.seed(:exsss, {seed, case_number, seed + case_number})

        {message, q} =
          case rem(case_number, 6) do
            0 -> random_bound_quorum()
            1 -> random_competing_quorum()
            _ -> random_quorum()
          end

        expected = exhaustive_quorum(message, q)
        actual = quorum_decision(verify_quorum(message, q))
        {seed, case_number, q, expected, actual}
      end

    mismatches = Enum.filter(cases, fn {_, _, _, expected, actual} -> expected != actual end)
    IO.puts("DIFFERENTIAL cases=#{length(cases)} mismatches=#{length(mismatches)}")

    for unit <- [
          :key,
          :principal,
          {:role, shared_principal: true},
          {:role, shared_principal: false}
        ] do
      selected = Enum.filter(cases, fn {_, _, q, _, _} -> q.unit == unit end)
      assert length(selected) > 0

      assert Enum.any?(selected, fn {_, _, _, decision, _} ->
               match?({:satisfied, _}, decision)
             end)

      assert Enum.any?(selected, fn {_, _, _, decision, _} -> decision == {:unsatisfied, nil} end)
    end

    for kind <- [:nested, :same_parameter] do
      assert Enum.any?(cases, fn {_, _, q, expected, _} ->
               match?({:satisfied, _}, expected) and
                 Enum.any?(q.bindings, &(elem(&1, 0) == kind))
             end)
    end

    assert mismatches == [], inspect(Enum.take(mismatches, 5), pretty: true, limit: :infinity)
  end

  @tag :role_false_worst
  @tag timeout: 60_000
  test "16 optional role-false slots with unreachable extra role stay within the node budget" do
    {message, p} = generated_pool(64, 1)

    slots =
      for id <- assignment_ids() do
        slot(id,
          policy: p,
          required: false,
          label: if(id == :p, do: "absent", else: nil),
          principal: if(id == :p, do: "unreachable", else: "shared"),
          role: id
        )
      end

    q = quorum(slots, mode: :any, unit: {:role, shared_principal: false}, max_signatures: 64)
    {us, result} = :timer.tc(fn -> verify_quorum(message, q) end)
    assert {:ok, %{count: 1, satisfied: satisfied}} = result
    assert length(satisfied) == 15
    IO.puts("ROLE_FALSE_WORST #{us} us")
  end

  test "an unmatched required slot takes precedence over an unsatisfied binding" do
    q =
      quorum([slot(:x, label: "absent"), slot(:y, label: "sig-b26", required: false)],
        bindings: [{:same_parameter, "nonce", [:x, :y]}]
      )

    error(verify_quorum(signed(["sig-b26"]), q), :quorum_not_met)
  end

  # Local RFC 9421 construction and real custodian verification exercise assignment,
  # not independent protocol conformance. Randomness controls policy and wire choices.
  defp random_quorum do
    labels = Enum.take(~w(a b c d e f), :rand.uniform(6))

    message =
      Enum.reduce(Enum.with_index(labels), unsigned(), fn {label, index}, message ->
        covered = random_choice([~s["@method"], ~s["@authority"], ~s["@method" "@authority"]])

        covered =
          if index > 0 and :rand.uniform(3) == 1 do
            inner = random_choice(Enum.take(labels, index))
            covered <> ~s[ "signature-input";key="#{inner}" "signature";key="#{inner}"]
          else
            covered
          end

        parameters =
          for name <- ~w(nonce tag created), :rand.uniform(4) != 1, into: "" do
            value =
              if name == "created",
                do: to_string(:rand.uniform(2)),
                else: ~s["v#{:rand.uniform(2)}"]

            ";#{name}=#{value}"
          end

        {:ok, message} =
          RequestSeal.sign(
            message,
            %{
              label: label,
              signature_input:
                "(" <> covered <> ")" <> parameters <> ~s[;keyid="test-shared-secret"],
              algorithm: "hmac-sha256"
            },
            signer("hmac"),
            field_schemas: schemas()
          )

        message
      end)

    coherent = :rand.uniform(2) == 1
    identities = Map.new(labels, &{&1, random_choice([nil, "A", "B", "C", "D", "E", "F"])})

    slots =
      for id <- Enum.take(assignment_ids(), :rand.uniform(6)) do
        # These are caller-owned real HMAC custodians. A label can be observed
        # under different trusted equivalence declarations, including unknown.
        resolvers =
          Map.new(labels, fn label ->
            identity =
              if coherent,
                do: identities[label],
                else: random_choice([nil, "A", "B", "C", "D", "E", "F"])

            {label, handle_resolver(hmac(identity))}
          end)

        p =
          policy(
            key_resolver: fn %{label: label} = request ->
              Map.fetch!(resolvers, label).(request)
            end,
            components: random_choice(["()", ~s[("@method")], ~s[("@authority")]])
          )

        slot(id,
          policy: p,
          required: :rand.uniform(4) == 1,
          label: random_choice([nil, nil, nil, "absent" | labels]),
          tag: random_choice([nil, nil, nil, "v1", "v2", "absent"]),
          principal: random_choice(~w(p1 p2 p3)),
          role: random_choice([:agent, :consumer, :proxy])
        )
      end

    ids = Enum.map(slots, & &1.id)

    bindings =
      if length(ids) >= 2 do
        [first, second | _] = Enum.shuffle(ids)

        random_choice([
          [],
          [],
          [],
          [{:nested, outer: first, inner: second}],
          [{:same_parameter, random_choice(~w(nonce tag created)), [first, second]}],
          [{:nested, outer: first, inner: second}, {:same_parameter, "nonce", [first, second]}]
        ])
      else
        []
      end

    mode = random_choice([:any, :all, {:threshold, :rand.uniform(6)}])
    mode = if mode == :all and not Enum.any?(slots, & &1.required), do: :any, else: mode

    unit =
      random_choice([
        :key,
        :principal,
        {:role, shared_principal: true},
        {:role, shared_principal: false}
      ])

    {message, quorum(slots, mode: mode, unit: unit, bindings: bindings)}
  end

  defp random_competing_quorum do
    {message, p} = generated_pool(1 + :rand.uniform(5), 2)
    [first, second] = Enum.take_random(~w(p1 p2 p3 p4), 2)
    [role1, role2] = Enum.take_random([:agent, :consumer, :proxy], 2)

    slots = [
      slot(:a, policy: p, label: "s00", required: false, principal: first, role: role1),
      slot(:b,
        policy: p,
        label: "s01",
        required: :rand.uniform(2) == 1,
        principal: first,
        role: role1
      ),
      slot(:c, policy: p, label: "s00", required: false, principal: second, role: role2)
    ]

    slots =
      slots ++
        for id <- Enum.take([:d, :e, :f], :rand.uniform(4) - 1),
            do:
              slot(id,
                policy: p,
                label: "absent",
                required: false,
                principal: random_choice([first, second]),
                role: random_choice([role1, role2])
              )

    unit =
      random_choice([
        :key,
        :principal,
        {:role, shared_principal: true},
        {:role, shared_principal: false}
      ])

    mode = random_choice([:any, {:threshold, :rand.uniform(3)}])
    {message, quorum(slots, unit: unit, mode: mode)}
  end

  defp random_bound_quorum do
    size = 1 + :rand.uniform(5)
    labels = Enum.take(~w(a b c d e f), size)
    ids = Enum.take(assignment_ids(), size)
    nonce = "v#{:rand.uniform(3)}"

    message =
      Enum.reduce(Enum.with_index(labels), unsigned(), fn {label, n}, message ->
        covered =
          if n == 1,
            do: ~s["@method" "signature-input";key="a" "signature";key="a"],
            else: ~s["@method"]

        {:ok, message} =
          RequestSeal.sign(
            message,
            %{
              label: label,
              signature_input:
                "(" <> covered <> ~s[);nonce="#{nonce}";keyid="test-shared-secret"],
              algorithm: "hmac-sha256"
            },
            signer("hmac"),
            field_schemas: schemas()
          )

        message
      end)

    resolvers = Map.new(labels, &{&1, handle_resolver(hmac("key-#{&1}"))})
    p = policy(key_resolver: fn %{label: label} = request -> resolvers[label].(request) end)

    slots =
      for {id, label} <- Enum.zip(ids, labels) do
        slot(id,
          policy: p,
          label: random_choice([nil, label]),
          required: :rand.uniform(2) == 1,
          principal: random_choice(~w(p1 p2 p3)),
          role: random_choice([:agent, :consumer, :proxy])
        )
      end

    bindings =
      random_choice([
        [{:nested, outer: :b, inner: :a}],
        [{:same_parameter, "nonce", [:a, :b]}],
        [{:nested, outer: :b, inner: :a}, {:same_parameter, "nonce", [:a, :b]}]
      ])

    unit =
      random_choice([
        :key,
        :principal,
        {:role, shared_principal: true},
        {:role, shared_principal: false}
      ])

    mode = random_choice([:any, {:threshold, :rand.uniform(size)}])
    {message, quorum(slots, unit: unit, mode: mode, bindings: bindings)}
  end

  defp random_choice(values), do: Enum.at(values, :rand.uniform(length(values)) - 1)
  defp quorum_decision({:ok, result}), do: {:satisfied, result.count}
  defp quorum_decision({:error, _}), do: {:unsatisfied, nil}

  # Share only real parsing/cryptography with the product. Connected components,
  # assignments, role counting, bindings, and mode checks below are independent
  # exhaustive enumerations, without matching or pruning from Evaluation.
  defp exhaustive_quorum(message, q) do
    {:ok, {inputs, signatures}} =
      RequestSeal.Authentication.dictionaries(message, q.max_signatures)

    candidates =
      for slot <- q.slots,
          {label, input} <- inputs,
          slot.label == nil or slot.label == label,
          slot.tag == nil or slot.tag == RequestSeal.SignatureFields.parameters(input)["tag"],
          {result, _} =
            RequestSeal.Authentication.verify_label(
              message,
              slot.policy,
              label,
              input,
              signatures[label],
              %{},
              %{}
            ),
          {:ok, verification, identity} <- [result] do
        %{slot: slot, label: label, verification: verification, identity: identity}
      end

    indexed = Enum.with_index(candidates)

    candidates =
      Enum.map(indexed, fn {candidate, index} ->
        component = reference_component(MapSet.new([index]), indexed)

        known =
          Enum.any?(candidates, &(&1.label == candidate.label and &1.identity.kind != :unknown))

        Map.merge(candidate, %{class: Enum.min(component), known: known})
      end)
      |> Enum.filter(&(q.unit != :key or &1.known))

    best =
      enumerate_assignments(q.slots, candidates, [])
      |> Enum.filter(&reference_bindings?(&1, q.bindings))
      |> Enum.map(&{reference_count(&1, q.unit), &1})
      |> Enum.max_by(fn {count, records} -> {count, length(records)} end, fn -> {0, []} end)

    {count, records} = best
    required = Enum.filter(q.slots, & &1.required)
    required_filled = Enum.all?(required, fn s -> Enum.any?(records, &(&1.slot.id == s.id)) end)

    mode_met =
      case q.mode do
        :any ->
          true

        {:threshold, n} ->
          count >= n

        :all ->
          q.unit != {:role, shared_principal: false} or
            reference_count(Enum.filter(records, & &1.slot.required), q.unit) ==
              length(Enum.uniq(Enum.map(required, & &1.role)))
      end

    if count > 0 and required_filled and mode_met,
      do: {:satisfied, count},
      else: {:unsatisfied, nil}
  end

  defp reference_component(component, indexed) do
    connected =
      for {candidate, index} <- indexed,
          {other, other_index} <- indexed,
          MapSet.member?(component, other_index),
          candidate.label == other.label or
            (candidate.identity.kind == :unknown and other.identity.kind == :unknown) or
            KeyIdentity.same?(candidate.identity, other.identity),
          into: component,
          do: index

    if connected == component, do: component, else: reference_component(connected, indexed)
  end

  defp enumerate_assignments([], _, chosen), do: [chosen]

  defp enumerate_assignments([slot | rest], candidates, chosen) do
    filled =
      for candidate <- candidates,
          candidate.slot.id == slot.id,
          Enum.all?(chosen, &(&1.label != candidate.label and &1.class != candidate.class)),
          assignment <- enumerate_assignments(rest, candidates, [candidate | chosen]),
          do: assignment

    if slot.required, do: filled, else: filled ++ enumerate_assignments(rest, candidates, chosen)
  end

  defp reference_bindings?(records, bindings) do
    Enum.all?(bindings, fn
      {:nested, [outer: outer, inner: inner]} ->
        o = Enum.find(records, &(&1.slot.id == outer))
        i = Enum.find(records, &(&1.slot.id == inner))

        o != nil and i != nil and
          Enum.all?(~w(signature-input signature), fn name ->
            ~s["#{name}";key="#{i.label}"] in o.verification.signature.covered
          end)

      {:same_parameter, name, ids} ->
        selected = Enum.filter(records, &(&1.slot.id in ids))
        values = Enum.map(selected, & &1.verification.signature.parameters[name])

        length(selected) == length(ids) and Enum.all?(values, &(&1 != nil)) and
          length(Enum.uniq(values)) == 1
    end)
  end

  defp reference_count(records, :key), do: length(records)

  defp reference_count(records, :principal),
    do: length(Enum.uniq(Enum.map(records, & &1.slot.principal)))

  defp reference_count(records, {:role, shared_principal: true}),
    do: length(Enum.uniq(Enum.map(records, & &1.slot.role)))

  defp reference_count(records, {:role, shared_principal: false}) do
    pairs = Enum.uniq(Enum.map(records, &{&1.slot.role, &1.slot.principal}))
    reference_role_count(Enum.uniq(Enum.map(pairs, &elem(&1, 0))), pairs, [])
  end

  defp reference_role_count([], _, principals), do: length(principals)

  defp reference_role_count([role | rest], pairs, principals) do
    choices = for {^role, principal} <- pairs, principal not in principals, do: principal

    counts =
      for principal <- choices, do: reference_role_count(rest, pairs, [principal | principals])

    Enum.max([reference_role_count(rest, pairs, principals) | counts])
  end

  defp assignment_ids, do: [:a, :b, :c, :d, :e, :f, :g, :h, :i, :j, :k, :l, :m, :n, :o, :p]
  defp permutations([]), do: [[]]

  defp permutations(xs),
    do: for(x <- xs, tail <- permutations(List.delete(xs, x)), do: [x | tail])

  # Locally constructed RFC 9421 signatures; resource/assignment evidence only,
  # never an independent external-conformance vector.
  defp generated_pool(size, nonce_values) do
    nonce =
      if is_function(nonce_values, 1), do: nonce_values, else: fn n -> rem(n, nonce_values) end

    keys =
      for n <- 0..(size - 1), into: %{} do
        {public_bytes, private_bytes} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, public_key} = PublicKey.import({:ed25519, public_bytes}, :raw)
        {"k#{n}", {public_key, private_bytes}}
      end

    p =
      policy(
        key_resolver: fn %{keyid: id} ->
          {key, _} = Map.fetch!(keys, id)
          {:ok, %{algorithm: "ed25519", key: key}}
        end
      )

    m =
      Enum.reduce(0..(size - 1), unsigned(), fn n, m ->
        {_, private_bytes} = keys["k#{n}"]

        {:ok, one} =
          RequestSeal.sign(
            unsigned(),
            %{
              label: "s#{String.pad_leading(to_string(n), 2, "0")}",
              signature_input: ~s[("@method");keyid="k#{n}";nonce="n#{nonce.(n)}"],
              algorithm: "ed25519"
            },
            fn alg, base -> RequestSeal.Crypto.sign(alg, base, {:ed25519, private_bytes}) end
          )

        %{
          m
          | fields:
              m.fields ++
                Enum.filter(
                  one.fields,
                  &(String.downcase(&1.name) in ~w(signature signature-input))
                )
        }
      end)

    {m, p}
  end

  defp trace_counts(owner, counts) do
    receive do
      {:trace, _, :call, {_, fun, _}} ->
        trace_counts(owner, Map.update(counts, fun, 1, &(&1 + 1)))

      {:counts, ref} ->
        send(owner, {:counts, ref, counts})
        trace_counts(owner, counts)

      :stop ->
        :ok
    end
  end

  defp flip(wire) do
    <<first, rest::binary>> = wire |> String.trim_trailing(":") |> Base.decode64!()
    Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>) <> ":"
  end
end
