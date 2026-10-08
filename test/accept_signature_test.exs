defmodule RequestSeal.AcceptSignatureTest do
  use ExUnit.Case, async: false
  import RequestSeal.MultiSignatureSupport
  alias RequestSeal.{AcceptSignature, StructuredFields}
  alias RequestSeal.StructuredFields.Value

  for {first, last} <- [{"a", "fresh"}, {"fresh", "a"}] do
    @first first
    @last last
    test "N3 duplicate request parameters #{@first} then #{@last}" do
      wire = ~s[s=("@method");nonce="#{@first}";nonce="#{@last}"]
      error(AcceptSignature.parse(wire, target: :request), :duplicate_parameter, :fields)
      assert {:ok, _} = AcceptSignature.parse(~s[s=("@method");nonce="fresh"], target: :request)
    end
  end

  test "N3 duplicate request component parameters reject in both orders" do
    for keys <- [~s[;key="a";key="b"], ~s[;key="b";key="a"]] do
      error(
        AcceptSignature.parse(~s[s=("signature"#{keys})], target: :request),
        :duplicate_parameter,
        :fields
      )
    end
  end

  test "Section 5.1 request parses and serializes exact published parameters" do
    wire = corpus()["accept_signature"]
    assert {:ok, [r]} = AcceptSignature.parse(wire, target: :request)
    assert r.label == "sig1"
    assert r.parameters == %{"keyid" => "test-key-rsa-pss", "created" => true, "tag" => "app-123"}
    assert {:ok, ^wire} = AcceptSignature.serialize([r])
    assert {:ok, [^r]} = AcceptSignature.parse([wire], target: :request)

    for target <- [:request, :response] do
      assert {:ok, []} = AcceptSignature.parse("", target: target)
    end
  end

  test "target applicability, bare timestamp requests, parameter types and duplicates reject" do
    error(
      AcceptSignature.parse(~s[s=("@status")], target: :request),
      :inapplicable_component,
      :negotiation
    )

    for wire <- [~s[s=("@method";req)], ~s[s=("@status";req)]] do
      error(AcceptSignature.parse(wire, target: :request), :inapplicable_component, :negotiation)
    end

    error(
      AcceptSignature.parse(~s[s=("@method")], target: :response),
      :inapplicable_component,
      :negotiation
    )

    assert {:ok, _} = AcceptSignature.parse(~s[s=("@status" "@method";req)], target: :response)

    for wire <- [
          ~s[s=("@method");created=1],
          ~s[s=("@method");expires=?0],
          ~s[s=("@method");nonce],
          ~s[s=("@method");alg="EdDSA"],
          ~s[s=("@method");unknown],
          ~s[s=("@method" "@method")],
          ~s[s="@method"]
        ] do
      error(
        AcceptSignature.parse(wire, target: :request),
        :invalid_accept_signature,
        :negotiation
      )
    end

    error(
      AcceptSignature.parse([~s[s=("@method")], ~s[s=("@method")]], target: :request),
      :duplicate_label,
      :fields
    )

    error(AcceptSignature.parse(~s[s=(), s=()], target: :request), :duplicate_label, :fields)
    error(AcceptSignature.parse("s=()", target: :other), :invalid_options, :input)

    error(
      AcceptSignature.serialize([
        %{
          label: "s",
          components: %Value{type: :inner_list, value: []},
          parameters: %{"created" => 1}
        }
      ]),
      :invalid_accept_signature,
      :negotiation
    )
  end

  test "malformed request shapes and callbacks remain bounded without partial results" do
    assert {:ok, [r]} = AcceptSignature.parse(~s[s=("@method");created], target: :request)

    for bad <- [
          %{r | components: ~s[("@method")]},
          %{r | components: nil},
          %{r | parameters: nil},
          Map.put(r, :unknown, true)
        ] do
      error(AcceptSignature.serialize([bad]), :invalid_accept_signature, :negotiation)
    end

    # Real signing is attempted only after a usable chooser result; observe
    # the real callback on the successful path to calibrate the instrument.
    owner = self()

    signing = fn a, b ->
      send(owner, :signed_real_bytes)
      signer("ed25519").(a, b)
    end

    for choice <- [
          fn _ -> {:ok, %{algorithm: "ed25519", created: nil, expires: nil}} end,
          fn _ -> {:ok, %{algorithm: "ed25519", created: 1_000_000_000_000_000, expires: nil}} end
        ] do
      error(
        AcceptSignature.fulfill(unsigned(), [r], choice, signing, []),
        :negotiation_unfulfillable,
        :negotiation
      )

      refute_received :signed_real_bytes
    end

    chooser = fn _ -> {:ok, %{algorithm: "ed25519", created: 1_618_884_473, expires: nil}} end
    assert {:ok, _} = AcceptSignature.fulfill(unsigned(), [r], chooser, signing, [])
    assert_received :signed_real_bytes
  end

  test "fulfill source request only with available components and authoritative HTTP algorithm" do
    assert {:ok, requests} = AcceptSignature.parse(corpus()["accept_signature"], target: :request)

    error(
      AcceptSignature.fulfill(unsigned(), requests, &choose/1, signer("rsa_pss"), []),
      :negotiation_unfulfillable,
      :negotiation
    )

    m = add(unsigned(), "Cache-Control", "max-age=60")
    assert {:ok, signed} = AcceptSignature.fulfill(m, requests, &choose/1, signer("rsa_pss"), [])
    q = quorum([slot(:requested, label: "sig1")])
    assert {:ok, r} = verify_quorum(signed, q, accept_signature: requests)
    assert r.negotiation == :fulfilled

    for choice <- [
          fn _ -> :error end,
          fn _ -> {:ok, %{algorithm: {:jws, "PS256"}, created: 1_618_884_473, expires: nil}} end,
          fn _ -> {:ok, %{algorithm: "ed25519", created: nil, expires: nil}} end
        ] do
      error(
        AcceptSignature.fulfill(m, requests, choice, signer("rsa_pss"), []),
        :negotiation_unfulfillable,
        :negotiation
      )
    end

    assert {:ok, with_alg} =
             AcceptSignature.parse(~s[s=("@method");alg="rsa-pss-sha512"], target: :request)

    error(
      AcceptSignature.fulfill(
        m,
        with_alg,
        fn _ -> {:ok, %{algorithm: "ed25519", created: nil, expires: nil}} end,
        signer("ed25519"),
        []
      ),
      :negotiation_unfulfillable,
      :negotiation
    )

    assert {:ok, _} = AcceptSignature.fulfill(m, with_alg, &choose/1, signer("rsa_pss"), [])
  end

  test "incompatible requested algorithm rejects before entering the signing API" do
    assert {:ok, requests} =
             AcceptSignature.parse(~s[s=("@method");alg="rsa-pss-sha512"], target: :request)

    chooser = fn _ -> {:ok, %{algorithm: "ed25519", created: nil, expires: nil}} end
    owner = self()
    tracer = spawn_link(fn -> trace_calls(owner) end)
    Code.ensure_loaded!(RequestSeal)
    assert :erlang.trace_pattern({RequestSeal, :sign, 4}, true, []) == 1
    :erlang.trace(self(), true, [:call, {:tracer, tracer}])

    try do
      error(
        AcceptSignature.fulfill(unsigned(), requests, chooser, signer("ed25519"), []),
        :negotiation_unfulfillable,
        :negotiation
      )

      drain_trace(tracer)
      refute_received :entered_sign
      assert {:ok, plain} = AcceptSignature.parse("s=()", target: :request)
      assert {:ok, _} = AcceptSignature.fulfill(unsigned(), plain, chooser, signer("ed25519"), [])
      drain_trace(tracer)
      assert_received :entered_sign
    after
      :erlang.trace(self(), false, [:call])
      :erlang.trace_pattern({RequestSeal, :sign, 4}, false, [])
      send(tracer, :stop)
    end
  end

  test "nonce challenges bind exact label, covered identities and requested parameters" do
    wire = corpus()["accept_signature"] <> ~s[;nonce="fresh-challenge";expires]
    assert {:ok, [request]} = AcceptSignature.parse(wire, target: :request)
    m = add(unsigned(), "Cache-Control", "max-age=60")
    assert {:ok, signed} = AcceptSignature.fulfill(m, [request], &choose/1, signer("rsa_pss"), [])
    q = quorum([slot(:requested)], mode: :any)

    assert {:ok, %{negotiation: :fulfilled}} =
             verify_quorum(signed, q, accept_signature: [request])

    extra = local_sign(signed, "extra", ~s[("@method")])

    assert {:ok, %{negotiation: :fulfilled}} =
             verify_quorum(extra, q, accept_signature: [request])

    renamed = rewrite(signed, fn _, v -> String.replace(v, "sig1", "renamed") end)

    error(
      verify_quorum(renamed, q, accept_signature: [request]),
      :negotiation_unfulfilled,
      :negotiation
    )

    for changed <- [
          %{request | parameters: Map.put(request.parameters, "tag", "different")},
          %{request | parameters: Map.put(request.parameters, "nonce", "other-challenge")},
          %{request | parameters: Map.put(request.parameters, "keyid", "different")}
        ] do
      assert {:ok, changed_message} =
               AcceptSignature.fulfill(m, [changed], &choose/1, signer("rsa_pss"), [])

      # Use the public verification key directly to isolate negotiation from resolver lookup.
      q =
        quorum(
          [
            slot(:requested,
              policy:
                policy(
                  key_resolver: fn _ ->
                    {:ok, %{algorithm: "rsa-pss-sha512", key: public("rsa_pss")}}
                  end
                )
            )
          ],
          mode: :any
        )

      error(
        verify_quorum(changed_message, q, accept_signature: [request]),
        :negotiation_unfulfilled,
        :negotiation
      )
    end

    components = %{request.components | value: tl(request.components.value)}

    assert {:ok, dropped} =
             AcceptSignature.fulfill(
               m,
               [%{request | components: components}],
               &choose/1,
               signer("rsa_pss"),
               []
             )

    error(
      verify_quorum(dropped, q, accept_signature: [request]),
      :negotiation_unfulfilled,
      :negotiation
    )

    no_times =
      local_sign(
        m,
        "sig1",
        ~s[("@method" "@target-uri" "@authority" "content-digest" "cache-control");keyid="test-key-rsa-pss";tag="app-123";nonce="fresh-challenge"],
        "rsa_pss",
        "rsa-pss-sha512"
      )

    error(
      verify_quorum(no_times, q, accept_signature: [request]),
      :negotiation_unfulfilled,
      :negotiation
    )
  end

  test "negotiation compares component parameters as identities and permits order changes" do
    assert {:ok, [request]} =
             AcceptSignature.parse(~s[s=("content-digest";sf "@method");keyid="test-key-ed25519"],
               target: :request
             )

    q = quorum([slot(:ed)])
    plain = local_sign(unsigned(), "s", ~s[("content-digest" "@method");keyid="test-key-ed25519"])

    error(
      verify_quorum(plain, q, accept_signature: [request]),
      :negotiation_unfulfilled,
      :negotiation
    )

    exact =
      local_sign(
        unsigned(),
        "s",
        ~s[("@method" "content-digest";sf);keyid="test-key-ed25519";created=1618884473]
      )

    assert {:ok, _} = verify_quorum(exact, q, accept_signature: [request])

    extra =
      local_sign(
        unsigned(),
        "s",
        ~s[("@method" "content-digest";sf "@path");keyid="test-key-ed25519"]
      )

    error(
      verify_quorum(extra, q, accept_signature: [request]),
      :negotiation_unfulfilled,
      :negotiation
    )

    {:ok, reversed} =
      StructuredFields.serialize(
        %Value{
          type: :list,
          value: [%{request.components | value: Enum.reverse(request.components.value)}]
        },
        RequestSeal.SignatureFields.schema(:list)
      )

    assert reversed == ~s[("@method" "content-digest";sf)]
  end

  test "fulfillment preserves request order and copies requested strings verbatim" do
    assert {:ok, requests} =
             AcceptSignature.parse(
               [
                 ~s[first=("@method");keyid="test-key-ed25519";nonce="challenge\\\"quoted";tag="tag-one"],
                 ~s[second=("@path");created;expires]
               ],
               target: :request
             )

    chooser = fn _ ->
      {:ok, %{algorithm: "ed25519", created: 1_618_884_473, expires: 1_618_884_540}}
    end

    assert {:ok, m} =
             AcceptSignature.fulfill(unsigned(), requests, chooser, signer("ed25519"), [])

    inputs = Enum.filter(m.fields, &(String.downcase(&1.name) == "signature-input"))

    assert Enum.map(inputs, &(String.split(&1.value, "=", parts: 2) |> hd())) == [
             "first",
             "second"
           ]

    assert {:ok, r} = RequestSeal.verify(m, policy(), label: "first")
    assert r.signature.parameters["nonce"] == hd(requests).parameters["nonce"]
    assert r.signature.parameters["tag"] == "tag-one"
    # second explicitly lacks keyid, so caller supplies the selected public key.
    p = policy(key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public("ed25519")}} end)
    assert {:ok, r} = RequestSeal.verify(m, p, label: "second")
    assert r.signature.parameters["created"] == 1_618_884_473
    assert r.signature.parameters["expires"] == 1_618_884_540
  end

  defp trace_calls(owner) do
    receive do
      {:trace, _, :call, {RequestSeal, :sign, _}} ->
        send(owner, :entered_sign)
        trace_calls(owner)

      {:flush, ref} ->
        send(owner, {:flushed, ref})
        trace_calls(owner)

      :stop ->
        :ok
    end
  end

  defp drain_trace(tracer) do
    ref = :erlang.trace_delivered(self())
    assert_receive {:trace_delivered, _, ^ref}
    send(tracer, {:flush, ref})
    assert_receive {:flushed, ^ref}
  end

  defp choose(_),
    do: {:ok, %{algorithm: "rsa-pss-sha512", created: 1_618_884_473, expires: 1_618_884_540}}
end
