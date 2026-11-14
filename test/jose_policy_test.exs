defmodule RequestSeal.JOSEPolicyTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Custody, PublicKey}
  alias RequestSeal.JOSE.{Error, JWE, JWS, Support}
  alias RequestSeal.Test.JOSEBatchCustodian
  import RequestSeal.JOSEVectors, only: [fixture: 1, replace: 3, header: 2]

  setup do
    {:ok, handle} = Custody.Local.new({:jwe, "A256KW"}, {:aes, <<0::256>>})
    on_exit(fn -> Custody.release(handle) end)

    {:ok, token} =
      JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}, {"typ", "test"}], "payload", handle)

    observer = self()

    p =
      policy(handle, "A256KW", fn request ->
        send(observer, {:resolved, request})
        {:ok, %{algorithm: request.algorithm, key: handle}}
      end)

    {:ok, token: token, handle: handle, p: p}
  end

  defp policy(handle, alg, resolver \\ nil) do
    %{
      algorithms: [alg],
      encryption: ["A256GCM"],
      max_plaintext: 1_048_576,
      timeout: 5000,
      resolve_timeout: 1000,
      unwrap_timeout: 1000,
      protected: %{expected: %{"typ" => "test"}, permitted: []},
      key_resolver: resolver || fn _ -> {:ok, %{algorithm: alg, key: handle}} end
    }
  end

  defp error(result, reason, layer \\ :input),
    do: assert(result == {:error, Error.new(reason, layer)})

  defp mutate_header(token, fun) do
    [h | _] = String.split(token, ".")

    header(
      token,
      h |> Support.decode() |> :json.decode() |> fun.() |> :json.encode() |> IO.iodata_to_binary()
    )
  end

  test "2.6 exact key set requires every field and refuses extras", %{token: t, p: p} do
    for k <- Map.keys(p), do: error(JWE.decrypt(t, Map.delete(p, k)), :invalid_policy)
    error(JWE.decrypt(t, Map.put(p, :extra, true)), :invalid_policy)
    assert {:ok, %{plaintext: "payload"}} = JWE.decrypt(t, p)
  end

  test "2.6 positive bounded budgets and strict sum including largest accepted sum", %{
    token: t,
    p: p
  } do
    for k <- [:timeout, :resolve_timeout, :unwrap_timeout],
        value <- [0, 300_001, :infinity, 1.0] do
      error(JWE.decrypt(t, Map.put(p, k, value)), :invalid_policy)
    end

    for timeout <- [1999, 2000],
        do: error(JWE.decrypt(t, %{p | timeout: timeout}), :invalid_policy)

    assert {:ok, _} =
             JWE.decrypt(t, %{
               p
               | timeout: 300_000,
                 resolve_timeout: 149_999,
                 unwrap_timeout: 150_000
             })
  end

  for {name, protected} <- [
        {"expected not object", %{expected: [], permitted: []}},
        {"expected non JSON", %{expected: %{"x" => :atom}, permitted: []}},
        {"expected oversized",
         %{expected: %{"x" => String.duplicate("x", 16_384)}, permitted: []}},
        {"expected too many", %{expected: Map.new(1..65, &{"x#{&1}", 0}), permitted: []}},
        {"permitted too many", %{expected: %{}, permitted: Enum.map(1..65, &"x#{&1}")}},
        {"duplicate permitted", %{expected: %{}, permitted: ["x", "x"]}},
        {"overlap", %{expected: %{"x" => 1}, permitted: ["x"]}},
        {"nonbinary permitted", %{expected: %{}, permitted: [:x]}},
        {"extra protected field", %{expected: %{}, permitted: [], extra: true}}
      ] do
    test "2.6 policy refuses #{name}", %{token: t, p: p} do
      error(JWE.decrypt(t, %{p | protected: unquote(Macro.escape(protected))}), :invalid_policy)
      refute_receive {:resolved, _}
    end
  end

  for name <- ~w(alg enc iv tag epk apu apv) do
    test "2.6 policy cannot name reserved member #{name}", %{token: t, p: p} do
      for protected <- [
            %{expected: %{unquote(name) => "x"}, permitted: []},
            %{expected: %{}, permitted: [unquote(name)]}
          ] do
        error(JWE.decrypt(t, %{p | protected: protected}), :invalid_policy)
      end
    end
  end

  test "2.6 largest expected and permitted policy bounds are accepted", %{token: t, p: p} do
    expected = Map.new(1..63, &{"x#{&1}", 0}) |> Map.put("typ", "test")

    error(
      JWE.decrypt(t, %{p | protected: %{expected: expected, permitted: []}}),
      :protected_mismatch
    )

    # {"typ":"..."} has ten bytes of JSON framing.
    expected = %{"typ" => String.duplicate("x", 16_374)}
    assert byte_size(Support.json_encode(expected)) == 16_384

    error(
      JWE.decrypt(t, %{p | protected: %{expected: expected, permitted: []}}),
      :protected_mismatch
    )

    permitted = ["typ" | Enum.map(1..63, &"x#{&1}")]
    assert {:ok, _} = JWE.decrypt(t, %{p | protected: %{expected: %{}, permitted: permitted}})
  end

  test "2.6 step 1 header refusals precede algorithm and member checks", %{token: t, p: p} do
    for {k, reason} <- [
          {"crit", :unsupported_critical_header},
          {"zip", :compression_unsupported},
          {"jku", :unsupported_header},
          {"x5u", :unsupported_header},
          {"jwk", :unsupported_header},
          {"b64", :unsupported_header}
        ] do
      bad = mutate_header(t, &(&1 |> Map.put("alg", "none") |> Map.put(k, nil)))
      error(JWE.decrypt(bad, p), reason)
      refute_receive {:resolved, _}
    end
  end

  test "2.6 step 2 algorithm selection precedes structure and member checks", %{token: t, p: p} do
    t = t |> mutate_header(&Map.put(&1, "alg", "none")) |> replace(2, "!")
    error(JWE.decrypt(t, p), :algorithm_not_permitted)
    refute_receive {:resolved, _}
  end

  test "2.6 step 3 public structure precedes members and expectations", %{token: t, p: p} do
    t = mutate_header(t, &Map.put(&1, "extra", true))

    for {segment, value, reason} <- [
          {1, "!", :invalid_base64},
          {2, Support.b64(<<0>>), :invalid_iv},
          {4, Support.b64(<<0>>), :invalid_tag},
          {3, "!", :invalid_base64}
        ] do
      error(JWE.decrypt(replace(t, segment, value), p), reason)
    end

    error(JWE.decrypt(t, %{p | max_plaintext: 1}), :limit)
    refute_receive {:resolved, _}
  end

  test "2.6 step 4 member set precedes expected values and resolution", %{token: t, p: p} do
    t = mutate_header(t, &(&1 |> Map.put("extra", true) |> Map.put("typ", "wrong")))
    error(JWE.decrypt(t, p), :unexpected_member)
    refute_receive {:resolved, _}
  end

  for mode <- [:missing, :different] do
    test "2.6 step 5 #{mode} expectation is protected_mismatch before resolution", %{
      token: t,
      p: p
    } do
      t =
        mutate_header(t, fn h ->
          if unquote(mode) == :missing, do: Map.delete(h, "typ"), else: Map.put(h, "typ", "wrong")
        end)

      error(JWE.decrypt(t, p), :protected_mismatch)
      refute_receive {:resolved, _}
    end
  end

  test "2.6 exact JSON equality distinguishes integer and boolean and admits empty expectations",
       %{token: t, p: p} do
    error(
      JWE.decrypt(t, %{p | protected: %{expected: %{"typ" => true}, permitted: []}}),
      :protected_mismatch
    )

    assert {:ok, _} = JWE.decrypt(t, %{p | protected: %{expected: %{}, permitted: ["typ"]}})
  end

  test "7.11 wrong width waits for member and expectation refusals", %{token: t, p: p} do
    t = replace(t, 1, Support.b64(<<0::256>>))
    error(JWE.decrypt(mutate_header(t, &Map.put(&1, "extra", 1)), p), :unexpected_member)
    error(JWE.decrypt(mutate_header(t, &Map.put(&1, "typ", "wrong")), p), :protected_mismatch)
    refute_receive {:resolved, _}
  end

  test "7.11 unwrap closure resolver entry is refused", %{token: t, p: p} do
    p = %{
      p
      | key_resolver: fn _ ->
          {:ok, %{algorithm: "A256KW", unwrap: fn _, _ -> {:ok, <<0::256>>} end}}
        end
    }

    error(JWE.decrypt(t, p), :key_resolver_failed, :key)
  end

  test "2.6 resolver deadline R is key_resolver_failed key", %{token: t, p: p} do
    owner = self()

    task =
      Task.async(fn ->
        JWE.decrypt(t, %{
          p
          | resolve_timeout: 150,
            key_resolver: fn _ ->
              send(owner, {:blocked_resolver, self()})
              receive do: (:never -> :error)
            end
        })
      end)

    assert_receive {:blocked_resolver, pid}
    monitor = Process.monitor(pid)
    error(Task.await(task), :key_resolver_failed, :key)
    assert_receive {:DOWN, ^monitor, _, ^pid, _}
  end

  test "2.6 admission unfinished at R reports deadline_exceeded input", %{p: p} do
    token = String.duplicate(" ", 1_048_566) <> ".a.b.c.d"
    error(JWE.decrypt(token, %{p | resolve_timeout: 1}), :deadline_exceeded, :input)
    refute_receive {:resolved, _}
  end

  test "2.6 AEAD response unfinished at D reports deadline_exceeded crypto", %{token: t, p: p} do
    owner = self()
    id = make_ref()

    :ok =
      :telemetry.attach(
        id,
        [:request_seal, :jose, :content_authentication],
        fn _, _, _, _ ->
          send(owner, {:aead_waiting, self()})
          receive do: (:never -> :ok)
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(id) end)

    task =
      Task.async(fn ->
        JWE.decrypt(t, %{p | timeout: 600, resolve_timeout: 100, unwrap_timeout: 100})
      end)

    assert_receive {:aead_waiting, worker}
    monitor = Process.monitor(worker)
    error(Task.await(task), :deadline_exceeded, :crypto)
    assert_receive {:DOWN, ^monitor, _, ^worker, _}
  end

  for alg <- ~w(A128KW A256KW ECDH-ES+A128KW ECDH-ES+A256KW),
      failure <- [
        :corrupt,
        :wrong_key,
        :truncated,
        :overlong,
        :refusal,
        :call_error,
        :unwrap_timeout,
        :tag
      ] do
    test "2.11 #{alg} #{failure} has one authenticated uniform failure" do
      alg = unquote(alg)
      failure = unquote(failure)
      {material, recipient} = recipient(alg)

      {:ok, token} =
        JWE.encrypt([{"alg", alg}, {"enc", "A256GCM"}, {"typ", "test"}], "payload", recipient)

      mode = failure_mode(failure)
      material = failure_material(material, failure)
      handle = JOSEBatchCustodian.start(alg, material, mode, self())
      on_exit(fn -> Custody.release(handle) end)
      token = failure_token(token, failure)
      observer = self()

      p = %{
        policy(handle, alg)
        | unwrap_timeout: 150,
          key_resolver: fn _ ->
            send(observer, :kw_resolved)
            {:ok, %{algorithm: alg, key: handle}}
          end
      }

      attach_content()
      task = Task.async(fn -> JWE.decrypt(token, p) end)

      unless failure in [:truncated, :overlong] do
        assert_receive :kw_resolved
        assert_receive {:batch_holder, holder, _, _, _, 1}
        continue_holder(holder, failure)
      end

      error(Task.await(task), :decryption_failed, :crypto)
      assert_receive {:content, measurements, metadata}
      assert {measurements, metadata} == {%{}, %{outcome: :failed}}
      refute_receive {:content, _, _}
      if failure in [:truncated, :overlong], do: refute_receive(:kw_resolved)
    end
  end

  defp recipient(alg) when alg in ~w(A128KW A256KW) do
    material = {:aes, :binary.copy(<<0>>, if(alg == "A128KW", do: 16, else: 32))}
    {:ok, handle} = Custody.Local.new({:jwe, alg}, material)
    on_exit(fn -> Custody.release(handle) end)
    {material, handle}
  end

  defp recipient(_) do
    {pub, scalar} = :crypto.generate_key(:ecdh, :x25519)
    {:ok, public} = PublicKey.import({:x25519, pub}, :raw)
    {{:ecdh, {:x25519, scalar}}, public}
  end

  defp failure_material(material, :wrong_key), do: wrong_material(material)
  defp failure_material(material, _), do: material
  defp wrong_material({:aes, key}), do: {:aes, :binary.copy(<<1>>, byte_size(key))}

  defp wrong_material({:ecdh, {:x25519, _}}) do
    {_, scalar} = :crypto.generate_key(:ecdh, :x25519)
    {:ecdh, {:x25519, scalar}}
  end

  for {name, member, value, reason} <- [
        {"iv width", "iv", Support.b64(<<0>>), :invalid_iv},
        {"tag width", "tag", Support.b64(<<0>>), :invalid_tag},
        {"iv base64", "iv", "!", :invalid_base64},
        {"tag base64", "tag", "!", :invalid_base64}
      ] do
    test "7.11 GCMKW wrong width with #{name} keeps parameter precedence", %{token: t, p: p} do
      t =
        t
        |> replace(1, Support.b64(<<0>>))
        |> mutate_header(
          &(&1
            |> Map.put("alg", "A256GCMKW")
            |> Map.put("iv", Support.b64(<<0::96>>))
            |> Map.put("tag", Support.b64(<<0::128>>))
            |> Map.put(unquote(member), unquote(value)))
        )

      error(JWE.decrypt(t, %{p | algorithms: ["A256GCMKW"]}), unquote(reason))
      refute_receive {:resolved, _}
    end
  end

  test "GCMKW well formed parameters wrong width authenticates once without resolution", %{
    token: t,
    p: p
  } do
    attach_content()

    t =
      t
      |> replace(1, "AA")
      |> mutate_header(
        &(&1
          |> Map.put("alg", "A256GCMKW")
          |> Map.put("iv", Support.b64(<<0::96>>))
          |> Map.put("tag", Support.b64(<<0::128>>)))
      )

    error(JWE.decrypt(t, %{p | algorithms: ["A256GCMKW"]}), :decryption_failed, :crypto)
    assert_receive {:content, measurements, metadata}
    assert {measurements, metadata} == {%{}, %{outcome: :failed}}
    refute_receive {:resolved, _}
  end

  defp attach_content do
    id = make_ref()

    :ok =
      :telemetry.attach(
        id,
        [:request_seal, :jose, :content_authentication],
        fn _, m, md, pid -> send(pid, {:content, m, md}) end,
        self()
      )

    on_exit(fn -> :telemetry.detach(id) end)
  end

  defp jws_policy(mode, resolver) do
    %{
      algorithms: ["RS256"],
      timeout: 5000,
      protected: %{expected: %{"typ" => "dpop+jwt"}, permitted: [], embedded_key: mode},
      key_resolver: resolver
    }
  end

  defp embedded_token(jwk) do
    v = fixture("rfc7515.json")["A.2"]
    h = IO.iodata_to_binary(:json.encode(%{"alg" => "RS256", "typ" => "dpop+jwt", "jwk" => jwk}))
    # Sign exact RFC 9449-shaped bytes with the published RFC 7515 private key.
    base = Support.b64(h) <> "." <> Support.b64("claims")

    {:ok, signature} =
      RequestSeal.Crypto.sign({:jws, "RS256"}, base, RequestSeal.JOSEVectors.rsa(v["key"]))

    base <> "." <> Support.b64(signature)
  end

  defp embedded_jwk, do: fixture("rfc7515.json")["A.2"]["key"] |> Map.take(~w(kty n e))

  test "2.7 published RFC 9449 figure 2 DPoP proof verifies with its own JWK" do
    # RFC 9449 §4.1 figure 2, RFC 8792 wrapping removed; no regenerated bytes.
    # https://www.rfc-editor.org/rfc/rfc9449.html#figure-2
    token =
      Enum.join([
        "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik",
        "VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR",
        "nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE",
        "QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj",
        "oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia",
        "WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg",
        "4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
      ])

    p = %{
      jws_policy(:require, fn %{embedded_key: %PublicKey{material: {:ec, "P-256", _}}} ->
        {:ok, %{algorithm: "ES256", key: :embedded}}
      end)
      | algorithms: ["ES256"]
    }

    assert {:ok, result} = JWS.verify(token, p)
    assert :json.decode(result.payload)["htm"] == "POST"
    error(JWS.verify(replace(token, 2, Support.b64(<<0::512>>)), p), :invalid_signature, :crypto)
  end

  test "2.7 RSA signature verifies only with its embedded public JWK" do
    p =
      jws_policy(:require, fn %{embedded_key: %PublicKey{}} ->
        {:ok, %{algorithm: "RS256", key: :embedded}}
      end)

    assert {:ok, %{payload: "claims"}} = JWS.verify(embedded_token(embedded_jwk()), p)
  end

  for shape <- [
        :missing,
        :not_object,
        :private,
        :extra,
        :missing_member,
        :bad_import,
        :oct,
        :x25519,
        :bad_ec,
        :bad_okp,
        :small_rsa
      ] do
    test "2.7 embedded #{shape} is invalid_header before resolver" do
      jwk = refused_jwk(unquote(shape))
      owner = self()

      p =
        jws_policy(:require, fn _ ->
          send(owner, :embedded_resolved)
          :error
        end)

      t = embedded_token(jwk)
      t = if unquote(shape) == :missing, do: mutate_header(t, &Map.delete(&1, "jwk")), else: t
      error(JWS.verify(t, p), :invalid_header)
      refute_receive :embedded_resolved
    end
  end

  for member <- ~w(d p q dp dq qi oth k kid use key_ops alg x5c) do
    test "2.7 embedded member #{member} is refused before resolution" do
      owner = self()

      p =
        jws_policy(:require, fn _ ->
          send(owner, :embedded_resolved)
          :error
        end)

      error(
        JWS.verify(embedded_token(Map.put(embedded_jwk(), unquote(member), "AA")), p),
        :invalid_header
      )

      refute_receive :embedded_resolved
    end
  end

  test "2.7 exact policy and protected key sets and explicit embedded mode" do
    p = jws_policy(:require, fn _ -> {:ok, %{algorithm: "RS256", key: :embedded}} end)
    t = embedded_token(embedded_jwk())
    for k <- Map.keys(p), do: error(JWS.verify(t, Map.delete(p, k)), :invalid_policy)

    for protected <- [
          Map.delete(p.protected, :embedded_key),
          Map.put(p.protected, :embedded_key, :allow),
          Map.put(p.protected, :extra, nil),
          %{p.protected | expected: %{"alg" => "RS256"}},
          %{p.protected | permitted: ["jwk"]},
          %{p.protected | expected: %{"typ" => "dpop+jwt"}, permitted: ["typ"]}
        ] do
      error(JWS.verify(t, %{p | protected: protected}), :invalid_policy)
    end
  end

  test "2.7 member then expectation then embedded shape precede resolution" do
    owner = self()

    p =
      jws_policy(:require, fn _ ->
        send(owner, :embedded_resolved)
        :error
      end)

    t = embedded_token(nil)
    error(JWS.verify(mutate_header(t, &Map.put(&1, "extra", 1)), p), :unexpected_member)
    error(JWS.verify(mutate_header(t, &Map.put(&1, "typ", "wrong")), p), :protected_mismatch)
    error(JWS.verify(t, p), :invalid_header)
    refute_receive :embedded_resolved
  end

  test "2.7 require refuses a verification handle even when it holds the embedded key" do
    v = fixture("rfc7515.json")["A.2"]
    {:ok, h} = Custody.Local.new({:jws, "RS256"}, RequestSeal.JOSEVectors.rsa(v["key"]))
    on_exit(fn -> Custody.release(h) end)
    p = jws_policy(:require, fn _ -> {:ok, %{algorithm: "RS256", key: h}} end)
    error(JWS.verify(embedded_token(embedded_jwk()), p), :key_resolver_failed, :key)
  end

  test "2.7 binding mismatch is algorithm_mismatch key after shape before resolver" do
    {pub, _} = :crypto.generate_key(:eddsa, :ed25519)
    jwk = %{"kty" => "OKP", "crv" => "Ed25519", "x" => Support.b64(pub)}
    owner = self()

    p =
      jws_policy(:require, fn _ ->
        send(owner, :embedded_resolved)
        :error
      end)

    error(JWS.verify(embedded_token(jwk), p), :algorithm_mismatch, :key)
    refute_receive :embedded_resolved
  end

  test "2.7 refuse mode refuses jwk and embedded sentinel and require refuses every other key" do
    t = embedded_token(embedded_jwk())
    resolver = fn _ -> {:ok, %{algorithm: "RS256", key: :embedded}} end
    error(JWS.verify(t, jws_policy(:refuse, resolver)), :unsupported_header)
    plain = mutate_header(t, &Map.delete(&1, "jwk"))
    error(JWS.verify(plain, jws_policy(:refuse, resolver)), :key_resolver_failed, :key)

    for key <- [RequestSeal.JOSEVectors.public(embedded_jwk()), fn _, _, _ -> :ok end, nil] do
      error(
        JWS.verify(t, jws_policy(:require, fn _ -> {:ok, %{algorithm: "RS256", key: key}} end)),
        :key_resolver_failed,
        :key
      )
    end
  end

  test "2.7 closure keys are refused and x5c requires explicit member policy" do
    t = fixture("rfc7515.json")["A.2"]["compact"]

    p = %{
      jws_policy(:refuse, fn _ -> {:ok, %{algorithm: "RS256", key: fn _, _, _ -> :ok end}} end)
      | protected: %{expected: %{}, permitted: [], embedded_key: :refuse}
    }

    error(JWS.verify(t, p), :key_resolver_failed, :key)
    t = mutate_header(t, &Map.put(&1, "x5c", ["uninterpreted"]))
    error(JWS.verify(t, p), :unexpected_member)
    owner = self()

    p = %{
      p
      | protected: %{p.protected | permitted: ["x5c"]},
        key_resolver: fn %{header: h} ->
          send(owner, {:chain, h["x5c"]})
          :error
        end
    }

    error(JWS.verify(t, p), :unknown_key, :key)
    assert_receive {:chain, ["uninterpreted"]}
  end

  defp continue_holder(_, :unwrap_timeout), do: :ok
  defp continue_holder(holder, _), do: send(holder, :continue)
  defp failure_mode(:refusal), do: :refuse
  defp failure_mode(:call_error), do: :error
  defp failure_mode(_), do: :all

  defp failure_token(token, failure) do
    case failure do
      :corrupt -> replace(token, 1, Support.b64(<<0::320>>))
      :truncated -> replace(token, 1, Support.b64(<<0::256>>))
      :overlong -> replace(token, 1, Support.b64(<<0::384>>))
      :tag -> replace(token, 4, Support.b64(<<0::128>>))
      _ -> token
    end
  end

  defp refused_jwk(shape) do
    case shape do
      :missing -> nil
      :not_object -> []
      :private -> Map.put(embedded_jwk(), "d", "AA")
      :extra -> Map.put(embedded_jwk(), "kid", "id")
      :missing_member -> Map.delete(embedded_jwk(), "e")
      :bad_import -> Map.put(embedded_jwk(), "n", "!")
      :oct -> %{"kty" => "oct", "k" => "AA"}
      :x25519 -> %{"kty" => "OKP", "crv" => "X25519", "x" => Support.b64(<<0::256>>)}
      :bad_ec -> %{"kty" => "EC", "crv" => "P-256", "x" => "AA", "y" => "AA"}
      :bad_okp -> %{"kty" => "OKP", "crv" => "Ed25519", "x" => "AA"}
      :small_rsa -> %{"kty" => "RSA", "n" => "AQ", "e" => "Aw"}
    end
  end
end
