defmodule RequestSeal.SignatureBasePropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties
  alias RequestSeal.{Crypto, Policy, SignatureBase}
  alias RequestSeal.PropertySupport, as: P
  @seed 9421
  @runs 300

  setup_all do: %{keys: P.keys(@seed)}

  property "generated component lists have deterministic bases and reject duplicates" do
    check all(
            value <- string(:alphanumeric, min_length: 1, max_length: 128),
            names <-
              map(
                list_of(member_of(["@method", "@path", "@authority", "x-covered"]),
                  min_length: 1,
                  max_length: 8
                ),
                &Enum.uniq/1
              ),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      message = P.message(value, "/" <> value)
      params = "(" <> Enum.map_join(names, " ", &inspect/1) <> ")"
      assert {:ok, base} = SignatureBase.build(message, params)
      assert SignatureBase.build(message, params) == {:ok, base}
      duplicate = "(" <> Enum.map_join(names ++ [hd(names)], " ", &inspect/1) <> ")"

      assert {:error, %SignatureBase.Error{reason: :duplicate_component}} =
               SignatureBase.build(message, duplicate)
    end
  end

  property "encoded targets, query parameters and structured field selections retain covered values" do
    check all(
            sample <- P.signature_case(),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      params = "(" <> Enum.join(sample.components, " ") <> ")"
      assert {:ok, base} = SignatureBase.build(sample.message, params, sample.options)
      assert SignatureBase.build(sample.message, params, sample.options) == {:ok, base}
      assert base =~ ~s["@path": #{hd(String.split(sample.target, "?"))}]
      assert base =~ ~s["@query-param";name="q": #{sample.query_value}]
      assert base =~ ~s["x-covered";sf: #{sample.dictionary}]
      assert base =~ ~s["x-covered";bs: :#{Base.encode64(sample.dictionary)}:]
      assert base =~ ~s["x-covered";key="#{sample.key}": #{sample.number}]
      duplicate = "(" <> Enum.join(sample.components ++ [hd(sample.components)], " ") <> ")"

      assert {:error, %SignatureBase.Error{reason: :duplicate_component}} =
               SignatureBase.build(sample.message, duplicate, sample.options)
    end
  end

  test "seeded asymmetric key material is reproducible and seed-specific" do
    assert P.keys(@seed) == P.keys(@seed)
    refute P.keys(@seed) == P.keys(@seed + 1)
  end

  property "newline-bearing covered values reject before a base is returned" do
    check all(
            value <- string(:alphanumeric, max_length: 100),
            newline <- member_of(["\r", "\n", "\r\n"]),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      m = P.message(value)
      [f] = m.fields

      assert {:error, %SignatureBase.Error{reason: :invalid_message}} =
               SignatureBase.build(
                 %{m | fields: [%{f | value: value <> newline}]},
                 ~s[("x-covered")]
               )
    end
  end

  property "Ed25519 and P-256 sign/verify round-trip and every covered byte rejects", %{
    keys: keys
  } do
    check all(
            value <- string(:alphanumeric, min_length: 1, max_length: 24),
            extras <- list_of(member_of(["@method", "@authority", "@scheme"]), max_length: 4),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      m = P.message(value, "/" <> value)
      names = Enum.uniq(extras ++ ["x-covered", "@path"])
      params = "(" <> Enum.map_join(names, " ", &inspect/1) <> ")"
      assert {:ok, base} = SignatureBase.build(m, params)

      for {algorithm, material, public} <- keys do
        assert {:ok, signature} = Crypto.sign(algorithm, base, material)
        assert :ok = Crypto.verify(algorithm, base, signature, public)
        signer = fn alg, bytes -> Crypto.sign(alg, bytes, material) end

        assert {:ok, signed} =
                 RequestSeal.sign(
                   m,
                   %{label: "sig", signature_input: params, algorithm: algorithm},
                   signer
                 )

        assert {:ok, policy} =
                 Policy.new(%{
                   algorithms: [algorithm],
                   components: params,
                   key_resolver: fn _ -> {:ok, %{algorithm: algorithm, key: public}} end,
                   freshness: :not_evaluated,
                   content: :not_required,
                   replay: :not_required
                 })

        assert {:ok, _} = RequestSeal.verify(signed, policy, label: "sig")

        for name <- names do
          covered =
            case name do
              "x-covered" -> value
              "@path" -> m.raw_target
              "@method" -> m.method
              "@authority" -> m.authority
              "@scheme" -> m.scheme
            end

          for i <- 0..(byte_size(covered) - 1) do
            changed = P.change(covered, i)

            mutated =
              case name do
                "x-covered" -> %{m | fields: [%{hd(m.fields) | value: changed}]}
                "@path" -> %{m | raw_target: changed}
                "@method" -> %{m | method: changed}
                "@authority" -> %{m | authority: changed}
                "@scheme" -> %{m | scheme: changed}
              end

            changed_signed = %{
              signed
              | raw_target: mutated.raw_target,
                method: mutated.method,
                authority: mutated.authority,
                scheme: mutated.scheme,
                fields:
                  Enum.map(signed.fields, fn f ->
                    if f.name == "x-covered", do: %{f | value: hd(mutated.fields).value}, else: f
                  end)
            }

            assert {:error, %RequestSeal.Error{}} =
                     RequestSeal.verify(changed_signed, policy, label: "sig")

            case SignatureBase.build(mutated, params) do
              {:ok, other_base} ->
                refute other_base == base

                assert {:error, %Crypto.Error{reason: :invalid_signature}} =
                         Crypto.verify(algorithm, other_base, signature, public)

              {:error, %SignatureBase.Error{}} ->
                :ok
            end
          end
        end
      end
    end
  end
end
