defmodule RequestSeal.JOSEPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties
  alias RequestSeal.JOSE.{Error, Header, JWE, JWS, Nested, Support}
  alias RequestSeal.PropertySupport, as: P
  @seed 7516
  @runs 300

  setup do
    ctx = P.jose(@seed)
    on_exit(fn -> if Process.alive?(ctx.owner), do: Agent.stop(ctx.owner) end)
    ctx
  end

  property "random and mutated compact strings return only typed results", ctx do
    check all(
            bytes <- binary(max_length: 2048),
            payload <- binary(min_length: 1, max_length: 64),
            index <- non_negative_integer(),
            mask <- integer(1..255),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      assert {:ok, signed} = JWS.sign([{"alg", "EdDSA"}], payload, ctx.signer)

      assert {:ok, encrypted} =
               JWE.encrypt([{"alg", "dir"}, {"enc", "A256GCM"}], payload, ctx.wrap)

      for input <- [bytes, P.change(signed, index, mask), P.change(encrypted, index, mask)],
          result <- [JWS.verify(input, ctx.jws), JWE.decrypt(input, ctx.jwe)] do
        case result do
          {:ok, _} -> :ok
          {:error, %Error{}} -> :ok
          other -> flunk("unexpected result: #{inspect(other)}")
        end
      end
    end
  end

  property "every single-byte change of a valid JWS and JWE is rejected", ctx do
    check all(
            payload <- binary(min_length: 1, max_length: 16),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      assert {:ok, signed} = JWS.sign([{"alg", "EdDSA"}], payload, ctx.signer)

      assert {:ok, encrypted} =
               JWE.encrypt([{"alg", "dir"}, {"enc", "A256GCM"}], payload, ctx.wrap)

      assert {:ok, _} = JWS.verify(signed, ctx.jws)
      assert {:ok, _} = JWE.decrypt(encrypted, ctx.jwe)

      for i <- 0..(byte_size(signed) - 1) do
        assert {:error, %Error{}} = JWS.verify(P.change(signed, i), ctx.jws)
      end

      for i <- 0..(byte_size(encrypted) - 1) do
        assert {:error, %Error{}} = JWE.decrypt(P.change(encrypted, i), ctx.jwe)
      end
    end
  end

  property "header bytes, members, arrays, depth and segment ceilings hold", ctx do
    check all(
            filler <- member_of([" ", "\t", "\r", "\n"]),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      for {kind, alg, enc, count} <- [{:jws, "EdDSA", nil, 3}, {:jwe, "dir", "A256GCM", 5}] do
        json =
          :json.encode(if enc, do: %{"alg" => alg, "enc" => enc}, else: %{"alg" => alg})
          |> IO.iodata_to_binary()

        good = json <> String.duplicate(filler, 16_384 - byte_size(json))
        assert {:ok, _} = Support.safe(fn -> {:ok, Header.parse(Support.b64(good))} end)

        assert {:error, %Error{reason: :limit}} =
                 Support.safe(fn -> Header.parse(Support.b64(good <> filler)) end)

        assert {:error, %Error{reason: :limit}} =
                 Support.safe(fn -> Header.json(good <> filler) end)

        pairs = [{"alg", alg}] ++ if(enc, do: [{"enc", enc}], else: [])
        pairs = pairs ++ Enum.map(1..(64 - length(pairs)), &{"x#{&1}", &1})
        assert {:ok, _} = Support.safe(fn -> {:ok, Header.from_pairs(pairs)} end)

        assert {:error, %Error{reason: :limit}} =
                 Support.safe(fn -> Header.from_pairs(pairs ++ [{"extra", 0}]) end)

        for n <- [64, 65] do
          raw =
            :json.encode(%{"alg" => alg, "x" => List.duplicate(0, n)}) |> IO.iodata_to_binary()

          if n == 64 do
            assert {:ok, _} = Support.safe(fn -> {:ok, Header.json(raw)} end)
          else
            assert {:error, %Error{reason: :limit}} = Support.safe(fn -> Header.json(raw) end)
          end
        end

        assert {:ok, _} =
                 Support.safe(fn -> {:ok, Header.json(~s({"alg":"#{alg}","x":[[[0]]]}))} end)

        assert {:error, %Error{reason: :limit}} =
                 Support.safe(fn -> Header.json(~s({"alg":"#{alg}","x":[[[[0]]]]})) end)

        token =
          if kind == :jws do
            {:ok, c} = JWS.sign_protected(good, "payload", ctx.signer)
            assert {:ok, _} = JWS.verify(c, ctx.jws)
            c
          else
            header = [{"alg", alg}, {"enc", enc}, {"padding", ""}]
            {wire, _} = Header.serialize(header)
            size = byte_size(Support.decode(wire))

            header =
              List.keyreplace(
                header,
                "padding",
                0,
                {"padding", String.duplicate("a", 16_384 - size)}
              )

            {:ok, c} = JWE.encrypt(header, "payload", ctx.wrap)
            assert {:ok, _} = JWE.decrypt(c, ctx.jwe)
            c
          end

        assert length(String.split(token, ".")) == count

        result =
          if kind == :jws,
            do: JWS.verify(token <> ".", ctx.jws),
            else: JWE.decrypt(token <> ".", ctx.jwe)

        assert {:error, %Error{reason: :invalid_serialization}} = result
      end
    end
  end

  test "compact byte ceiling accepts exactly the boundary and rejects one more" do
    for count <- [3, 5] do
      input =
        Enum.join(
          List.duplicate("a", count - 1) ++ [String.duplicate("a", 1_048_576 - 2 * (count - 1))],
          "."
        )

      assert byte_size(input) == 1_048_576
      assert Support.segment_count?(input, count)
      assert {:ok, _} = Support.safe(fn -> {:ok, Support.compact(input, count)} end)

      assert {:error, %Error{reason: :limit}} =
               Support.safe(fn -> Support.compact(input <> "a", count) end)
    end
  end

  test "segment count rejects oversized input before splitting" do
    Code.ensure_loaded!(Support)

    assert :erlang.trace_pattern(
             {Support, :segments, 3},
             [{:_, [], [{:message, {:const, :split}}]}],
             [:local]
           ) == 1

    on_exit(fn -> :erlang.trace_pattern({Support, :segments, 3}, false, [:local]) end)
    parent = self()

    for {input, expected, split?} <- [
          {"a.b.c", true, true},
          {String.duplicate("a", 1_048_577) <> ".b.c", false, false}
        ] do
      pid =
        spawn(fn ->
          receive do
            :go -> send(parent, {:result, self(), Support.segment_count?(input, 3)})
          end

          receive do
            :stop -> :ok
          end
        end)

      on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
      :erlang.trace(pid, true, [:call, {:tracer, self()}])
      send(pid, :go)
      assert_receive {:result, ^pid, ^expected}, 1_000
      ref = :erlang.trace_delivered(pid)
      assert_receive {:trace_delivered, ^pid, ^ref}, 1_000

      if split?,
        do: assert_received({:trace, ^pid, :call, {Support, :segments, _}, :split}),
        else: refute_received({:trace, ^pid, :call, {Support, :segments, _}, :split})

      send(pid, :stop)
    end
  end

  property "separator storms reject within a fixed parser-work budget" do
    check all(
            n <- integer(10_000..1_048_576),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      input = :binary.copy(".", n)

      for count <- [3, 5] do
        {:reductions, before} = Process.info(self(), :reductions)

        assert {:error, %Error{reason: :invalid_serialization}} =
                 Support.safe(fn -> Support.compact(input, count) end)

        {:reductions, after_count} = Process.info(self(), :reductions)
        assert after_count - before < 10_000
      end
    end
  end

  property "one JWS inside one JWE accepts and a third envelope rejects", ctx do
    check all(
            payload <- binary(min_length: 1, max_length: 32),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      assert {:ok, signed} = JWS.sign([{"alg", "EdDSA"}], payload, ctx.signer)

      assert {:ok, nested} =
               JWE.encrypt([{"alg", "dir"}, {"enc", "A256GCM"}, {"cty", "JWS"}], signed, ctx.wrap)

      assert {:ok, _} = Nested.verify(nested, ctx.jwe, ctx.jws, content_types: ["JWS"])

      assert {:ok, deeper} =
               JWE.encrypt([{"alg", "dir"}, {"enc", "A256GCM"}, {"cty", "JWS"}], nested, ctx.wrap)

      assert {:error, %Error{reason: :nesting_depth}} =
               Nested.verify(deeper, ctx.jwe, ctx.jws, content_types: ["JWS"])

      assert {:ok, storm} =
               JWE.encrypt(
                 [{"alg", "dir"}, {"enc", "A256GCM"}, {"cty", "JWS"}],
                 :binary.copy(".", 700_000),
                 ctx.wrap
               )

      assert {:error, %Error{reason: :nesting_depth}} =
               Nested.verify(storm, ctx.jwe, ctx.jws, content_types: ["JWS"])

      assert {:ok, signed} = JWS.sign([{"alg", "EdDSA"}, {"cty", "JWS"}], signed, ctx.signer)

      assert {:ok, deeper} =
               JWE.encrypt([{"alg", "dir"}, {"enc", "A256GCM"}, {"cty", "JWS"}], signed, ctx.wrap)

      assert {:error, %Error{reason: :nesting_depth}} =
               Nested.verify(deeper, ctx.jwe, ctx.jws, content_types: ["JWS"])
    end
  end
end
