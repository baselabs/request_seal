# Run with MIX_ENV=test mix run bench/ceilings.exs. Inputs use public RFC grammars;
# locally generated keys measure implementations, not external conformance.
defmodule RequestSeal.Ceilings do
  alias RequestSeal.{FieldOccurrence, SignatureBase}
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.PropertySupport, as: P
  alias RequestSeal.JOSE.{Header, JWE, JWS, KeyManagement, Support}
  @samples 100

  def run do
    {machine, 0} = System.cmd("uname", ["-sm"])

    cpu =
      if :os.type() == {:unix, :darwin} do
        case System.cmd("sysctl", ["-n", "machdep.cpu.brand_string"], stderr_to_stdout: true) do
          {cpu, 0} -> String.trim(cpu)
          {_, _} -> "not exposed by sandbox"
        end
      else
        File.read!("/proc/cpuinfo")
        |> String.split("\n")
        |> Enum.find(&String.starts_with?(&1, "model name"))
      end

    otp_version =
      File.read!(
        Path.join([to_string(:code.root_dir()), "releases", System.otp_release(), "OTP_VERSION"])
      )
      |> String.trim()

    IO.puts(
      "machine=#{String.trim(machine)} cpu=#{cpu} OTP=#{otp_version} ERTS=#{:erlang.system_info(:version)} Elixir=#{System.version()} word_bytes=#{:erlang.system_info(:wordsize)} samples=#{@samples}"
    )

    IO.puts(
      "units: time=microseconds; reductions=current parser process; nearest-rank p50/p99; GC before each parser sample; 10 warmups; worst=highest observed candidate p99"
    )

    sf()
    signature()
    jose()
    discovery()
    oaep()
  end

  defp measure(parser, cases) do
    results =
      for {name, ceiling, fun} <- cases do
        for _ <- 1..10, do: fun.()

        samples =
          for _ <- 1..@samples do
            :erlang.garbage_collect()
            {:reductions, before} = Process.info(self(), :reductions)
            {us, _} = :timer.tc(fun)
            {:reductions, after_count} = Process.info(self(), :reductions)
            {us, after_count - before}
          end

        time = Enum.map(samples, &elem(&1, 0))
        reductions = Enum.map(samples, &elem(&1, 1))

        IO.puts(
          "#{parser} candidate=#{name} ceiling=#{ceiling} n=#{@samples} time_p50=#{quantile(time, 0.5)} time_p99=#{quantile(time, 0.99)} time_max=#{Enum.max(time)} reductions_p50=#{quantile(reductions, 0.5)} reductions_p99=#{quantile(reductions, 0.99)} reductions_max=#{Enum.max(reductions)}"
        )

        {quantile(time, 0.99), name}
      end

    {_, worst} = Enum.max(results)
    IO.puts("#{parser} worst_observed_candidate=#{worst}")
  end

  defp sf do
    dictionary =
      Enum.map_join(1..1024, ",", fn i -> "k#{i}" <> String.duplicate("a", 50) <> "=a" end)

    nodes = Enum.join(List.duplicate("a;p;q;r", 1023) ++ ["a;p;q"], ",")

    cases = [
      {"bytes", :list, "a" <> String.duplicate(" ", 65_535), "bytes:65536"},
      {"dictionary", :dictionary, pad(dictionary, 65_536), "bytes:65536,members:1024"},
      {"nodes", :list, nodes, "nodes:4096"},
      {"parameters", :item, "a" <> Enum.map_join(1..256, "", &";p#{&1}"), "parameters:256"},
      {"inner_items", :list, "(" <> Enum.join(List.duplicate("a", 256), " ") <> ")",
       "inner_items:256,depth:3"},
      {"value", :item, "\"" <> String.duplicate("a", 16_384) <> "\"", "value_bytes:16384"}
    ]

    measure(
      "StructuredFields",
      for {name, type, bytes, ceiling} <- cases do
        schema = P.schema(type)
        {:ok, _} = SF.parse(bytes, schema)
        {name, ceiling, fn -> {:ok, _} = SF.parse(bytes, schema) end}
      end
    )
  end

  defp signature do
    fields =
      for i <- 1..256 do
        {:ok, f} =
          FieldOccurrence.new(%{
            name: "x#{i}",
            value: String.duplicate("a", 4000),
            section: :headers
          })

        f
      end

    message = %{P.message("a") | fields: fields}
    params = "(" <> Enum.map_join(fields, " ", &inspect(&1.name)) <> ")"
    {:ok, base} = SignatureBase.build(message, params)
    [first | rest] = fields

    message = %{
      message
      | fields: [
          %{first | value: first.value <> String.duplicate("a", 1_048_576 - byte_size(base))}
          | rest
        ]
    }

    {:ok, base} = SignatureBase.build(message, params)
    1_048_576 = byte_size(base)
    query = Enum.map_join(1..256, "&", &"k#{&1}=#{String.duplicate("a", 50)}")
    query_message = P.message("a", "/?" <> query)
    query_params = "(" <> Enum.map_join(1..256, " ", &~s("@query-param";name="k#{&1}")) <> ")"

    measure("SignatureBase", [
      {"base", "bytes:1048576,components:256",
       fn -> {:ok, _} = SignatureBase.build(message, params) end},
      {"query", "components:256",
       fn -> {:ok, _} = SignatureBase.build(query_message, query_params) end}
    ])
  end

  defp jose do
    ctx = P.jose()

    try do
      header = pad(~s({"alg":"EdDSA","x":[[[0]]]}), 16_384)
      # Select the largest payload fitting the compact ceiling under Base64url's
      # 4/3 expansion, with a protected header exactly at its own ceiling.
      {:ok, small} = JWS.sign_protected(header, "a", ctx.signer)
      fixed = byte_size(small) - byte_size(Support.b64("a"))
      payload = String.duplicate("a", div((1_048_576 - fixed) * 3, 4))
      {:ok, signed} = JWS.sign_protected(header, payload, ctx.signer)
      {:ok, _} = JWS.verify(signed, ctx.jws)

      jwe_header = [{"alg", "dir"}, {"enc", "A256GCM"}, {"x", [[[0]]]}, {"padding", ""}]
      {wire, _} = Header.serialize(jwe_header)
      decoded_size = byte_size(Support.decode(wire))

      jwe_header =
        List.keyreplace(
          jwe_header,
          "padding",
          0,
          {"padding", String.duplicate("a", 16_384 - decoded_size)}
        )

      {wire, _} = Header.serialize(jwe_header)
      16_384 = byte_size(Support.decode(wire))
      {:ok, small} = JWE.encrypt(jwe_header, "a", ctx.wrap)
      fixed = byte_size(small) - byte_size(Support.b64("a"))
      plaintext = String.duplicate("a", div((1_048_576 - fixed) * 3, 4))
      {:ok, encrypted} = JWE.encrypt(jwe_header, plaintext, ctx.wrap)
      {:ok, _} = JWE.decrypt(encrypted, ctx.jwe)
      storm = :binary.copy(".", 1_048_576)
      whitespace = :binary.copy(" ", 1_048_576)

      for {name, token, count} <- [{"JOSE.JWS", signed, 3}, {"JOSE.JWE", encrypted, 5}] do
        measure(name, [
          {"compact", "compact_bytes:#{byte_size(token)},header_bytes:16384,depth:4",
           fn -> parse_compact(token, count) end},
          {"separator_storm", "compact_bytes:1048576,segments:over-limit",
           fn ->
             {:error, _} = Support.safe(fn -> Support.compact(storm, count) end)
           end},
          {"whitespace_storm", "compact_bytes:1048576,segments:under-limit",
           fn ->
             {:error, _} = Support.safe(fn -> Support.compact(whitespace, count) end)
           end}
        ])
      end

      members =
        Map.new(1..63, &{"k#{&1}", 0})
        |> Map.put("alg", "EdDSA")
        |> :json.encode()
        |> IO.iodata_to_binary()

      measure("JOSE.Header", [
        {"bytes_depth", "bytes:16384,depth:4",
         fn -> {:ok, _} = Support.safe(fn -> {:ok, Header.json(header)} end) end},
        {"members", "members:64",
         fn -> {:ok, _} = Support.safe(fn -> {:ok, Header.json(members)} end) end}
      ])
    after
      Agent.stop(ctx.owner)
    end
  end

  defp parse_compact(token, count) do
    {:ok, _} =
      Support.safe(fn ->
        [protected | rest] = Support.compact(token, count)
        Header.parse(protected)
        Enum.each(rest, &Support.decode/1)
        {:ok, :parsed}
      end)
  end

  defp discovery do
    base = P.jwks(32)
    body = pad(base, 65_536)
    nested = Enum.reduce(1..31, 0, fn _, inner -> [inner] end)

    adversarial =
      :json.decode(base) |> Map.put("depth", nested) |> Map.put("array", List.duplicate(0, 256))

    adversarial =
      Enum.reduce(1..253, adversarial, fn i, doc ->
        Map.put(doc, "member#{i}", String.duplicate("a", 150))
      end)

    structured = :json.encode(adversarial) |> IO.iodata_to_binary() |> pad(65_536)

    for type <- [:jwks_uri, :directory] do
      source = P.source(type)

      measure(
        "Discovery.#{type}",
        for {name, input, ceiling} <- [
              {"body_keys", body, "bytes:65536,keys:32"},
              {"json_shape", structured, "bytes:65536,keys:32,members:256,array:256,depth:32"}
            ] do
          {name, ceiling,
           fn ->
             {:ok, keys} = RequestSeal.Discovery.parse_body(input, source, 100)
             32 = map_size(keys)
           end}
        end
      )
    end
  end

  defp oaep do
    key = :public_key.generate_key({:rsa, 2048, 65537})
    {:ok, public} = RequestSeal.PublicKey.import({:rsa, elem(key, 2), elem(key, 3)}, :raw)

    for algorithm <- ["RSA-OAEP", "RSA-OAEP-256"] do
      {:ok, valid} =
        JWE.encrypt([{"alg", algorithm}, {"enc", "A256GCM"}], "timing measurement", public)

      policy = %{
        algorithms: [algorithm],
        encryption: ["A256GCM"],
        max_plaintext: 1024,
        timeout: 5000,
        key_resolver: fn _ ->
          {:ok,
           %{
             algorithm: algorithm,
             unwrap: fn ek, h -> KeyManagement.unwrap(algorithm, ek, h, {:rsa, key}) end
           }}
        end
      }

      [protected, ek, iv, ct, tag] = String.split(valid, ".")
      # Recover the real encoded message and re-encrypt each corrupted byte
      # with raw RSA, preserving modulus-width ciphertext for every failure.
      encoded = :public_key.decrypt_private(Support.decode(ek), key, rsa_padding: :rsa_no_padding)

      <<0, _::binary>> = encoded

      corruptions =
        Map.new([leading_zero: 0, masked_seed: 1, padding: 200], fn {name, index} ->
          corrupted =
            :public_key.encrypt_public(
              P.change(encoded, index),
              {:RSAPublicKey, elem(key, 2), elem(key, 3)},
              rsa_padding: :rsa_no_padding
            )

          {:error, _} = KeyManagement.unwrap(algorithm, corrupted, %{}, {:rsa, key})
          {name, Enum.join([protected, Support.b64(corrupted), iv, ct, tag], ".")}
        end)

      bad_tag =
        Enum.join([protected, ek, iv, ct, Support.b64(P.change(Support.decode(tag), 0))], ".")

      tokens = Map.merge(corruptions, %{valid: valid, tag: bad_tag})
      names = [:valid, :leading_zero, :masked_seed, :padding, :tag]
      failures = [:leading_zero, :masked_seed, :padding, :tag]
      results = Map.new(tokens, fn {name, token} -> {name, JWE.decrypt(token, policy)} end)
      {:ok, _} = results.valid
      {:error, padding_error} = results.padding

      errors =
        Enum.map(failures, fn name ->
          {:error, error} = results[name]
          error
        end)

      errors_equal = length(Enum.uniq(errors)) == 1
      failure_results_equal = failures |> Enum.map(&results[&1]) |> Enum.uniq() |> length() == 1
      all_results_equal = results |> Map.values() |> Enum.uniq() |> length() == 1
      true = errors_equal and failure_results_equal
      for _ <- 1..30, {_name, token} <- tokens, do: JWE.decrypt(token, policy)
      # Rotate order every sample to avoid measuring order/thermal drift as an oracle.
      samples =
        Enum.reduce(0..999, Map.new(names, &{&1, []}), fn i, acc ->
          order =
            Enum.drop(names, rem(i, length(names))) ++ Enum.take(names, rem(i, length(names)))

          Enum.reduce(order, acc, fn name, acc ->
            {us, result} = :timer.tc(fn -> JWE.decrypt(tokens[name], policy) end)

            case {name, result} do
              {:valid, {:ok, _}} -> :ok
              {_, {:error, ^padding_error}} -> :ok
            end

            Map.update!(acc, name, &[us | &1])
          end)
        end)

      for name <- names do
        times = samples[name]

        IO.puts(
          "OAEP algorithm=#{algorithm} case=#{name} n=1000 time_p50=#{quantile(times, 0.5)} time_p99=#{quantile(times, 0.99)} time_min=#{Enum.min(times)} time_max=#{Enum.max(times)}"
        )
      end

      # Pairwise rank probability is an empirical effect size. A deterministic
      # paired bootstrap yields a 99% interval without altering crypto RNG.
      # The OR of the two unadjusted criteria has no joint 99% confidence claim.
      for corruption <- [:leading_zero, :masked_seed, :padding], comparison <- [:valid, :tag] do
        a = samples[corruption] |> Enum.reverse()
        b = samples[comparison] |> Enum.reverse()
        effect = rank_probability(a, b)
        :rand.seed(:exsss, {7516, 1000, 29})

        bootstrap =
          for _ <- 1..1000 do
            indices = for _ <- 1..1000, do: :rand.uniform(1000) - 1
            tuple_a = List.to_tuple(a)
            tuple_b = List.to_tuple(b)
            deltas = Enum.map(indices, &(elem(tuple_a, &1) - elem(tuple_b, &1)))
            Enum.sum(deltas) / 1000
          end

        lo = quantile(bootstrap, 0.005)
        hi = quantile(bootstrap, 0.995)

        ks = ks_distance(a, b)
        critical = 1.63 * :math.sqrt(2 / 1000)

        conclusion =
          if lo > 0 or hi < 0 or ks > critical,
            do: "timing_separation_detected_by_unadjusted_criteria",
            else: "no_timing_separation_detected_by_unadjusted_criteria"

        IO.puts(
          "OAEP algorithm=#{algorithm} case=#{corruption} versus=#{comparison} rank_probability=#{Float.round(effect, 4)} ks=#{Float.round(ks, 4)} ks_99critical=#{Float.round(critical, 4)} paired_mean_delta_us_99ci=[#{Float.round(lo, 3)},#{Float.round(hi, 3)}] conclusion=#{conclusion}"
        )
      end

      IO.puts(
        "OAEP algorithm=#{algorithm} caller_failures=#{inspect(Map.take(results, failures))} errors_equal=#{errors_equal} failure_results_equal=#{failure_results_equal} all_results_equal=#{all_results_equal}"
      )
    end
  end

  defp ks_distance(a, b) do
    fa = Enum.frequencies(a)
    fb = Enum.frequencies(b)
    values = Enum.sort(Enum.uniq(a ++ b))

    {_, _, maximum} =
      Enum.reduce(values, {0, 0, 0.0}, fn x, {ca, cb, maximum} ->
        ca = ca + Map.get(fa, x, 0)
        cb = cb + Map.get(fb, x, 0)
        {ca, cb, max(maximum, abs(ca / length(a) - cb / length(b)))}
      end)

    maximum
  end

  defp rank_probability(a, b) do
    Enum.reduce(a, 0.0, fn x, sum ->
      sum +
        Enum.reduce(b, 0.0, fn y, n ->
          n +
            cond do
              x > y -> 1
              x == y -> 0.5
              true -> 0
            end
        end)
    end) / (length(a) * length(b))
  end

  defp quantile(values, p),
    do: values |> Enum.sort() |> Enum.at(max(ceil(length(values) * p) - 1, 0))

  defp pad(bytes, n), do: bytes <> String.duplicate(" ", n - byte_size(bytes))
end

RequestSeal.Ceilings.run()
