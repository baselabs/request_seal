defmodule RequestSeal.AshConsumerTest do
  use ExUnit.Case, async: false

  @tag timeout: 600_000
  test "an offline consumer compiles and maps scopes with no Ash installed" do
    root = Path.expand("..", __DIR__)

    scratch =
      Path.join(
        System.tmp_dir!(),
        "request_seal_consumer_#{System.pid()}_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(scratch)
    on_exit(fn -> File.rm_rf!(scratch) end)

    # Known-positive: compile a real path dependency with an injected warning.
    # Mix may exit zero for dependency warnings despite the consumer's flag.
    warning_source = Path.join(scratch, "warning_source")
    File.mkdir_p!(warning_source)
    File.cp!(Path.join(root, "mix.exs"), Path.join(warning_source, "mix.exs"))
    File.cp_r!(Path.join(root, "lib"), Path.join(warning_source, "lib"))
    File.cp_r!(Path.join(root, "config"), Path.join(warning_source, "config"))

    File.write!(Path.join(warning_source, "lib/compiler_warning_probe.ex"), """
    defmodule RequestSeal.CompilerWarningProbe do
      def probe(unused_warning_canary), do: :ok
    end
    """)

    warning_consumer = Path.join(scratch, "warning_consumer")
    {mix, warning_env} = consumer(warning_consumer, warning_source)

    {warning_output, _status} =
      System.cmd(mix, ["compile", "--warnings-as-errors"],
        cd: warning_consumer,
        env: warning_env,
        stderr_to_stdout: true
      )

    assert warning_output =~ "unused_warning_canary", warning_output

    assert_raise ExUnit.AssertionError, fn ->
      refute warning_output =~ "warning:", warning_output
    end

    IO.puts("PASS: warning assertion rejected an injected path-dependency warning")
    File.rm_rf!(warning_consumer)
    File.rm_rf!(warning_source)

    {mix, env} = consumer(scratch, root)

    {output, status} =
      System.cmd(mix, ["compile", "--warnings-as-errors"],
        cd: scratch,
        env: env,
        stderr_to_stdout: true
      )

    assert status == 0, output
    refute output =~ "warning:", output

    probe = """
    #{inspect(System.version())} = System.version()
    #{inspect(System.otp_release())} = System.otp_release()
    false = Code.ensure_loaded?(Ash)
    true = Code.ensure_loaded?(RequestSeal)
    vector = :json.decode(File.read!(#{inspect(Path.join(root, "test/fixtures/verification/rfc9421.json"))})) |> Enum.find(&(&1["section"] == "B.2.3"))
    public = :json.decode(File.read!(#{inspect(Path.join(root, "test/fixtures/signature_base/rfc9421.json"))})) |> Enum.find(&(&1["section"] == "B.2.3")) |> Map.fetch!("message")
    {:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ~s[{"hello": "world"}]})
    {:ok, transport} = RequestSeal.TransportFacts.new(%{})
    wire_fields = public["fields"] ++ [["Signature-Input", vector["signature_input"]], ["Signature", vector["signature"]]]
    fields = for [name, value] <- wire_fields do
      {:ok, field} = RequestSeal.FieldOccurrence.new(%{name: name, value: value, section: :headers, provenance: :caller})
      field
    end
    {:ok, message} = RequestSeal.Message.new(%{kind: :request, method: public["method"], raw_target: public["raw_target"], target_form: :origin, scheme: public["scheme"], authority: public["authority"], fields: fields, body: body, transport: transport, trailers: :unavailable})
    {:ok, key} = RequestSeal.PublicKey.import(File.read!(#{inspect(Path.join(root, "test/fixtures/crypto/rsa_pss_public.pem"))}), :pem)
    {:ok, policy} = RequestSeal.Policy.new(%{algorithms: [vector["algorithm"]], components: "()", key_resolver: fn _ -> {:ok, %{algorithm: vector["algorithm"], key: key}} end, content: :not_required, freshness: :not_evaluated, replay: :not_required})
    {:ok, verification} = RequestSeal.verify(message, policy, label: vector["label"])
    {:ok, scope} = RequestSeal.Ash.scope(verification, %{actor: fn _ -> :error end, unattributed: :anonymous, tenant: :none})
    [actor: nil, tenant: nil, context: %{request_seal: %{principal: :unattributed}}, authorize?: true] = RequestSeal.Ash.Scope.to_opts(scope)
    false = Code.ensure_loaded?(Ash)
    IO.puts("PASS: framework-free consumer verified published bytes and mapped scope")
    """

    {output, status} =
      System.cmd(mix, ["run", "-e", probe], cd: scratch, env: env, stderr_to_stdout: true)

    assert status == 0, output
    assert output =~ "PASS: framework-free consumer"
    refute File.dir?(Path.join(scratch, "deps/ash"))
  end

  defp consumer(scratch, root) do
    File.mkdir_p!(scratch)

    File.write!(Path.join(scratch, "mix.exs"), """
    defmodule Consumer.MixProject do
      use Mix.Project
      def project, do: [app: :consumer, version: "0.0.0", deps: [{:request_seal, path: #{inspect(root)}}]]
      def application, do: [extra_applications: [:crypto]]
    end
    """)

    elixir_bin = :code.lib_dir(:elixir) |> to_string() |> Path.join("../../bin") |> Path.expand()
    otp_bin = :code.root_dir() |> to_string() |> Path.join("bin")

    {Path.join(elixir_bin, "mix"),
     [
       {"PATH", Enum.join([elixir_bin, otp_bin, System.fetch_env!("PATH")], ":")},
       {"MIX_ENV", "prod"},
       {"MIX_BUILD_PATH", Path.join(scratch, "_build")},
       {"MIX_DEPS_PATH", Path.join(scratch, "deps")},
       {"HEX_OFFLINE", "1"}
     ]}
  end
end
