defmodule RequestSeal.CustodyLocalOwnerTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  alias RequestSeal.Custody
  alias RequestSeal.Custody.Local
  alias RequestSeal.Custody.Local.Owner

  # Canary only; never a deployment key or external conformance claim.
  @seed "owner-canary-32-byte-secret-123!"
  @encodings [:base64url, :base64, :hex, :raw]

  setup do
    dir = Path.join(System.tmp_dir!(), "request-seal-owner-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    %{dir: dir}
  end

  test "a fetched handle outlives its fetching process", c do
    path = seed_file(c.dir, "key", @seed)
    owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, :raw}}]})
    parent = self()

    {pid, monitor} =
      spawn_monitor(fn -> send(parent, {:fetched, Owner.fetch(owner, :signing)}) end)

    assert_receive {:fetched, {:ok, handle}}
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}
    assert_signs(handle)
    assert Owner.ready?(owner, :signing)
    refute Owner.ready?(owner, :unknown)
    assert {:error, :unconfigured} = Owner.fetch(owner, :unknown)
  end

  test "released holders are unavailable through every Owner query", c do
    path = seed_file(c.dir, "released", @seed)
    owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, :raw}}]})
    assert {:ok, handle} = Owner.fetch(owner, :signing)
    assert :ok = Local.release(handle)
    assert {:error, %Custody.Error{reason: :key_not_found}} = Custody.sign(handle, "bytes")
    assert Owner.status(owner) == %{signing: :unconfigured}
    refute Owner.ready?(owner, :signing)
    assert {:error, :unconfigured} = Owner.fetch(owner, :signing)
  end

  test "supervised restart retires cached handles and rereads every source", c do
    var = env("RESTART", Base.encode64(@seed))
    path = seed_file(c.dir, "direct", @seed)
    indirect = seed_file(c.dir, "indirect", Base.encode16(@seed))
    path_var = env("PATH", indirect)

    keys = [
      direct: {"ed25519", {:file, path, :raw}},
      indirect: {"ed25519", {:file_from_env, path_var, :hex}},
      environment: {"ed25519", {:env, var, :base64}}
    ]

    owner = start_supervised!({Owner, name: __MODULE__.Restart, keys: keys})

    old =
      Map.new(keys, fn {name, _} ->
        {:ok, handle} = Owner.fetch(owner, name)
        {name, handle}
      end)

    monitors =
      Enum.map(old, fn {_, handle} ->
        {pid, _} = handle.ref.()
        {pid, Process.monitor(pid)}
      end)

    # Change all sources before restart, proving restart reads again.
    {_public, next_seed} = :crypto.generate_key(:eddsa, :ed25519)
    File.write!(path, next_seed)
    next_path = seed_file(c.dir, "rotated", Base.encode16(next_seed))
    System.put_env(path_var, next_path)
    System.put_env(var, Base.encode64(next_seed))
    owner_monitor = Process.monitor(owner)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :killed}

    for {pid, monitor} <- monitors do
      assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 5_000
    end

    fresh = restarted_owner!(owner)
    assert Owner.status(fresh) == %{direct: :ready, indirect: :ready, environment: :ready}

    for {name, cached} <- old do
      assert {:error, %Custody.Error{reason: :key_not_found}} = Custody.sign(cached, "bytes")
      assert {:ok, handle} = Owner.fetch(fresh, name)
      assert_signs(handle)
      assert {:ok, public} = Custody.public_key(handle)
      {expected, _} = :crypto.generate_key(:eddsa, :ed25519, next_seed)
      assert public.material == {:ed25519, expected}
    end

    assert System.get_env(var) == Base.encode64(next_seed)
  end

  test "canary stays out of state, inspection, child specs, status and failure logs", c do
    assert byte_size(@seed) == 32
    strings = Enum.map(@encodings, &encode(@seed, &1))

    keys =
      Enum.map(@encodings, fn encoding ->
        path = seed_file(c.dir, Atom.to_string(encoding), encode(@seed, encoding))
        {encoding, {"ed25519", {:file, path, encoding}}}
      end)

    child = Owner.child_spec(keys: keys)
    owner = start_supervised!(child)
    parent = self()

    :sys.replace_state(owner, fn state ->
      send(parent, {:already_sensitive, Process.flag(:sensitive, true)})
      state
    end)

    assert_received {:already_sensitive, true}
    assert Enum.all?(Owner.status(owner), fn {_, status} -> status == :ready end)

    surfaces = [
      inspect(child),
      inspect(Owner.status(owner)),
      inspect(:sys.get_state(owner)),
      inspect(:sys.get_status(owner))
      | Enum.map(@encodings, fn encoding ->
          assert {:ok, handle} = result = Owner.fetch(owner, encoding)
          assert_signs(handle)
          inspect(result)
        end)
    ]

    # A real decoding failure includes the whole canary in each input. The log
    # mutation in Owner's rejection path must make this assertion fail.
    log =
      capture_log(fn ->
        bad =
          Enum.map(@encodings, fn encoding ->
            assert String.contains?(invalid_input(encoding), encode(@seed, encoding))
            path = seed_file(c.dir, "bad-#{encoding}", invalid_input(encoding))
            {encoding, {"ed25519", {:file, path, encoding}}}
          end)

        rejected = start_supervised!({Owner, keys: bad}, id: :rejected)

        for encoding <- @encodings do
          assert Owner.status(rejected)[encoding] == {:error, :invalid_seed}
          assert {:error, :unconfigured} = Owner.fetch(rejected, encoding)
        end
      end)

    for value <- strings, surface <- [log | surfaces] do
      refute String.contains?(surface, value), "seed canary leaked"
    end
  end

  test "terminate and crash reports redact seeds while retaining key and atom reason", c do
    strings = Enum.map(@encodings, &encode(@seed, &1))

    keys =
      Enum.map(@encodings, fn encoding ->
        path = seed_file(c.dir, "crash-#{encoding}", encode(@seed, encoding))
        {encoding, {"ed25519", {:file, path, encoding}}}
      end)

    bad = seed_file(c.dir, "crash-failed", invalid_input(:base64))

    {:ok, owner} =
      Owner.start_link(keys: [{:failing_key, {"ed25519", {:file, bad, :base64}}} | keys])

    Process.unlink(owner)
    parent = self()

    filter = fn
      %{meta: %{pid: ^owner}, msg: {:report, report}}, _ ->
        send(parent, {:owner_report, report})
        :ignore

      _, _ ->
        :ignore
    end

    :ok = :logger.add_primary_filter(:request_seal_owner_reports, {filter, nil})

    try do
      log =
        capture_log(fn ->
          try do
            GenServer.stop(owner, {:owner_failure, strings})
          catch
            :exit, _ -> :ok
          end
        end)

      assert_receive {:owner_report, %{label: {:gen_server, :terminate}} = termination}
      assert_receive {:owner_report, %{label: {:proc_lib, :crash}} = crash}

      for value <- strings,
          surface <- [
            log,
            inspect(termination, limit: :infinity, printable_limit: :infinity),
            inspect(crash, limit: :infinity, printable_limit: :infinity)
          ] do
        refute String.contains?(surface, value), "seed canary leaked in crash diagnostics"
      end

      assert {Owner, names} = Keyword.fetch!(hd(crash.report), :process_label)
      assert :failing_key in names
      assert termination.state.failing_key == {:error, :invalid_seed}
      assert {:owner_failure, stacktrace} = termination.reason
      assert is_list(stacktrace)
      assert [{:exit, :owner_failure, _}] = for({:error_info, info} <- hd(crash.report), do: info)
      assert log =~ "failing_key"
      assert log =~ "owner_failure"
    after
      :logger.remove_primary_filter(:request_seal_owner_reports)
      if Process.alive?(owner), do: GenServer.stop(owner)
    end
  end

  test "source errors are per-key, bounded and fail closed", c do
    valid = seed_file(c.dir, "valid", @seed)
    insecure = seed_file(c.dir, "insecure", @seed, 0o644)
    link = Path.join(c.dir, "link")
    File.ln_s!(valid, link)
    missing = env("MISSING", nil)
    wrong = env("WRONG_TAG", Base.encode64(@seed))
    long = seed_file(c.dir, "long", @seed <> "!")

    keys = [
      valid: {"ed25519", {:file, valid, :raw}},
      insecure: {"ed25519", {:file, insecure, :raw}},
      symlink: {"ed25519", {:file, link, :raw}},
      missing_var: {"ed25519", {:env, missing, :raw}},
      missing_path_var: {"ed25519", {:file_from_env, missing, :raw}},
      missing_file: {"ed25519", {:file, Path.join(c.dir, "absent"), :raw}},
      wrong_tag: {"ed25519", {:env, wrong, :hex}},
      long: {"ed25519", {:file, long, :raw}},
      directory: {"ed25519", {:file, c.dir, :raw}},
      invalid_encoding: {"ed25519", {:file, valid, :guess}},
      literal: {"ed25519", {:literal, @seed}},
      invalid_algorithm: {"rsa-v1_5-sha256", {:file, valid, :raw}}
    ]

    owner = start_supervised!({Owner, keys: keys})
    refute inspect(Owner.child_spec(keys: keys)) =~ @seed

    assert Owner.status(owner) == %{
             valid: :ready,
             insecure: {:error, :insecure_file},
             symlink: {:error, :insecure_file},
             directory: {:error, :insecure_file},
             missing_var: :unconfigured,
             missing_path_var: :unconfigured,
             missing_file: :unconfigured,
             wrong_tag: {:error, :invalid_seed},
             long: {:error, :invalid_seed},
             invalid_encoding: {:error, :invalid_seed},
             literal: {:error, :invalid_seed},
             invalid_algorithm: {:error, :invalid_seed}
           }

    for {name, _} <- keys, name != :valid do
      refute Owner.ready?(owner, name)
      assert {:error, :unconfigured} = Owner.fetch(owner, name)
    end

    assert {:ok, handle} = Owner.fetch(owner, :valid)
    assert_signs(handle)

    assert {:error, :invalid_options} =
             GenServer.call(owner, {:register, :later, {:file, valid, :raw}})

    assert {:error, :unconfigured} = Owner.fetch(owner, :later)
  end

  test "all tagged sources decode real seeds, trim text only and accept stricter files", c do
    for encoding <- @encodings do
      wire = encode(@seed, encoding)
      input = if encoding == :raw, do: wire, else: " \t" <> wire <> "\r\n"
      path = seed_file(c.dir, "trim-#{encoding}", input, 0o400)
      var = env("SEED_#{encoding}", input)
      path_var = env("FILE_#{encoding}", path)

      keys = [
        environment: {"ed25519", {:env, var, encoding}},
        file: {"ed25519", {:file, path, encoding}},
        indirect: {"ed25519", {:file_from_env, path_var, encoding}}
      ]

      owner = start_supervised!({Owner, keys: keys}, id: encoding)
      assert Owner.status(owner) == %{environment: :ready, file: :ready, indirect: :ready}

      for {name, _} <- keys do
        assert {:ok, handle} = Owner.fetch(owner, name)
        assert_signs(handle)
      end

      assert System.get_env(var) == input
    end
  end

  @tag skip: elem(System.cmd("id", ["-u"]), 0) |> String.trim() == "0"
  test "mode 000 cannot be read by an unprivileged owner", c do
    path = seed_file(c.dir, "unreadable", @seed, 0o000)
    owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, :raw}}]})
    assert Owner.status(owner) == %{signing: {:error, :unreadable}}
  end

  test "stopped Owner differs from a bad key", c do
    path = seed_file(c.dir, "stopped", @seed)
    owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, :raw}}]})
    stop_supervised!(Owner)
    assert Owner.fetch(owner, :signing) == {:error, :owner_unavailable}
    refute Owner.ready?(owner, :signing)
    assert Owner.status(owner) == {:error, :owner_unavailable}
  end

  test "busy Owner times out consistently on real blocked calls", c do
    path = seed_file(c.dir, "busy", @seed)
    owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, :raw}}]})
    :ok = :sys.suspend(owner)

    try do
      tasks =
        Enum.map(
          [
            fn -> Owner.fetch(owner, :signing) end,
            fn -> Owner.ready?(owner, :signing) end,
            fn -> query_status(owner) end
          ],
          &Task.async/1
        )

      results = Enum.map(tasks, &Task.await(&1, 7_000))
      assert results == [{:error, :owner_unavailable}, false, {:error, :owner_unavailable}]
    after
      :sys.resume(owner)
    end
  end

  test "empty environment values and indirect paths are unconfigured" do
    var = env("EMPTY", "")

    owner =
      start_supervised!(
        {Owner,
         keys: [
           seed: {"ed25519", {:env, var, :base64url}},
           path: {"ed25519", {:file_from_env, var, :base64url}}
         ]}
      )

    assert Owner.status(owner) == %{seed: :unconfigured, path: :unconfigured}
  end

  test "source is sensitive at its first real file metadata read", c do
    path = seed_file(c.dir, "sensitivity", @seed)
    # Known-positive control: the same observer sees a nonsensitive reader.
    control = observe_file(path, 1, false)

    try do
      assert {:ok, _} = File.lstat(path)
      reader = self()
      assert_receive {:source_read, ^reader, {:sensitive, false}}
    after
      :sys.remove(:file_server_2, control)
    end

    observer = observe_file(path, 1, false)

    try do
      owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, :raw}}]})
      assert_receive {:source_read, ^owner, {:sensitive, true}}
      assert Owner.ready?(owner, :signing)
    after
      :sys.remove(:file_server_2, observer)
    end
  end

  for step <- [1, 2], action <- [:unlink, :replace] do
    @tag read_step: step, action: action
    test "file #{action} after metadata check #{step} is insecure", c do
      path = seed_file(c.dir, "race", @seed)
      replacement = seed_file(c.dir, "replacement", @seed)
      observer = observe_file(path, c.read_step, true)

      task =
        Task.async(fn -> Owner.start_link(keys: [signing: {"ed25519", {:file, path, :raw}}]) end)

      try do
        assert_receive {:source_read, owner, {:sensitive, true}}
        assert_receive {:source_checked, ^owner}, 1_000

        assert :ok =
                 if(c.action == :unlink,
                   do: :prim_file.delete(path),
                   else: :prim_file.rename(replacement, path)
                 )

        send(Process.whereis(:file_server_2), {:resume_owner, owner})
        assert {:ok, ^owner} = Task.await(task)

        try do
          assert Owner.status(owner) == %{signing: {:error, :insecure_file}}
          assert Owner.fetch(owner, :signing) == {:error, :unconfigured}
        after
          GenServer.stop(owner)
        end
      after
        :sys.remove(:file_server_2, observer)
      end
    end
  end

  test "padded Base64url remains accepted", c do
    path = seed_file(c.dir, "padded", Base.url_encode64(@seed))
    owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, :base64url}}]})
    assert {:ok, handle} = Owner.fetch(owner, :signing)
    assert_signs(handle)
  end

  for {name, encoding, input} <- [
        {:unpadded_base64, :base64, Base.encode64(@seed, padding: false)},
        {:base64url_alphabet, :base64, Base.url_encode64(:binary.copy(<<255>>, 32))},
        {:base64_alphabet, :base64url, Base.encode64(:binary.copy(<<255>>, 32))},
        {:odd_hex, :hex, Base.encode16(@seed) <> "0"},
        {:interior_space, :base64url,
         String.replace_prefix(Base.url_encode64(@seed, padding: false), "b3", "b 3")},
        {:interior_tab, :base64, "b3d\t" <> binary_part(Base.encode64(@seed), 3, 41)},
        {:interior_hex_space, :hex, "6f " <> binary_part(Base.encode16(@seed), 2, 62)}
      ] do
    @tag encoding: encoding, input: input
    test "decoder rejects #{name}", c do
      assert_invalid_source(c.dir, c.input, c.encoding)
    end
  end

  for encoding <- [:base64url, :base64], tail <- ["F", "G", "H"] do
    @tag encoding: encoding, tail: tail
    test "decoder rejects noncanonical #{encoding} tail #{tail}", c do
      # 32 zero bytes ending in 1: canonical final sextet is E.
      canonical = encode(<<0::248, 1>>, c.encoding)
      input = String.replace(canonical, "E", c.tail)
      assert_invalid_source(c.dir, input, c.encoding)
    end
  end

  for encoding <- [:base64url, :base64, :hex],
      whitespace <- ["\u00a0", "\u2028", "\u0085", "\v", "\f"] do
    @tag encoding: encoding, whitespace: whitespace
    test "decoder rejects non-ASCII trim #{encoding} #{inspect(whitespace)}", c do
      assert_invalid_source(
        c.dir,
        c.whitespace <> encode(@seed, c.encoding) <> c.whitespace,
        c.encoding
      )
    end
  end

  defp assert_invalid_source(dir, input, encoding) do
    path = seed_file(dir, "invalid", input)
    owner = start_supervised!({Owner, keys: [signing: {"ed25519", {:file, path, encoding}}]})
    assert Owner.status(owner) == %{signing: {:error, :invalid_seed}}
    assert Owner.fetch(owner, :signing) == {:error, :unconfigured}
  end

  # Observe the real OTP file server, suspending only the Owner across the chosen
  # metadata result. The file operation itself is never replaced or simulated.
  defp observe_file(path, step, suspend?) do
    parent = self()

    observer = fn
      {count, nil}, {:in, {:"$gen_call", {pid, _} = from, {:read_link_info, ^path, _}}}, _ ->
        if count + 1 == step do
          observe_reader(pid, parent, suspend?)
          {count + 1, from}
        else
          {count + 1, nil}
        end

      {count, from}, {:out, {:ok, _}, from, _}, _ when from != nil ->
        pid = elem(from, 0)
        send(parent, {:source_checked, pid})

        if suspend?, do: resume_reader(pid, parent)

        {count, nil}

      state, _, _ ->
        state
    end

    :ok = :sys.install(:file_server_2, {observer, observer, {0, nil}})
    observer
  end

  defp observe_reader(pid, parent, suspend?) do
    :erlang.suspend_process(pid)
    probe = {:sensitivity_probe, make_ref()}
    send(pid, probe)
    {:messages, messages} = Process.info(pid, :messages)
    send(parent, {:source_read, pid, {:sensitive, probe not in messages}})
    unless suspend?, do: :erlang.resume_process(pid)
  end

  defp resume_reader(pid, parent) do
    receive do
      {:resume_owner, ^pid} -> :ok
    after
      5_000 -> send(parent, :file_observer_timeout)
    end

    :erlang.resume_process(pid)
  end

  defp query_status(owner) do
    Owner.status(owner)
  catch
    :exit, reason -> {:exit, reason}
  end

  defp invalid_input(:raw), do: @seed <> "!"
  defp invalid_input(encoding), do: encode(@seed, encoding) <> "!"

  defp encode(seed, :base64url), do: Base.url_encode64(seed, padding: false)
  defp encode(seed, :base64), do: Base.encode64(seed)
  defp encode(seed, :hex), do: Base.encode16(seed, case: :lower)
  defp encode(seed, :raw), do: seed

  defp seed_file(dir, name, bytes, mode \\ 0o600) do
    path = Path.join(dir, name)
    File.write!(path, bytes)
    File.chmod!(path, mode)
    path
  end

  defp env(suffix, value) do
    var = "REQUEST_SEAL_OWNER_TEST_#{suffix}_#{System.unique_integer([:positive])}"
    before = System.fetch_env(var)
    if value == nil, do: System.delete_env(var), else: System.put_env(var, value)

    on_exit(fn ->
      case before do
        :error -> System.delete_env(var)
        {:ok, old} -> System.put_env(var, old)
      end

      assert System.fetch_env(var) == before
    end)

    var
  end

  defp assert_signs(handle) do
    assert {:ok, signature} = Custody.sign(handle, "exact bytes")
    assert :ok = Custody.verify(handle, "exact bytes", signature)

    assert {:error, %Custody.Error{reason: :invalid_signature}} =
             Custody.verify(handle, "changed bytes", signature)
  end

  defp restarted_owner!(previous, attempts \\ 100)
  defp restarted_owner!(_, 0), do: flunk("supervisor did not restart Owner")

  defp restarted_owner!(previous, attempts) do
    case Process.whereis(__MODULE__.Restart) do
      pid when is_pid(pid) and pid != previous ->
        pid

      _ ->
        Process.sleep(10)
        restarted_owner!(previous, attempts - 1)
    end
  end
end
