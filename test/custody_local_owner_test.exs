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
            path = seed_file(c.dir, "bad-#{encoding}", encode(@seed <> "!", encoding))
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

  test "source errors are per-key, bounded and fail closed", c do
    valid = seed_file(c.dir, "valid", @seed)
    insecure = seed_file(c.dir, "insecure", @seed, 0o644)
    unreadable = seed_file(c.dir, "unreadable", @seed, 0o000)
    link = Path.join(c.dir, "link")
    File.ln_s!(valid, link)
    missing = env("MISSING", nil)
    wrong = env("WRONG_TAG", Base.encode64(@seed))
    long = seed_file(c.dir, "long", @seed <> "!")

    keys = [
      valid: {"ed25519", {:file, valid, :raw}},
      insecure: {"ed25519", {:file, insecure, :raw}},
      unreadable: {"ed25519", {:file, unreadable, :raw}},
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
             unreadable: {:error, :unreadable},
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
