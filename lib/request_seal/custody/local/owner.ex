defmodule RequestSeal.Custody.Local.Owner do
  @moduledoc """
  Caller-supervised owner of Ed25519 signing handles.

  Add `{RequestSeal.Custody.Local.Owner, name: MyApp.Custody, keys: keys}` to
  your supervision tree. `start_link/1` documents the key sources and encodings;
  there is no guess-decoding.

  Files must be regular, not symbolic links, with mode 0600 or stricter (no
  execute, group, other, or special permission bits). Use `{:file, ...}` in
  production: environment seeds are inherited by OS child processes. Avoid `:raw`
  environment seeds; environment values cannot safely represent arbitrary binary
  data. Keep source paths and their parent directories under trusted control during startup.

  Bad keys do not prevent startup; `status/1` reports each key's bounded status.
  No signing capability is issued for a bad source.
  Key names, variable names, and paths are configuration, never seed values.

  The owner becomes sensitive before reading sources. Each decoded seed goes
  directly to `RequestSeal.Custody.Local.new/2`; only handles and bounded statuses
  remain in state. Holders monitor this owner, not the process calling `fetch/2`.
  Sources are read on every start and restart; environment variables are never
  deleted. Registration after startup is unsupported. Fetch per operation, or
  fetch again and retry once on custody `:key_not_found` after an owner restart.
  During restart, `:owner_unavailable` means wait for the supervised owner to
  become available before fetching again. A file that disappears or changes
  identity after its initial checks reports `:insecure_file`.
  Abnormal exits retain a bounded atom reason; private reason terms are discarded.
  Loading the library starts nothing.
  """
  use GenServer
  import Bitwise, only: [band: 2]
  alias RequestSeal.Custody.Local
  alias RequestSeal.KeyHandle

  @type encoding :: :base64url | :base64 | :hex | :raw
  @type source :: {:env | :file | :file_from_env, binary(), encoding()}
  @type key_status ::
          :ready | :unconfigured | {:error, :invalid_seed | :insecure_file | :unreadable}
  @type options :: [name: atom(), keys: [{atom(), {binary(), source()}}]]
  @max_source_bytes 4_096

  @doc """
  Build a child specification containing source descriptors, never loaded seeds.

  ## Parameters

    * `opts` - the same `:name` and `:keys` options as `start_link/1`.

  ## Returns

    * a `t:Supervisor.child_spec/0` map whose `:id` is `:name` (or this module
      when no name is given) and whose `:start` calls `start_link/1`. A key entry
      that is not a valid `{"ed25519", source}` descriptor is replaced by
      `:invalid_seed`, so the supervisor never retains it.

  Raises `ArgumentError` ("invalid custody owner options") when `opts` fails the
  checks that make `start_link/1` return `{:error, :invalid_options}`.

  ## Examples

      iex> keys = [builds: {"ed25519", {:file, "/etc/example/builds.key", :base64url}}]
      iex> RequestSeal.Custody.Local.Owner.child_spec(name: MyApp.Custody, keys: keys)
      %{
        id: MyApp.Custody,
        start: {RequestSeal.Custody.Local.Owner, :start_link, [[name: MyApp.Custody, keys: keys]]}
      }
      iex> RequestSeal.Custody.Local.Owner.child_spec(keys: [builds: {"rsa", {:env, "BUILD_KEY", :hex}}])
      %{
        id: RequestSeal.Custody.Local.Owner,
        start: {RequestSeal.Custody.Local.Owner, :start_link, [[name: nil, keys: [builds: :invalid_seed]]]}
      }
      iex> RequestSeal.Custody.Local.Owner.child_spec(keys: :none)
      ** (ArgumentError) invalid custody owner options
  """
  @spec child_spec(options()) :: Supervisor.child_spec()
  def child_spec(opts) do
    case options(opts) do
      {:ok, name, keys} ->
        %{id: name || __MODULE__, start: {__MODULE__, :start_link, [[name: name, keys: keys]]}}

      :error ->
        raise ArgumentError, "invalid custody owner options"
    end
  end

  @doc ~S"""
  Start a linked owner with a fixed set of source descriptors.

  Every source is read once during start (and again on each restart); each valid
  seed becomes one `RequestSeal.Custody.Local` handle owned by this process.

  ## Parameters

    * `opts` - keyword list; see Options. Unknown or duplicate options reject.

  ## Options

    * `:name` - optional atom used to register the owner (not `true` or `false`).
      Default: not registered.
    * `:keys` - required keyword list of `key_name: {"ed25519", source}` entries
      with unique atom key names. Sources:
      * `{:env, variable, encoding}` - the seed is the value of `variable`.
      * `{:file, path, encoding}` - the seed is the content of the file at `path`.
      * `{:file_from_env, variable, encoding}` - reads a file path from `variable`,
        then reads that file.

      Encodings are `:base64url` (padding optional), `:base64` (padded), `:hex`
      (either case), or `:raw`. Only ASCII space, tab, CR, and LF are trimmed from
      text encodings; raw bytes are unchanged. Base64 encodings must be canonical.
      Decoded seeds must be exactly 32 bytes. Source inputs are limited to 4,096
      bytes, including whitespace. An entry that is not of this shape does not
      stop startup; its status is `{:error, :invalid_seed}`.

  ## Returns

    * `{:ok, pid}` - the owner started, whatever the status of individual keys.
    * `{:error, :invalid_options}` - `opts` is not a keyword list, has an unknown
      or duplicate option, lacks a keyword-list `:keys`, repeats a key name, or
      has a `:name` that is not an atom or is a boolean.
    * any other `t:GenServer.on_start/0` result, such as
      `{:error, {:already_started, pid}}` when `:name` is taken.

  ## Examples

  A build signer reads its seed from a 0600 file. The file is created and
  restricted before the seed is written, then removed after the owner stops.

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> path = Path.join(System.tmp_dir!(), "request-seal-builds-#{System.unique_integer([:positive])}.key")
      iex> File.touch!(path)
      :ok
      iex> File.chmod!(path, 0o600)
      :ok
      iex> File.write!(path, Base.url_encode64(seed, padding: false) <> "\n")
      :ok
      iex> {:ok, owner} = RequestSeal.Custody.Local.Owner.start_link(keys: [builds: {"ed25519", {:file, path, :base64url}}])
      iex> RequestSeal.Custody.Local.Owner.status(owner)
      %{builds: :ready}
      iex> GenServer.stop(owner)
      :ok
      iex> File.rm!(path)
      :ok
      iex> RequestSeal.Custody.Local.Owner.start_link(keys: [builds: {"ed25519", {:file, path, :base64url}}], timeout: 1_000)
      {:error, :invalid_options}
  """
  @spec start_link(options()) :: GenServer.on_start()
  def start_link(opts) do
    case options(opts) do
      {:ok, name, keys} ->
        GenServer.start_link(__MODULE__, keys, if(name, do: [name: name], else: []))

      :error ->
        {:error, :invalid_options}
    end
  end

  @doc ~S"""
  Fetch a handle; distinguish an unconfigured key from an unavailable owner.

  The handle's holder is owned and monitored by the owner, not by the caller;
  do not release it unless the key should stay unavailable until the owner restarts.

  ## Parameters

    * `owner` - the owner's PID or registered name (`t:GenServer.server/0`).
    * `name` - the atom key name given in `:keys`.

  ## Returns

    * `{:ok, %RequestSeal.KeyHandle{}}` - an Ed25519 signing handle whose holder
      was alive when the owner replied.
    * `{:error, :unconfigured}` - the name is unknown, its source was missing,
      empty, or failed, or its holder has stopped.
    * `{:error, :owner_unavailable}` - the owner is stopped or did not reply
      within the default `GenServer.call/3` timeout.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> variable = "REQUEST_SEAL_DOC_SEED_#{System.unique_integer([:positive])}"
      iex> System.put_env(variable, Base.encode16(seed))
      :ok
      iex> {:ok, owner} = RequestSeal.Custody.Local.Owner.start_link(keys: [crawler: {"ed25519", {:env, variable, :hex}}])
      iex> System.delete_env(variable)
      :ok
      iex> {:ok, handle} = RequestSeal.Custody.Local.Owner.fetch(owner, :crawler)
      iex> {:ok, _signature} = RequestSeal.Custody.sign(handle, "GET https://www.example.org/robots.txt")
      iex> RequestSeal.Custody.Local.Owner.fetch(owner, :messaging)
      {:error, :unconfigured}
      iex> GenServer.stop(owner)
      :ok
      iex> RequestSeal.Custody.Local.Owner.fetch(owner, :crawler)
      {:error, :owner_unavailable}
  """
  @spec fetch(GenServer.server(), atom()) ::
          {:ok, KeyHandle.t()} | {:error, :unconfigured | :owner_unavailable}
  def fetch(owner, name) do
    GenServer.call(owner, {:fetch, name})
  catch
    :exit, _ -> {:error, :owner_unavailable}
  end

  @doc ~S"""
  Return each configured key's bounded status.

  ## Parameters

    * `owner` - the owner's PID or registered name (`t:GenServer.server/0`).

  ## Returns

    * a map from each configured key name to:
      * `:ready` - a handle is available.
      * `:unconfigured` - missing or empty variable, missing file, or stopped holder.
      * `{:error, :invalid_seed}` - the source decoded to no valid 32-byte seed,
        or the key entry was malformed.
      * `{:error, :insecure_file}` - the file is not a regular file with mode 0600
        or stricter, or it changed identity during reading.
      * `{:error, :unreadable}` - the source could not be read.
    * `{:error, :owner_unavailable}` - the owner is stopped or did not reply
      within the default `GenServer.call/3` timeout.

  ## Examples

      iex> unset = "REQUEST_SEAL_DOC_UNSET_#{System.unique_integer([:positive])}"
      iex> keys = [
      ...>   messaging: {"ed25519", {:env, unset, :base64url}},
      ...>   orders: {"ed25519", {:url, "https://keys.example.com/orders", :hex}}
      ...> ]
      iex> {:ok, owner} = RequestSeal.Custody.Local.Owner.start_link(keys: keys)
      iex> RequestSeal.Custody.Local.Owner.status(owner)
      %{messaging: :unconfigured, orders: {:error, :invalid_seed}}
      iex> GenServer.stop(owner)
      :ok
      iex> RequestSeal.Custody.Local.Owner.status(owner)
      {:error, :owner_unavailable}
  """
  @spec status(GenServer.server()) :: %{atom() => key_status()} | {:error, :owner_unavailable}
  def status(owner) do
    GenServer.call(owner, :status)
  catch
    :exit, _ -> {:error, :owner_unavailable}
  end

  @doc ~S"""
  Report whether a handle is available for the named key.

  Equivalent to `match?({:ok, _}, fetch(owner, name))`. Readiness is a snapshot;
  a holder can still stop between this call and a signing call.

  ## Parameters

    * `owner` - the owner's PID or registered name (`t:GenServer.server/0`).
    * `name` - the atom key name given in `:keys`.

  ## Returns

    * `true` - `fetch/2` would return a handle.
    * `false` - the key is unconfigured or the owner is unavailable.

  ## Examples

      iex> unset = "REQUEST_SEAL_DOC_UNSET_#{System.unique_integer([:positive])}"
      iex> {:ok, owner} = RequestSeal.Custody.Local.Owner.start_link(keys: [documents: {"ed25519", {:env, unset, :hex}}])
      iex> RequestSeal.Custody.Local.Owner.ready?(owner, :documents)
      false
      iex> GenServer.stop(owner)
      :ok
      iex> RequestSeal.Custody.Local.Owner.ready?(owner, :documents)
      false
  """
  @spec ready?(GenServer.server(), atom()) :: boolean()
  def ready?(owner, name), do: match?({:ok, _}, fetch(owner, name))

  @impl true
  def init(keys) do
    Process.flag(:sensitive, true)
    :proc_lib.set_label({__MODULE__, Keyword.keys(keys)})
    state = Map.new(keys, fn {name, source} -> {name, load_key(source)} end)
    {:ok, state, {:continue, :discard_sources}}
  end

  @impl true
  def handle_continue(:discard_sources, state) do
    :erlang.garbage_collect()
    {:noreply, state}
  end

  @impl true
  def handle_call({:fetch, name}, _from, state) do
    reply =
      case Map.get(state, name) do
        {:ok, handle} ->
          if holder_alive?(handle), do: {:ok, handle}, else: {:error, :unconfigured}

        _ ->
          {:error, :unconfigured}
      end

    {:reply, reply, state}
  end

  def handle_call(:status, _from, state), do: {:reply, statuses(state), state}
  def handle_call(_, _from, state), do: {:reply, {:error, :invalid_options}, state}

  @impl true
  def handle_cast(_, state), do: {:noreply, state}

  @impl true
  def handle_info(_, state), do: {:noreply, state}

  # OTP's crash report is separate from format_status/1. Sanitize the exit
  # itself so neither report nor a supervisor can retain private reason terms.
  @impl true
  def terminate(reason, _state) when reason in [:normal, :shutdown], do: :ok
  def terminate({:shutdown, _}, _state), do: exit(:shutdown)
  def terminate(reason, _state), do: exit(crash_reason(reason))

  defp crash_reason(reason) when reason in [:badarg, :badarith, :function_clause, :undef],
    do: reason

  defp crash_reason(_), do: :owner_failure

  @impl true
  def format_status(status) do
    Map.new(status, fn
      {:state, state} -> {:state, statuses(state)}
      {:reason, reason} -> {:reason, crash_reason(reason)}
      {key, _} when key in [:message, :log] -> {key, :redacted}
      pair -> pair
    end)
  end

  defp statuses(state) do
    Map.new(state, fn
      {name, {:ok, handle}} -> {name, if(holder_alive?(handle), do: :ready, else: :unconfigured)}
      pair -> pair
    end)
  end

  # Only this local custodian interprets its own holder reference. Readiness is
  # a snapshot; a holder can still stop between fetching and signing.
  defp holder_alive?(%KeyHandle{custodian: Local, ref: ref}) do
    {holder, _token} = ref.()
    Process.alive?(holder)
  end

  defp options(opts) do
    with true <- is_list(opts) and Keyword.keyword?(opts),
         true <- Enum.all?(Keyword.keys(opts), &(&1 in [:name, :keys])),
         true <- length(opts) == length(Keyword.keys(opts) |> Enum.uniq()),
         name = Keyword.get(opts, :name),
         true <- is_atom(name) and name not in [true, false],
         keys = Keyword.get(opts, :keys),
         true <- is_list(keys) and Keyword.keyword?(keys),
         true <- length(keys) == length(Keyword.keys(keys) |> Enum.uniq()) do
      {:ok, name, Enum.map(keys, fn {key, spec} -> {key, descriptor(spec)} end)}
    else
      _ -> :error
    end
  end

  # Sanitize rejected descriptors before they can be retained by a supervisor.
  defp descriptor({"ed25519", {kind, location, encoding}} = spec)
       when kind in [:env, :file, :file_from_env] and is_binary(location) and
              encoding in [:base64url, :base64, :hex, :raw],
       do: spec

  defp descriptor(_), do: :invalid_seed

  defp load_key({"ed25519", {kind, location, encoding}}) do
    with {:ok, input} <- read_source(kind, location),
         {:ok, seed} <- decode(input, encoding),
         {:ok, handle} <- Local.new("ed25519", {:ed25519, seed}) do
      {:ok, handle}
    else
      :unconfigured ->
        :unconfigured

      {:error, reason} when reason in [:invalid_seed, :insecure_file, :unreadable] ->
        {:error, reason}

      _ ->
        {:error, :invalid_seed}
    end
  rescue
    _ -> {:error, :unreadable}
  catch
    _, _ -> {:error, :unreadable}
  end

  defp load_key(_), do: {:error, :invalid_seed}

  defp read_source(:env, variable) do
    case System.fetch_env(variable) do
      {:ok, ""} -> :unconfigured
      {:ok, value} -> {:ok, value}
      :error -> :unconfigured
    end
  end

  defp read_source(:file_from_env, variable) do
    with {:ok, path} <- read_source(:env, variable), do: read_source(:file, path)
  end

  defp read_source(:file, path) do
    with {:ok, stat} <- File.lstat(path),
         :ok <- secure_file(stat) do
      read_existing_file(path, stat)
    end
    |> file_result()
  end

  defp read_existing_file(path, stat) do
    result =
      with {:ok, file} <- :file.open(path, [:read, :binary, :raw]) do
        try do
          read_file(file, path, stat)
        after
          :file.close(file)
        end
      end

    case result do
      {:error, :enoent} -> {:error, :insecure_file}
      other -> other
    end
  end

  defp read_file(file, path, before) do
    with {:ok, record} <- :file.read_file_info(file),
         opened = File.Stat.from_record(record),
         :ok <- secure_file(opened),
         true <- same_file?(before, opened),
         :ok <- check_current_file(path, opened),
         {:ok, bytes} <- read_bytes(file),
         :ok <- check_current_file(path, opened) do
      {:ok, bytes}
    else
      false -> {:error, :insecure_file}
      error -> error
    end
  end

  defp read_bytes(file) do
    case :file.read(file, @max_source_bytes + 1) do
      :eof -> {:ok, ""}
      result -> result
    end
  end

  defp check_current_file(path, opened) do
    with {:ok, current} <- File.lstat(path),
         :ok <- secure_file(current),
         true <- same_file?(opened, current) do
      :ok
    else
      false -> {:error, :insecure_file}
      error -> error
    end
  end

  defp same_file?(left, right),
    do:
      {left.major_device, left.minor_device, left.inode} ==
        {right.major_device, right.minor_device, right.inode}

  defp secure_file(%File.Stat{type: :regular, mode: mode}) when band(mode, 0o7177) == 0,
    do: :ok

  defp secure_file(_), do: {:error, :insecure_file}
  defp file_result({:error, :enoent}), do: :unconfigured
  defp file_result({:error, :insecure_file} = error), do: error
  defp file_result({:error, _}), do: {:error, :unreadable}
  defp file_result(result), do: result

  defp decode(input, encoding) when byte_size(input) <= @max_source_bytes do
    result =
      case encoding do
        :raw -> {:ok, input}
        :base64url -> decode_base64(trim_ascii(input), :base64url)
        :base64 -> decode_base64(trim_ascii(input), :base64)
        :hex -> Base.decode16(trim_ascii(input), case: :mixed)
      end

    case result do
      {:ok, seed} when byte_size(seed) == 32 -> {:ok, seed}
      _ -> {:error, :invalid_seed}
    end
  end

  defp decode(_, _), do: {:error, :invalid_seed}

  defp decode_base64(input, encoding) do
    {result, encode} =
      case encoding do
        :base64url -> {Base.url_decode64(input, padding: false), &Base.url_encode64/2}
        :base64 -> {Base.decode64(input), &Base.encode64/2}
      end

    with {:ok, bytes} <- result,
         true <-
           encode.(bytes, padding: encoding == :base64 or String.ends_with?(input, "=")) == input do
      {:ok, bytes}
    else
      _ -> :error
    end
  end

  defp trim_ascii(<<byte, rest::binary>>) when byte in [32, 9, 13, 10], do: trim_ascii(rest)
  defp trim_ascii(input), do: trim_ascii_end(input)
  defp trim_ascii_end(<<>>), do: <<>>

  defp trim_ascii_end(input) do
    if :binary.last(input) in [32, 9, 13, 10],
      do: trim_ascii_end(binary_part(input, 0, byte_size(input) - 1)),
      else: input
  end
end
