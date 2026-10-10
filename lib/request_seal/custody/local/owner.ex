defmodule RequestSeal.Custody.Local.Owner do
  @moduledoc """
  Caller-supervised owner of Ed25519 signing handles.

  Add `{RequestSeal.Custody.Local.Owner, name: MyApp.Custody, keys: keys}` to
  your supervision tree. `keys` is a keyword list of
  `name: {"ed25519", source}` entries. Sources are `{:env, variable, encoding}`,
  `{:file, path, encoding}`, or `{:file_from_env, variable, encoding}`; the last
  reads a file path from the variable. Encodings are `:base64url` (padding optional),
  `:base64` (padded), `:hex` (either case), or `:raw`. Only ASCII space, tab, CR,
  and LF are trimmed from text encodings; raw bytes are unchanged. Base64
  encodings must be canonical. Decoded seeds must be exactly 32 bytes. Source
  inputs are limited to 4,096 bytes, including whitespace. There is no guess-decoding.

  Files must be regular, not symbolic links, with mode 0600 or stricter (no
  execute, group, other, or special permission bits). Use `{:file, ...}` in
  production: environment seeds are inherited by OS child processes. Avoid `:raw`
  environment seeds; environment values cannot safely represent arbitrary binary
  data. Keep source paths and their parent directories under trusted control during startup.

  Bad keys do not prevent startup. `status/1` reports `:ready`, `:unconfigured`
  (missing or empty variable, missing file, or stopped holder), or `{:error, reason}`
  with `:invalid_seed`, `:insecure_file`, or `:unreadable`. `fetch/2` returns `{:error, :unconfigured}`
  for a missing or failed key. Calls to a stopped or busy owner return
  `{:error, :owner_unavailable}` from `fetch/2` and `status/1`; `ready?/2` is false.
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

  @doc "Build a child specification containing source descriptors, never loaded seeds."
  @spec child_spec(options()) :: Supervisor.child_spec()
  def child_spec(opts) do
    case options(opts) do
      {:ok, name, keys} ->
        %{id: name || __MODULE__, start: {__MODULE__, :start_link, [[name: name, keys: keys]]}}

      :error ->
        raise ArgumentError, "invalid custody owner options"
    end
  end

  @doc "Start a linked owner with a fixed set of source descriptors."
  @spec start_link(options()) :: GenServer.on_start()
  def start_link(opts) do
    case options(opts) do
      {:ok, name, keys} ->
        GenServer.start_link(__MODULE__, keys, if(name, do: [name: name], else: []))

      :error ->
        {:error, :invalid_options}
    end
  end

  @doc "Fetch a handle; distinguish an unconfigured key from an unavailable owner."
  @spec fetch(GenServer.server(), atom()) ::
          {:ok, KeyHandle.t()} | {:error, :unconfigured | :owner_unavailable}
  def fetch(owner, name) do
    GenServer.call(owner, {:fetch, name})
  catch
    :exit, _ -> {:error, :owner_unavailable}
  end

  @doc "Return each configured key's bounded status."
  @spec status(GenServer.server()) :: %{atom() => key_status()} | {:error, :owner_unavailable}
  def status(owner) do
    GenServer.call(owner, :status)
  catch
    :exit, _ -> {:error, :owner_unavailable}
  end

  @doc "Report whether a handle is available for the named key."
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
