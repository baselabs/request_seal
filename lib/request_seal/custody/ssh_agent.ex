defmodule RequestSeal.Custody.SSHAgent do
  @moduledoc """
  Non-exporting signing through a caller-selected OpenSSH agent Unix socket.

  Protocol: [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html) (formerly
  draft-miller-ssh-agent; identity listing and signing, Sections 5.5 and 5.6),
  [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709.html),
  [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332.html), and
  [RFC 5656](https://www.rfc-editor.org/rfc/rfc5656.html).

  `new/4` binds a trusted public key to an explicit socket path and proves
  possession before returning a handle. It never reads `SSH_AUTH_SOCK`, starts
  an agent, loads keys, or accesses private files. The caller owns agent access and
  authorization. An OpenSSH agent is a separate process, not an HSM guarantee.

  A sensitive process retains the algorithm, socket, public key and optional
  purpose. It controls workers that open sockets and return only operation
  results. It ends on creator exit or `RequestSeal.Custody.release/1`.
  `RequestSeal.Custody.binding/2` checks live agent membership.

  `new/4` lists the supported algorithms; RSA PKCS #1 v1.5 SHA-256 signing uses
  agent flag 2.
  Each sign uses one new connection; replies cannot spill into another operation.
  Identity lists are bounded to 256 keys, receive frames to 1,048,576 bytes, key blobs and
  comments to 16,384 bytes. Selection uses exact public components, never a comment
  or key ID. ECDSA mpints convert to fixed-width r || s, and every returned signature
  must verify with `Crypto` before release. Verification uses the trusted public
  key locally; it does not assert current agent possession or authorization.

  Outgoing request frames have no library bound beyond the `max_bytes:` option of
  `RequestSeal.Custody.sign/3`. [OpenSSH caps the whole agent message at 256 KiB](https://github.com/openssh/openssh-portable/blob/V_9_9_P1/ssh-agent.c),
  including protocol overhead, so payloads slightly under 262,144 bytes are the
  practical limit. Observed with OpenSSH 9.9 and Ed25519: 262,000 bytes signed
  successfully; 262,200 returned `:custodian_protocol`. A larger `max_bytes:`
  does not raise the agent's limit.

  Removed keys during signing yield `:key_not_found`. Connect and pre-send connection failures yield
  retryable `:custodian_unavailable`. After a request is written, a closed
  connection, short frame, or malformed reply yields nonretryable
  `:custodian_protocol`; deadline expiry yields `:deadline_exceeded`.
  Deadline or caller death closes the worker's connection. No logs or telemetry
  contain the path, references, comments, bases, or signatures.
  """
  @behaviour RequestSeal.Custody
  alias RequestSeal.{Crypto, Custody, KeyHandle, KeyIdentity, PublicKey}
  alias RequestSeal.Crypto.Algorithm
  alias RequestSeal.Custody.{Context, Support}
  alias RequestSeal.Custody.SSHAgent.Wire
  import Support, only: [fail: 1, ensure: 2, unwrap: 1]
  @max_bytes_ceiling Crypto.max_bytes_ceiling()

  @doc """
  Bind a supported algorithm, explicit socket, and trusted public key after a real possession check.

  Construction proves possession by asking the agent to sign empty bytes and
  checking the returned signature against `public`. The returned handle has
  capabilities `[:sign, :verify]`; each later signature first confirms the key is
  still listed by the agent.

  ## Parameters

    * `algorithm` - `"ed25519"`, `"rsa-v1_5-sha256"`, `"ecdsa-p256-sha256"`,
      `"ecdsa-p384-sha384"`, or `{:jws, name}` with `name` one of `"EdDSA"`,
      `"RS256"`, `"ES256"`, or `"ES384"`. PSS and HMAC reject.
    * `socket_path` - an absolute agent socket path of 1–103 bytes with no NUL byte.
    * `public` - the trusted `t:RequestSeal.PublicKey.t/0` of the agent key; it
      must fit `algorithm`, and any JWK restrictions must permit verification
      with it.
    * `opts` - keyword list; see Options.

  ## Options

    * `:timeout` - deadline in milliseconds for the possession check, integer
      1–300,000. Default `5_000`.
    * `:issued_for` - application purpose atom or nil. Default nil.

  ## Returns

    * `{:ok, %RequestSeal.KeyHandle{}}` - a signing and verification handle.
    * `{:error, %RequestSeal.Custody.Error{}}` - reasons this function can return:
      `:invalid_options` (unknown, duplicate, or out-of-range option, or an
      invalid `socket_path`), `:unsupported_algorithm`, `:invalid_key` (`public`
      fails validation), `:key_mismatch` (`public` does not fit `algorithm` or its
      restrictions), `:custodian_unavailable` (no socket, refused, or closed before
      the request), `:custodian_rejected` (the agent does not hold the key, refuses,
      or returns a signature that fails verification), `:custodian_protocol`
      (malformed, short, or oversized reply, or a connection closed after the
      request), `:deadline_exceeded`, and
      `:custodian_failure`. Meanings: `RequestSeal.Custody.Error`.

  ## Examples

  Algorithm and path checks run before any agent connection:

      iex> {public, _seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, key} = RequestSeal.PublicKey.import({:ed25519, public}, :raw)
      iex> RequestSeal.Custody.SSHAgent.new("hmac-sha256", "/run/agent.sock", key)
      {:error, %RequestSeal.Custody.Error{reason: :unsupported_algorithm, retryable: false}}
      iex> RequestSeal.Custody.SSHAgent.new("ed25519", "agent.sock", key)
      {:error, %RequestSeal.Custody.Error{reason: :invalid_options, retryable: false}}
      iex> RequestSeal.Custody.SSHAgent.new("ecdsa-p256-sha256", "/run/agent.sock", key)
      {:error, %RequestSeal.Custody.Error{reason: :key_mismatch, retryable: false}}

  Fragment (requires a running OpenSSH agent holding the Ed25519 key; not executed here):

      {:ok, key} = RequestSeal.PublicKey.import(trusted_public_key_pem, :pem)
      {:ok, handle} = RequestSeal.Custody.SSHAgent.new("ed25519", "/run/user/1000/agent.sock", key, timeout: 2_000)
      {:ok, signature} = RequestSeal.Custody.sign(handle, "deploy build 9134 to staging.example.com")
      :ok = RequestSeal.Custody.verify(handle, "deploy build 9134 to staging.example.com", signature)
  """
  @spec new(Crypto.algorithm(), binary(), PublicKey.t(), keyword()) ::
          {:ok, KeyHandle.t()} | {:error, RequestSeal.Custody.Error.t()}
  def new(algorithm, socket_path, public, opts \\ []) do
    Support.safe(fn ->
      timeout = Support.timeout(opts, [:timeout, :issued_for])
      issued_for = Keyword.get(opts, :issued_for)
      ensure(KeyHandle.purpose?(issued_for), :invalid_options)
      {jose, _} = resolved = Algorithm.resolve(algorithm)
      ensure(jose in ~w(EdDSA RS256 ES256 ES384), :unsupported_algorithm)

      ensure(
        is_binary(socket_path) and byte_size(socket_path) in 1..103 and
          String.starts_with?(socket_path, "/") and not String.contains?(socket_path, <<0>>),
        :invalid_options
      )

      PublicKey.bind!(public, resolved)
      context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}
      Custody.run(context, fn -> sign_at(socket_path, public, algorithm, "", false, context) end)
      |> unwrap()

      {:ok,
       %KeyHandle{
         custodian: __MODULE__,
         algorithm: algorithm,
         capabilities: [:sign, :verify],
         issued_for: issued_for,
         operation_family: KeyHandle.family(algorithm),
         ref: retain({algorithm, socket_path, public, issued_for})
       }}
    end)
  end

  defp retain(state) do
    owner = self()
    token = make_ref()

    pid =
      spawn(fn ->
        Process.flag(:sensitive, true)
        Process.flag(:trap_exit, true)
        loop(Process.monitor(owner), token, state)
      end)

    address({pid, token})
  end

  defp loop(owner, token, state) do
    receive do
      {:DOWN, ^owner, :process, _, _} ->
        :ok

      {:release, ^token} ->
        :ok

      {:request, ^token, requester, %Context{deadline: deadline, owner: caller} = context,
       operation, reply}
      when is_pid(requester) and node(requester) == node() and is_pid(caller) and
             is_integer(deadline) and is_reference(reply) ->
        if not Process.alive?(requester) or
             perform(owner, token, requester, context, operation, reply, state) == :continue,
           do: loop(owner, token, state)

      _ ->
        loop(owner, token, state)
    end
  end

  defp perform(owner, token, requester, context, operation, reply, state) do
    requester_ref = Process.monitor(requester)
    caller_ref = Process.monitor(context.owner)
    holder = self()
    completed = make_ref()

    {worker, worker_ref} =
      :erlang.spawn_opt(
        fn ->
          Process.flag(:sensitive, true)
          result = Support.safe(fn -> retained_operation(operation, state, context) end)
          send(holder, {completed, result})
        end,
        [:link, :monitor]
      )

    try do
      receive do
        {^completed, result} ->
          send(reply, {reply, result})
          :continue

        {:EXIT, ^worker, _} ->
          send(reply, {reply, {:error, :custodian_failure}})
          :continue

        {:DOWN, ^requester_ref, :process, _, _} ->
          :continue

        {:DOWN, ^caller_ref, :process, _, _} ->
          :continue

        {:DOWN, ^owner, :process, _, _} ->
          :stop

        {:release, ^token} ->
          :stop
      after
        Context.remaining(context) -> :continue
      end
    after
      Process.unlink(worker)
      Process.exit(worker, :kill)

      receive do
        {:DOWN, ^worker_ref, :process, ^worker, _} -> :ok
      end

      Process.demonitor(requester_ref, [:flush])
      Process.demonitor(caller_ref, [:flush])
    end
  end

  # Compare the constructor's closure identity without calling a replacement.
  # Its environment contains only the address of the custodian's retained state.
  defp address(value), do: fn -> value end

  defp address!(ref) when is_function(ref, 0) do
    case :erlang.fun_info(ref, :env) do
      {:env, [{pid, token} = value]} when is_pid(pid) and is_reference(token) ->
        ensure(ref === address(value), :invalid_handle)
        value

      _ ->
        fail(:invalid_handle)
    end
  end

  defp address!(_), do: fail(:invalid_handle)

  defp request(ref, context, operation) do
    {pid, token} = address!(ref)
    monitor = Process.monitor(pid)
    reply = :erlang.alias()

    try do
      send(pid, {:request, token, self(), context, operation, reply})

      receive do
        {^reply, result} ->
          ensure(Context.remaining(context) > 0, :deadline_exceeded)
          result

        {:DOWN, ^monitor, :process, ^pid, _} ->
          fail(:key_not_found)
      after
        Context.remaining(context) -> fail(:deadline_exceeded)
      end
    after
      :erlang.unalias(reply)
      Process.demonitor(monitor, [:flush])
    end
  end

  defp lookup_context do
    %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}
  end

  @impl true
  def release(ref, context) do
    {pid, token} = address!(ref)
    monitor = Process.monitor(pid)

    try do
      send(pid, {:release, token})

      receive do
        {:DOWN, ^monitor, :process, ^pid, _} -> :ok
      after
        Context.remaining(context) -> {:error, :deadline_exceeded}
      end
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  @impl true
  def sign(ref, algorithm, bytes, context)
      when is_binary(bytes) and byte_size(bytes) <= @max_bytes_ceiling,
      do: request(ref, context, {:sign, algorithm, bytes})

  def sign(_, _, _, _), do: {:error, :invalid_data}

  defp sign_at(socket_path, public, algorithm, bytes, check, context) do
    blob = Wire.key_blob(public)
    {:ok, socket} = connect(socket_path, context)

    try do
      if check do
        identities = exchange(socket, <<11>>, context) |> Wire.identities() |> unwrap()
        ensure(blob in identities, :key_not_found)
      end

      {jose, _} = Algorithm.resolve(algorithm)
      flags = if jose == "RS256", do: 2, else: 0

      reply =
        exchange(
          socket,
          <<13>> <> Wire.string(blob) <> Wire.string(bytes) <> <<flags::32>>,
          context
        )

      Wire.signature(reply, algorithm, bytes, public)
    after
      :gen_tcp.close(socket)
    end
  end

  @impl true
  def verify(ref, algorithm, bytes, signature, context)
      when is_binary(bytes) and byte_size(bytes) <= @max_bytes_ceiling,
      do: request(ref, context, {:verify, algorithm, bytes, signature})

  def verify(_, _, _, _, _), do: {:error, :invalid_data}

  @impl true
  def public_key(ref), do: request(ref, lookup_context(), :public_key)

  @impl true
  def identity(ref), do: request(ref, lookup_context(), :identity)

  @impl true
  def signing_assignment(ref, context), do: request(ref, context, :signing_assignment)

  @impl true
  def binding(ref, context), do: request(ref, context, :binding)

  defp retained_operation(operation, state, context) do
    remaining!(context)
    ensure(Process.alive?(context.owner), :custodian_failure)
    operate(operation, state, context)
  end

  defp operate(:public_key, {_, _, public, _}, _context), do: {:ok, public}

  defp operate(:identity, {_, _, public, _}, _context),
    do: %KeyIdentity{kind: :public, value: KeyIdentity.normalize(public.material)}

  defp operate(:signing_assignment, {algorithm, _, _, issued_for}, _context),
    do: {:ok, {algorithm, issued_for}}

  defp operate({:sign, requested, bytes}, {algorithm, socket_path, public, issued_for}, context)
       when is_binary(bytes) and byte_size(bytes) <= @max_bytes_ceiling do
    check_signing!(requested, algorithm, issued_for, bytes, context)
    sign_at(socket_path, public, algorithm, bytes, true, context)
  end

  defp operate({:verify, requested, bytes, signature}, {algorithm, _, public, issued_for}, context)
       when is_binary(bytes) and byte_size(bytes) <= @max_bytes_ceiling do
    check_signing!(requested, algorithm, issued_for, bytes, context)
    Crypto.verify(algorithm, bytes, signature, public, max_bytes: @max_bytes_ceiling)
  end

  defp operate(:binding, {algorithm, socket_path, public, issued_for}, context) do
    Support.held_binding!(algorithm, issued_for, context)
    if context.operation == :binding, do: confirm_membership!(socket_path, public, context)
    {:ok, %{algorithm: algorithm, issued_for: issued_for, public_key: public}}
  end

  defp operate(_, _, _), do: {:error, :unsupported_operation}

  defp confirm_membership!(socket_path, public, context) do
    blob = Wire.key_blob(public)
    {:ok, socket} = connect(socket_path, context)

    try do
      identities = exchange(socket, <<11>>, context) |> Wire.identities() |> unwrap()
      ensure(blob in identities, :key_not_found)
    after
      :gen_tcp.close(socket)
    end
  end

  defp check_signing!(requested, algorithm, issued_for, bytes, context) do
    ensure(requested == algorithm, :key_mismatch)
    Support.signing_binding!(algorithm, issued_for, context, false)
    if issued_for != nil, do: Support.signing_bytes!(bytes, algorithm)
  end

  defp connect(path, context) do
    timeout = remaining!(context)

    case :gen_tcp.connect(
           {:local, path},
           0,
           [
             :binary,
             active: false,
             packet: 4,
             packet_size: 1_048_576,
             send_timeout: timeout,
             send_timeout_close: true
           ],
           timeout
         ) do
      {:ok, socket} -> {:ok, socket}
      {:error, reason} -> fail(socket_error(reason))
    end
  end

  defp exchange(socket, request, context) do
    :inet.setopts(socket, send_timeout: remaining!(context)) |> socket_result()
    :gen_tcp.send(socket, request) |> socket_result()

    case :gen_tcp.recv(socket, 0, remaining!(context)) do
      {:ok, response} -> response
      {:error, reason} -> fail(reply_error(reason))
    end
  end

  defp reply_error(reason) when reason in [:closed, :econnreset, :enotconn],
    do: :custodian_protocol

  defp reply_error(reason), do: socket_error(reason)

  defp socket_result(:ok), do: :ok
  defp socket_result({:error, reason}), do: fail(socket_error(reason))

  defp socket_error(reason)
       when reason in [:enoent, :econnrefused, :closed, :econnreset, :enotconn],
       do: :custodian_unavailable

  defp socket_error(:timeout), do: :deadline_exceeded
  defp socket_error(:emsgsize), do: :custodian_protocol
  defp socket_error(_), do: :custodian_failure

  defp remaining!(context) do
    remaining = Context.remaining(context)
    ensure(remaining > 0, :deadline_exceeded)
    remaining
  end
end
