defmodule RequestSeal.Custody.SSHAgent do
  @moduledoc """
  Non-exporting signing through a caller-selected OpenSSH agent Unix socket.

  Protocol: [draft-miller-ssh-agent-14](https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html),
  [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709.html),
  [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332.html), and
  [RFC 5656](https://www.rfc-editor.org/rfc/rfc5656.html).

  `new/4` accepts a trusted public key and an explicit absolute socket path
  (1–103 bytes, no NUL). It proves possession by signing empty bytes and checking
  the returned signature. Only `timeout:` is accepted, with the custody boundary's
  5,000 ms default and 1–300,000 ms bound. It never reads `SSH_AUTH_SOCK`, starts
  an agent, loads keys, or accesses private files. The caller owns agent access and
  authorization. An OpenSSH agent is a separate process, not an HSM guarantee.

  Supports HTTP Ed25519, RSA-v1_5-SHA256 (agent flag 2), P-256, and P-384,
  plus explicit JWS `EdDSA`, `RS256`, `ES256`, and `ES384`. PSS and HMAC reject.
  Each sign uses one new connection; replies cannot spill into another operation.
  Identity lists are bounded to 256 keys, frames to 1,048,576 bytes, key blobs and
  comments to 16,384 bytes. Selection uses exact public components, never a comment
  or key ID. ECDSA mpints convert to fixed-width r || s, and every returned signature
  must verify with `Crypto` before release. Verification uses the trusted public
  key locally; it does not assert current agent possession or authorization.

  Unknown keys at construction yield `:custodian_rejected`; removed keys during
  signing yield `:key_not_found`. Connect and pre-send connection failures yield
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
  import Support, only: [ensure: 2, unwrap: 1]

  @doc "Bind a supported algorithm, explicit socket, and trusted public key after a real possession check."
  @spec new(Crypto.algorithm(), binary(), PublicKey.t(), keyword()) ::
          {:ok, KeyHandle.t()} | {:error, RequestSeal.Custody.Error.t()}
  def new(algorithm, socket_path, public, opts \\ []) do
    Support.safe(fn ->
      Support.timeout(opts)
      {jose, _} = resolved = Algorithm.resolve(algorithm)
      ensure(jose in ~w(EdDSA RS256 ES256 ES384), :unsupported_algorithm)

      ensure(
        is_binary(socket_path) and byte_size(socket_path) in 1..103 and
          String.starts_with?(socket_path, "/") and not String.contains?(socket_path, <<0>>),
        :invalid_options
      )

      PublicKey.bind!(public, resolved)
      provisional = handle(algorithm, socket_path, public, false)
      Custody.sign(provisional, "", opts) |> unwrap()
      {:ok, handle(algorithm, socket_path, public, true)}
    end)
  end

  defp handle(algorithm, socket, public, check) do
    state = {algorithm, socket, public, check}

    %KeyHandle{
      custodian: __MODULE__,
      algorithm: algorithm,
      capabilities: [:sign, :verify],
      ref: fn -> state end
    }
  end

  @impl true
  def sign(ref, algorithm, bytes, context) do
    {bound, socket_path, public, check} = ref.()
    ensure(algorithm == bound, :key_mismatch)
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
  def verify(ref, algorithm, bytes, signature, _context) do
    {bound, _, public, _} = ref.()
    ensure(algorithm == bound, :key_mismatch)
    Crypto.verify(algorithm, bytes, signature, public)
  end

  @impl true
  def public_key(ref) do
    {_, _, public, _} = ref.()
    {:ok, public}
  end

  @impl true
  def identity(ref) do
    {_, _, public, _} = ref.()
    %KeyIdentity{kind: :public, value: KeyIdentity.normalize(public.material)}
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
      {:error, reason} -> ensure(false, socket_error(reason))
    end
  end

  defp exchange(socket, request, context) do
    :inet.setopts(socket, send_timeout: remaining!(context)) |> socket_result()
    :gen_tcp.send(socket, request) |> socket_result()

    case :gen_tcp.recv(socket, 0, remaining!(context)) do
      {:ok, response} -> response
      {:error, reason} -> ensure(false, reply_error(reason))
    end
  end

  defp reply_error(reason) when reason in [:closed, :econnreset, :enotconn],
    do: :custodian_protocol

  defp reply_error(reason), do: socket_error(reason)

  defp socket_result(:ok), do: :ok
  defp socket_result({:error, reason}), do: ensure(false, socket_error(reason))

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
