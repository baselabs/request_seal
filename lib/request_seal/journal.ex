defmodule RequestSeal.Journal do
  @moduledoc """
  Write an unsigned request intent before sending and sign it afresh for each
  transport attempt. The journal sends nothing. The caller determines whether
  to retry and supplies a current custody handle each time.

  Use the bounded local journal for in-process recovery, or persist the
  `entry/2` snapshot under a unique namespace and operation key in your own
  durable store. Persisted intents contain body and field bytes. Keep your
  own retention and access rules and keep application-specific credential
  fields out of requests submitted to the journal.
  """
  use GenServer

  alias RequestSeal.{Idempotency, KeyHandle, Message, SignatureBase, SignatureFields, Signing}
  alias RequestSeal.Message.Validation
  alias RequestSeal.Replay.{Claim, Commitment}

  @derive {Inspect, only: []}
  @enforce_keys [:namespace, :key, :method, :target, :fields, :body, :digest]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          namespace: binary(),
          key: binary(),
          method: binary(),
          target: binary(),
          fields: [{binary(), binary()}],
          body: binary(),
          digest: <<_::256>>
        }

  @type error ::
          {:error, :invalid_intent | :invalid_options | :journal_unavailable | :journal_full}

  @excluded ~w(authorization cookie proxy-authorization signature signature-input)
  @components [~s["@method"], ~s["@target-uri"], ~s["content-digest"], ~s["idempotency-key"]]

  @doc "Start a bounded local journal, with the required `:max_entries` (1–10,000)."
  @spec start_link(keyword()) :: GenServer.on_start() | {:error, :invalid_options}
  def start_link(max_entries: max) when is_integer(max) and max in 1..10_000,
    do: GenServer.start_link(__MODULE__, max)

  def start_link(_), do: {:error, :invalid_options}

  @doc """
  Capture a validated unsigned HTTP(S) origin-form request with a retained body of at most 1 MiB,
  one valid Idempotency-Key, a matching header Content-Digest, and no trailers
  or credential fields. The fields must leave room for the largest permitted
  Signature-Input and Signature fields.
  """
  @spec entry(binary(), Message.t()) :: {:ok, t()} | error()
  def entry(namespace, %Message{kind: :request, target_form: :origin} = message) do
    with true <- Claim.bounded?(namespace) and Message.validate(message) == :ok,
         true <- message.trailers in [[], :unavailable] and message.body.state == :retained,
         true <- byte_size(message.body.bytes) <= 1_048_576,
         true <- Message.field_bytes_fit?(message.fields, signature_field_bytes()),
         {:ok, key} <- Idempotency.key(message),
         {:ok, %{components: [{_, target}]}} <-
           SignatureBase.components(message, ~s[("@target-uri")]),
         fields = Enum.map(message.fields, &{&1.name, &1.value}),
         true <-
           length(fields) <= 256 and
             Enum.all?(fields, fn {name, _} -> String.downcase(name) not in @excluded end),
         [digest] <-
           for({name, value} <- fields, String.downcase(name) == "content-digest", do: value),
         body = message.body.bytes,
         {:ok, rebuilt} <- rebuild(message.method, target, fields, body),
         true <- valid_length?(fields, body),
         {:ok, _} <- RequestSeal.Digest.check(rebuilt, :content, section: :headers) do
      {:ok,
       %__MODULE__{
         namespace: namespace,
         key: key,
         method: message.method,
         target: target,
         fields: fields,
         body: body,
         digest: intent_digest(namespace, key, message.method, target, fields, body, digest)
       }}
    else
      _ -> {:error, :invalid_intent}
    end
  end

  def entry(_, _), do: {:error, :invalid_intent}

  @doc """
  Record the intent atomically before sending. Equal intent returns
  `:already_recorded`, and different intent under the same key returns
  `:conflict`.
  """
  @spec record(pid(), binary(), Message.t()) ::
          :recorded | :already_recorded | :conflict | error()
  def record(journal, namespace, message) do
    call(journal, {:record, namespace, message})
  end

  @doc "Read the recorded intent by its trusted namespace and decoded operation key."
  @spec load(pid(), binary(), binary()) :: {:ok, t()} | :not_found | error()
  def load(journal, namespace, key) do
    if Claim.bounded?(namespace) and Claim.bounded?(key),
      do: call(journal, {:load, {namespace, key}}),
      else: {:error, :invalid_options}
  end

  @doc """
  Reissue a local journal entry using a generated RFC 9421 signing spec and
  caller-owned custody handle. `:clock` and `:signing_timeout` are forwarded
  to signing. Nonces come from a fresh random draw on every call.
  """
  @spec reissue(pid(), binary(), binary(), map(), KeyHandle.t(), keyword()) ::
          {:ok, Message.t()} | :not_found | error() | {:error, RequestSeal.Error.t()}
  def reissue(journal, namespace, key, spec, signer, opts) do
    with {:ok, entry} <- load(journal, namespace, key), do: reissue(entry, spec, signer, opts)
  end

  @doc """
  Validate a loaded snapshot and sign its recorded intent with new creation,
  expiration and nonce parameters. The generated spec must cover the method,
  target, digest and operation key. An explicit nonce override is refused.
  """
  @spec reissue(t(), map(), KeyHandle.t(), keyword()) ::
          {:ok, Message.t()} | error() | {:error, RequestSeal.Error.t()}
  def reissue(%__MODULE__{} = recorded, spec, signer, opts) do
    with {:ok, normalized} <- signing_spec(spec, opts),
         {:ok, message} <-
           rebuild(recorded.method, recorded.target, recorded.fields, recorded.body),
         {:ok, ^recorded} <- entry(recorded.namespace, message) do
      case RequestSeal.sign(message, normalized, signer, opts) do
        {:ok, signed} ->
          fields =
            Enum.reject(
              signed.fields,
              &(String.downcase(&1.name) in ["signature", "signature-input"])
            )

          if fields == message.fields, do: {:ok, signed}, else: {:error, :invalid_intent}

        {:error, _} = error ->
          error
      end
    else
      {:error, :invalid_options} = error -> error
      _ -> {:error, :invalid_intent}
    end
  end

  def reissue(_, _, _, _), do: {:error, :invalid_intent}

  @doc "Remove a settled local intent so its capacity can be reused."
  @spec forget(pid(), binary(), binary()) :: :ok | error()
  def forget(journal, namespace, key) do
    if Claim.bounded?(namespace) and Claim.bounded?(key),
      do: call(journal, {:forget, {namespace, key}}),
      else: {:error, :invalid_options}
  end

  @impl GenServer
  def init(max), do: {:ok, {%{}, max}}

  @impl GenServer
  def handle_call({:record, namespace, message}, _from, state) do
    case entry(namespace, message) do
      {:ok, entry} -> store_entry(entry, state)
      error -> {:reply, error, state}
    end
  end

  def handle_call({:load, {namespace, key} = identity}, _from, {entries, _} = state) do
    reply =
      if Claim.bounded?(namespace) and Claim.bounded?(key) do
        case Map.fetch(entries, identity) do
          {:ok, entry} -> {:ok, entry}
          :error -> :not_found
        end
      else
        {:error, :invalid_options}
      end

    {:reply, reply, state}
  end

  def handle_call({:forget, {namespace, key} = identity}, _from, {entries, max} = state) do
    if Claim.bounded?(namespace) and Claim.bounded?(key),
      do: {:reply, :ok, {Map.delete(entries, identity), max}},
      else: {:reply, {:error, :invalid_options}, state}
  end

  def handle_call(_, _from, state), do: {:reply, {:error, :failure}, state}

  defp store_entry(entry, {entries, max} = state) do
    key = {entry.namespace, entry.key}
    digest = entry.digest

    case Map.fetch(entries, key) do
      {:ok, %{digest: ^digest}} ->
        {:reply, :already_recorded, state}

      {:ok, _} ->
        {:reply, :conflict, state}

      :error when map_size(entries) < max ->
        {:reply, :recorded, {Map.put(entries, key, entry), max}}

      :error ->
        {:reply, {:error, :journal_full}, state}
    end
  end

  defp call(pid, request) when is_pid(pid) do
    case GenServer.call(pid, request) do
      {:error, :failure} -> {:error, :journal_unavailable}
      reply -> reply
    end
  catch
    :exit, _ -> {:error, :journal_unavailable}
  end

  defp call(_, _), do: {:error, :invalid_options}

  defp signature_field_bytes do
    # Dictionary key, equals sign, byte-sequence delimiters and padded base64.
    encoded_signature_bytes = 4 * div(Signing.max_signature_bytes() + 2, 3)
    signature_bytes = SignatureFields.max_label_bytes() + 3 + encoded_signature_bytes

    byte_size("Signature-Input") + Validation.max_field_value_bytes() +
      byte_size("Signature") + signature_bytes
  end

  defp signing_spec(%{components: components} = spec, opts) do
    with true <-
           Keyword.keyword?(opts) and
             Enum.all?(Keyword.keys(opts), &(&1 in [:clock, :signing_timeout])),
         %{digest: nil, parameters: %{created: true, nonce: :random, expires_in: age}} =
           normalized
         when is_integer(age) and age > 0 <- Signing.normalize_spec!(spec),
         {:ok, input} <- SignatureFields.inner(components),
         {:ok, ids} <- SignatureFields.identifiers(input.value),
         true <- Enum.all?(@components, &(&1 in ids)) do
      {:ok, normalized}
    else
      _ -> {:error, :invalid_options}
    end
  catch
    {:adapter, _, _} -> {:error, :invalid_options}
  end

  defp signing_spec(_, _), do: {:error, :invalid_options}

  defp rebuild(method, target, fields, body) do
    with {:ok, message} <- Message.request(method, target, fields, body),
         true <- message.method == method,
         {:ok, %{components: [{_, ^target}]}} <-
           SignatureBase.components(message, ~s[("@target-uri")]) do
      {:ok, message}
    else
      _ -> {:error, :invalid_intent}
    end
  end

  defp valid_length?(fields, body) do
    case for({name, value} <- fields, String.downcase(name) == "content-length", do: value) do
      [] -> true
      [value] -> value == Integer.to_string(byte_size(body))
      _ -> false
    end
  end

  defp intent_digest(namespace, key, method, target, fields, body, digest) do
    field_bytes =
      fields
      |> Enum.flat_map(fn {name, value} -> [name, value] end)
      |> Commitment.frame()
      |> IO.iodata_to_binary()

    Commitment.digest("request-seal journal v1", [
      namespace,
      key,
      method,
      target,
      field_bytes,
      body,
      digest
    ])
  end
end
