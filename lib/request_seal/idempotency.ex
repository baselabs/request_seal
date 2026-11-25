defmodule RequestSeal.Idempotency do
  @moduledoc """
  Recover a stored response for a freshly verified retry of the same operation.

  Use `prepare/4` with trusted namespace and principal, then `reserve/3`.
  A conflict or an in-progress reservation grants no permission to execute.
  Only a reservation can be completed, and completion never overwrites a stored
  response. The application owns authorization, effect uniqueness, retention,
  storage confidentiality and safe response delivery. A lease can expire after
  an effect commits and before response storage. Enforce the effect's unique
  operation key at the effect boundary, including across restarts.
  """
  alias RequestSeal.{Message, Policy, SignatureBase, StructuredFields}
  alias RequestSeal.Custody.Context
  alias RequestSeal.Idempotency.{Error, Record, Reservation}
  alias RequestSeal.Replay.{Claim, Commitment}
  alias RequestSeal.StructuredFields.{Schema, Value}

  @type store :: {module(), term()}
  @type response :: %{status: 200..599, headers: [{binary(), binary()}], body: binary()}
  @type store_fault :: {:error, :unavailable | :timeout | :full | :failure}

  @key_schema %Schema{
    revision: :rfc9651,
    type: :item,
    item_types: [:string],
    parameter_types: []
  }

  @cover ~s[("@method" "@target-uri" "content-digest" "idempotency-key")]
  @max_body 1_048_576
  @excluded_headers ~w(authorization connection content-digest content-length cookie date keep-alive
    proxy-authenticate proxy-authorization proxy-connection repr-digest set-cookie set-cookie2 signature signature-input
    te trailer transfer-encoding upgrade www-authenticate)

  @doc """
  Atomically reserve the scoped key, renew a matching expired lease, or return
  the existing outcome. An active lease yields `:in_progress`. A different
  fingerprint yields `:conflict` while the row is retained. A reserved
  token must be unique across renewals and row lifetimes. Evaluate the record
  and any existing lease and retention ends against the store's trusted clock
  at the atomic transition. Return `:expired` when the prepared record is
  outside its admission window.
  """
  @callback reserve(term(), Record.t(), Context.t()) ::
              {:reserved, <<_::128>>}
              | {:stored, response()}
              | :in_progress
              | :conflict
              | :expired
              | store_fault()

  @doc """
  Complete the current matching reservation once, atomically. A missing,
  replaced, completed, expired, or different reservation returns `:not_reserved`.
  Compare both exclusive ends to the store's trusted clock at completion.
  """
  @callback store(term(), Reservation.t(), response(), Context.t()) ::
              :stored | :not_reserved | store_fault()

  @doc "Remove records with an exclusive retention end at or before the trusted time."
  @callback sweep(term(), non_neg_integer(), Context.t()) ::
              {:ok, non_neg_integer()} | store_fault()

  @doc """
  Decode one ordered `Idempotency-Key` header occurrence as a nonempty
  parameter-free RFC 9651 String of at most 256 decoded bytes.
  """
  @spec key(Message.t()) :: {:ok, binary()} | {:error, Error.t()}
  def key(message) do
    case Message.validate(message) do
      :ok -> read_key(message)
      _ -> error(:invalid_message)
    end
  end

  defp read_key(message) do
    case occurrences(message, "idempotency-key") do
      [] ->
        error(:missing_idempotency_key)

      [value] when byte_size(value) <= 1024 ->
        case StructuredFields.parse(value, @key_schema, max_bytes: 1024) do
          {:ok, %Value{value: {:string, key}, parameters: []}}
          when byte_size(key) in 1..256 ->
            {:ok, key}

          _ ->
            error(:invalid_idempotency_key)
        end

      _ ->
        error(:invalid_idempotency_key)
    end
  end

  @doc """
  Verify the request and build a response lookup record. The selected signature
  must cover `@method`, `@target-uri`, `content-digest` and `idempotency-key`
  directly, with a checked header Content-Digest over retained bytes. The
  policy must claim a nonce before returning a record. Pass `:namespace`,
  `:principal` and `:retention` (seconds). `:lease` defaults to 30 seconds
  (1–300, at most retention) and `:now` defaults to the system Unix clock.
  Resolve keys within the trusted principal's scope before serving a response.
  """
  @spec prepare(Message.t(), Policy.t(), binary(), keyword()) ::
          {:ok, Record.t()} | {:error, Error.t() | RequestSeal.Error.t()}
  def prepare(message, policy, label, opts) do
    with {:ok, {namespace, principal, now, lease, retention}} <- record_options(opts),
         :ok <- recovery_policy(policy),
         :ok <- request(message),
         {:ok, key} <- read_key(message),
         {:ok, %{components: pairs}} <- SignatureBase.components(message, @cover),
         {:ok, verification} <- RequestSeal.verify(message, policy, label: label),
         true <- Enum.all?(pairs, fn {id, _} -> id in verification.signature.covered end) do
      [{_, method}, {_, target}, {_, digest}, _] = pairs

      {:ok,
       %Record{
         namespace: namespace,
         principal: principal,
         key: key,
         fingerprint: fingerprint(method, target, digest, message.body.bytes),
         now: now,
         lease_until: now + lease,
         retain_until: now + retention
       }}
    else
      false -> error(:invalid_policy)
      {:error, %RequestSeal.Message.Error{}} -> error(:invalid_message)
      {:error, %RequestSeal.SignatureBase.Error{}} -> error(:invalid_message)
      {:error, _} = failure -> failure
    end
  end

  @doc """
  Derive the operation fingerprint from exact RFC 9421 method, target and
  Content-Digest component values and retained content bytes. Callers that
  need authenticated facts use `prepare/4`.
  """
  @spec fingerprint(binary(), binary(), binary(), binary()) :: <<_::256>>
  def fingerprint(method, target, digest, body),
    do: Commitment.digest("request-seal idempotency v1", [method, target, digest, body])

  @doc """
  Reserve a record, or return `{:stored, response}`, `:in_progress` or
  `:conflict`. Only `{:reserved, reservation}` admits the caller to its
  effect boundary. Its prepared lease and retention must still be live on the
  store's clock. Otherwise it returns `:record_expired`. The only option is
  `:timeout` in milliseconds (1–300,000).
  """
  @spec reserve(store(), Record.t(), keyword()) ::
          {:reserved, Reservation.t()}
          | {:stored, response()}
          | :in_progress
          | :conflict
          | {:error, Error.t()}
  def reserve(store, record, opts) do
    observed(:reserve, fn ->
      with true <- Record.valid?(record),
           result <- call(store, :reserve, [record], opts) do
        case result do
          {:reserved, <<_::128>> = token} ->
            {:reserved, %Reservation{record: record, token: token}}

          {:stored, _} = stored ->
            stored

          :expired ->
            error(:record_expired)

          state when state in [:conflict, :in_progress] ->
            state

          {:error, _} = error ->
            error
        end
      else
        false -> error(:invalid_record)
      end
    end)
  end

  @doc """
  Store a completed application response with explicit `:timeout` and
  `:allow_headers`. Status must be final and the body at most 1 MiB.
  Hop-by-hop, credential, framing, digest and signature fields are removed
  even when listed. Only explicitly allowlisted end-to-end fields are kept.
  Use only for responses eligible to be repeated to the authenticated principal.
  """
  @spec store(store(), Reservation.t(), response(), keyword()) ::
          :stored | :not_reserved | {:error, Error.t()}
  def store(store, reservation, response, opts) do
    observed(:store, fn ->
      with {:ok, allow, timeout} <- response_options(opts),
           true <- valid_reservation?(reservation),
           {:ok, clean} <- eligible(response, allow) do
        case call(store, :store, [reservation, clean], timeout: timeout) do
          state when state in [:stored, :not_reserved] -> state
          {:error, _} = error -> error
        end
      else
        false -> error(:invalid_record)
        {:error, _} = failure -> failure
      end
    end)
  end

  @doc "Sweep expired records under the caller's trusted clock and bounded timeout."
  @spec sweep(store(), non_neg_integer(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, Error.t()}
  def sweep(store, now, opts) when is_integer(now) and now in 0..253_402_300_799 do
    case call(store, :sweep, [now], opts) do
      {:ok, count} when is_integer(count) and count >= 0 -> {:ok, count}
      {:error, _} = error -> error
    end
  end

  def sweep(_, _, _), do: error(:invalid_options)

  defp request(%Message{kind: :request} = message) do
    if Message.validate(message) == :ok and message.body.state == :retained and
         byte_size(message.body.bytes) <= @max_body and
         match?([_], occurrences(message, "content-digest")),
       do: :ok,
       else: error(:invalid_message)
  end

  defp request(_), do: error(:invalid_message)

  defp occurrences(message, name) do
    for field <- message.fields, String.downcase(field.name) == name, do: field.value
  end

  defp recovery_policy(
         %Policy{
           replay: %{identifier: :nonce},
           content: %{kind: :content, section: :headers, algorithms: algorithms},
           components: components
         } = policy
       ) do
    required = [~s["@method"], ~s["@target-uri"], ~s["content-digest"], ~s["idempotency-key"]]

    with true <- Policy.valid?(policy) and Enum.any?(algorithms, &(&1 in ["sha-256", "sha-512"])),
         {:ok, input} <- RequestSeal.SignatureFields.inner(components),
         {:ok, ids} <- RequestSeal.SignatureFields.identifiers(input.value),
         true <- Enum.all?(required, &(&1 in ids)) do
      :ok
    else
      _ -> error(:invalid_policy)
    end
  end

  defp recovery_policy(_), do: error(:invalid_policy)

  defp record_options(opts) do
    with true <- valid_options?(opts, [:namespace, :principal, :now, :lease, :retention]),
         namespace when is_binary(namespace) <- opts[:namespace],
         principal when is_binary(principal) <- opts[:principal],
         now when is_integer(now) <-
           Keyword.get_lazy(opts, :now, fn -> System.system_time(:second) end),
         lease when is_integer(lease) <- Keyword.get(opts, :lease, 30),
         retention when is_integer(retention) <- opts[:retention],
         true <-
           Claim.bounded?(namespace) and Claim.bounded?(principal) and now >= 0 and
             lease in 1..300 and retention >= lease and now + retention <= 253_402_300_799 do
      {:ok, {namespace, principal, now, lease, retention}}
    else
      _ -> error(:invalid_options)
    end
  end

  defp response_options(opts) do
    with true <- valid_options?(opts, [:timeout, :allow_headers]),
         allow when is_list(allow) <- opts[:allow_headers],
         true <- length(allow) <= 64 and Enum.all?(allow, &header_name?/1),
         timeout when is_integer(timeout) and timeout in 1..300_000 <- opts[:timeout] do
      {:ok, allow, timeout}
    else
      _ -> error(:invalid_options)
    end
  rescue
    ArgumentError -> error(:invalid_options)
  end

  defp eligible(%{status: status, headers: headers, body: body} = response, allow)
       when map_size(response) == 3 and is_integer(status) and status in 200..599 and
              status not in [206, 304, 401, 407] and is_binary(body) and
              byte_size(body) <= @max_body and is_list(headers) do
    if length(headers) <= 64 and Enum.all?(headers, &header?/1) and
         (status not in [204, 205] or body == "") do
      connection =
        for {"connection", value} <- headers,
            name <- :binary.split(value, ",", [:global]),
            do: name |> RequestSeal.Discovery.HTTP1.trim_ows() |> String.downcase()

      {:ok,
       %{
         response
         | headers:
             Enum.filter(headers, fn {name, _} ->
               (allow == :all or name in allow) and name not in @excluded_headers and
                 name not in connection
             end)
       }}
    else
      error(:invalid_response)
    end
  rescue
    ArgumentError -> error(:invalid_response)
  end

  defp eligible(_, _), do: error(:invalid_response)

  @doc false
  def response?(response), do: match?({:ok, ^response}, eligible(response, :all))

  defp header?({name, value}) when is_binary(value) and byte_size(value) <= 4096,
    do: header_name?(name) and RequestSeal.Message.Validation.field_value?(value)

  defp header?(_), do: false

  defp header_name?(name), do: RequestSeal.SignatureFields.field_name?(name)

  @doc false
  def valid_reservation?(%Reservation{record: record, token: <<_::128>>} = reservation),
    do: map_size(reservation) == 3 and Record.valid?(record)

  def valid_reservation?(_), do: false

  defp valid_options?(opts, keys) do
    Keyword.keyword?(opts) and length(opts) <= length(keys) and
      length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) and
      Enum.all?(Keyword.keys(opts), &(&1 in keys))
  end

  defp call({adapter, ref}, operation, args, timeout: timeout)
       when is_atom(adapter) and is_integer(timeout) and timeout in 1..300_000 do
    context = %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + timeout}

    arguments = [ref | args] ++ [context]

    if Code.ensure_loaded?(adapter) and function_exported?(adapter, operation, length(arguments)) do
      callback = fn -> invoke_adapter(adapter, operation, arguments) end

      case RequestSeal.Replay.run(context, callback) do
        {:adapter_result, {:error, reason}} -> store_error(reason)
        {:adapter_result, result} -> result
        {:error, %RequestSeal.Replay.Error{reason: :store_timeout}} -> error(:store_timeout)
        _ -> error(:store_failed)
      end
    else
      error(:store_failed)
    end
  end

  defp call(_, _, _, _), do: error(:invalid_options)

  defp invoke_adapter(adapter, operation, arguments) do
    {:adapter_result, normalize(operation, apply(adapter, operation, arguments))}
  rescue
    _ -> {:adapter_result, {:error, :failure}}
  catch
    _, _ -> {:adapter_result, {:error, :failure}}
  end

  defp normalize(:reserve, {:reserved, <<_::128>>} = result), do: result

  defp normalize(:reserve, {:stored, response} = result) do
    if response?(response), do: result, else: {:error, :failure}
  end

  defp normalize(:reserve, result) when result in [:in_progress, :conflict, :expired], do: result
  defp normalize(:store, result) when result in [:stored, :not_reserved], do: result

  defp normalize(:sweep, {:ok, count} = result) when is_integer(count) and count >= 0,
    do: result

  defp normalize(_, {:error, reason} = result) when reason in [:timeout, :unavailable, :full],
    do: result

  defp normalize(_, _), do: {:error, :failure}

  defp observed(operation, fun) do
    start = System.monotonic_time()
    result = fun.()

    {outcome, reason} =
      case result do
        {:error, %{reason: reason}} -> {:error, reason}
        {outcome, _} -> {outcome, nil}
        outcome -> {outcome, nil}
      end

    RequestSeal.Telemetry.emit(
      [:request_seal, :idempotency, operation],
      System.monotonic_time() - start,
      %{outcome: outcome, reason: reason}
    )

    result
  end

  defp store_error(:timeout), do: error(:store_timeout)
  defp store_error(:unavailable), do: error(:store_unavailable)
  defp store_error(:full), do: error(:store_full)
  defp store_error(_), do: error(:store_failed)
  defp error(reason), do: {:error, %Error{reason: reason}}
end
