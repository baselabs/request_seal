if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Verify do
    @moduledoc """
    Verify the immutable captured request under an explicit policy and label.

    Verify reads only the message retained by `RequestSeal.Plug.Capture`. No
    authenticated identity is implicitly authorized. The RequestSeal reader's
    invocation is tracked separately from adapter reads. Pass-through parsers
    that leave the body unread do not impose a replay requirement, even when
    they fetch empty body params. Wrapper transformations after a read remain
    caller-controlled and cannot be observed by the replay check. Captured Plug
    values do not establish exact target evidence, so target-dependent
    components are refused (see `call/2`).
    """
    @behaviour Plug
    alias RequestSeal.{Policy, SignatureFields}
    alias RequestSeal.Adapter.{Error, Signing}
    alias RequestSeal.Plug.{Delivery, State, Target}

    @doc """
    Validates verification options once, at plug initialization.

    ## Parameters

      * `opts` - keyword list of the options below. Unknown or duplicate options
        reject.

    ## Options

      * `:policy` (required) - a valid `RequestSeal.Policy`, a zero-arity
        function, or an exported `{module, function, args}`. A function or MFA
        returns a policy directly and runs once per eligible request, after the
        capture and parser checks, before key resolution. Resolution runs
        synchronously; callers own deadlines for external work. No callback
        diagnostics are retained.
      * `:label` (required) - the signature label to verify.
      * `:on_reject` (required) - `:continue`, or `{:halt, status}` with a final
        status in 200..599.
      * `:assign` - a non-Boolean atom or nil (default nil; Booleans reject
        from 0.5.0). When set, a
        successful verification is also assigned under that key.
      * `:name` - a stable repeat-identity atom (or 1..256-byte binary),
        default nil. When set, a later Verify on the same connection reuses
        the first result when its `:name` and `:label` are equal, even if the
        `:policy` value is a rebuilt-equivalent policy whose function fields
        make `==` fail — the name is the caller's explicit assertion that the
        policy is the same one. A repeat with a different name, no name, or a
        different label still fails closed `:already_verified`; a policy-based
        repeat of a named verification never matches.

    ## Returns

      * keyword list - the validated options.

    Raises `RequestSeal.Adapter.Error` with reason `:invalid_options` and stage
    `:verify` on any invalid option.

    ## Examples

        iex> try do
        ...>   RequestSeal.Plug.Verify.init(policy: fn -> :unused end, label: "sig")
        ...> rescue
        ...>   error in RequestSeal.Adapter.Error -> {error.reason, error.stage}
        ...> end
        {:invalid_options, :verify}
    """
    @impl Plug
    def init(opts) do
      case Signing.protect(:plug, :attach, 0, fn ->
             Signing.options(opts, [:policy, :label, :on_reject, :assign, :name])

             Signing.ensure(
               policy_source?(opts[:policy]) and SignatureFields.label?(opts[:label]) and
                 assign?(opts[:assign]) and rejection?(opts[:on_reject]) and name?(opts[:name]),
               :invalid_options
             )

             opts
           end) do
        {:error, error} -> raise %{error | stage: :verify}
        opts -> opts
      end
    end

    defp policy_source?(%Policy{} = policy), do: Policy.valid?(policy)
    defp policy_source?(policy) when is_function(policy, 0), do: true

    defp policy_source?({module, function, args})
         when is_atom(module) and is_atom(function) and is_list(args) do
      Code.ensure_loaded?(module) and function_exported?(module, function, length(args))
    end

    defp policy_source?(_), do: false

    defp resolve_policy(%Policy{} = policy), do: policy

    defp resolve_policy(source) do
      policy =
        case source do
          function when is_function(function, 0) -> function.()
          {module, function, args} -> apply(module, function, args)
        end

      Signing.ensure(Policy.valid?(policy), :invalid_options)
      policy
    end

    defp assign?(assign), do: assign == nil or (is_atom(assign) and not is_boolean(assign))

    defp name?(name),
      do:
        name == nil or (is_atom(name) and not is_boolean(name)) or
          (is_binary(name) and byte_size(name) in 1..256)

    defp rejection?(:continue), do: true
    defp rejection?({:halt, status}), do: is_integer(status) and status in 200..599
    defp rejection?(_), do: false

    @doc """
    Verifies the captured request once and records the result in private state.

    From 0.5.0, a connection is verified at most once. A later Verify with the same
    `:policy` and `:label` values as the first is idempotent: it reuses the
    first result (assigning it under its own `:assign` on success) and applies
    `:on_reject` again on a rejection. A later Verify with any other policy or
    label fails closed: private state's `:verification` becomes
    `{:error, %RequestSeal.Adapter.Error{reason: :already_verified}}`, so
    `RequestSeal.Plug.verification/1` returns `:error` from then on, every
    assign made by Verify on the connection is removed, and `:on_reject`
    applies. The `:policy` and `:label` values are compared with `==`.

    Checks run in this order: a missing capture, the
    replay checks, policy resolution, target-dependent coverage, then
    `RequestSeal.verify/3` with the label. The replay checks reject a replaced
    or rewrapped replay adapter, a RequestSeal reader call without a replay
    read, and a partially drained replay or a handed-out digest that differs
    from the full captured body. Every check before `RequestSeal.verify/3` runs
    before key resolution, freshness evaluation, or replay callbacks; the policy
    function or MFA runs only after the capture and replay checks pass.

    ## Parameters

      * `conn` - a `Plug.Conn` that passed `RequestSeal.Plug.Capture`.
      * `opts` - options returned by `init/1`.

    ## Returns

      * `Plug.Conn` - on success, private state's `:verification` is
        `{:ok, %RequestSeal.Verification{}}`, readable with
        `RequestSeal.Plug.verification/1`, and the result is assigned when
        `:assign` is set.
      * `Plug.Conn` - on rejection, private state's `:verification` is
        `{:error, %RequestSeal.Adapter.Error{stage: :verify, attempt: 0}}`, any
        `:assign` key is removed, and with `{:halt, status}` the connection is
        sent with that status and an empty body and halted. Reasons:
        `:not_captured` (no capture), `:parser_order` (replay checks above),
        `:invalid_options` (a policy function or MFA returned an invalid
        policy), `:unsupported_component` (the policy requires, or the selected
        Signature-Input covers, `@request-target`, `@target-uri`, or `@query`;
        unrelated labels impose nothing), `:request_rejected` (the core
        verifier rejected, with its bounded `RequestSeal.Error` as `source`),
        and `:response_rejected` (a policy callback raised, threw, or exited, or
        another unexpected exception, without source details). Meanings:
        `RequestSeal.Adapter.Error`.

    ## Examples

        iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
        iex> components = ~s[("@method" "@authority" "@path")]
        iex> {:ok, message} =
        ...>   RequestSeal.Message.request("POST", "https://messages.example.com/inbox", [], "hi")
        iex> {:ok, signed} =
        ...>   RequestSeal.sign(message, %{
        ...>     label: "sig",
        ...>     algorithm: "ed25519",
        ...>     components: components,
        ...>     expires_in: 60
        ...>   }, handle)
        iex> conn =
        ...>   Enum.reduce(
        ...>     signed.fields,
        ...>     Plug.Test.conn(:post, "https://messages.example.com/inbox", "hi"),
        ...>     fn field, conn ->
        ...>       Plug.Conn.put_req_header(conn, String.downcase(field.name), field.value)
        ...>     end
        ...>   )
        iex> {:ok, policy} =
        ...>   RequestSeal.Policy.new(%{
        ...>     algorithms: ["ed25519"],
        ...>     components: components,
        ...>     key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
        ...>     freshness: :not_evaluated,
        ...>     content: :not_required,
        ...>     replay: :not_required
        ...>   })
        iex> capture =
        ...>   RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: 1_024, read_timeout: 5_000)
        iex> verify =
        ...>   RequestSeal.Plug.Verify.init(
        ...>     policy: policy,
        ...>     label: "sig",
        ...>     on_reject: {:halt, 401},
        ...>     assign: :signature
        ...>   )
        iex> conn = conn |> RequestSeal.Plug.Capture.call(capture) |> RequestSeal.Plug.Verify.call(verify)
        iex> {:ok, verification} = RequestSeal.Plug.verification(conn)
        iex> {verification.label, verification.authorization, conn.assigns.signature == verification}
        {"sig", :not_evaluated, true}
        iex> again = RequestSeal.Plug.Verify.call(conn, verify)
        iex> {RequestSeal.Plug.verification(again) == {:ok, verification}, again.halted}
        {true, false}
        iex> other = RequestSeal.Plug.Verify.init(policy: policy, label: "other", on_reject: {:halt, 401})
        iex> refused = RequestSeal.Plug.Verify.call(again, other)
        iex> {:error, error} = refused.private.request_seal.verification
        iex> {error.reason, RequestSeal.Plug.verification(refused), Map.has_key?(refused.assigns, :signature), refused.status}
        {:already_verified, :error, false, 401}
        iex> RequestSeal.Custody.Local.release(handle)
        :ok
    """
    @impl Plug
    def call(conn, opts) do
      state = State.get(conn)

      cond do
        state.verification == nil ->
          verify(conn, state, opts)

        state.verified_by == identity(opts) ->
          apply_result(conn, state, opts, state.verification)

        true ->
          refuse_repeat(conn, state, opts)
      end
    end

    # With :name set, repeat identity is the caller's stable name plus label;
    # without it, the policy value plus label, compared with == as before.
    defp identity(opts) do
      if opts[:name] == nil,
        do: {:policy, opts[:label], opts[:policy]},
        else: {:name, opts[:label], opts[:name]}
    end

    # A repeat with any other policy or label must not inherit the earlier
    # result: the connection is no longer verified and every Verify assign goes.
    defp refuse_repeat(conn, state, opts) do
      result = {:error, Error.new(:already_verified, :plug, :verify, 0)}
      conn = %{conn | assigns: Map.drop(conn.assigns, state.verify_assigns)}
      apply_result(conn, %{state | verified_by: :refused}, opts, result)
    end

    defp verify(conn, state, opts) do
      result =
        Signing.protect(:plug, :verify, 0, fn ->
          cond do
            state.capture == nil ->
              {:error, Error.new(:not_captured, :plug, :verify, 0)}

            not Delivery.retained?(conn.adapter, state.replay_id) ->
              {:error, Error.new(:parser_order, :plug, :verify, 0)}

            state.reader_called? and not Delivery.replayed?(conn.adapter) ->
              {:error, Error.new(:parser_order, :plug, :verify, 0)}

            Delivery.replayed?(conn.adapter) and
                not Delivery.replay_matches?(conn.adapter, state.capture.message.body.bytes) ->
              {:error, Error.new(:parser_order, :plug, :verify, 0)}

            true ->
              policy = resolve_policy(opts[:policy])

              if Target.verification_supported?(state.capture.message, policy, opts[:label]) do
                case RequestSeal.verify(state.capture.message, policy, label: opts[:label]) do
                  {:ok, _} = result ->
                    result

                  {:error, source} ->
                    {:error, Error.new(:request_rejected, :plug, :verify, 0, source)}
                end
              else
                {:error, Error.new(:unsupported_component, :plug, :verify, 0)}
              end
          end
        end)

      apply_result(conn, %{state | verified_by: identity(opts)}, opts, result)
    end

    defp apply_result(conn, state, opts, result) do
      assigns =
        if opts[:assign], do: [opts[:assign] | state.verify_assigns], else: state.verify_assigns

      conn =
        State.put(conn, %{state | verification: result, verify_assigns: Enum.uniq(assigns)})

      case result do
        {:ok, result} ->
          if opts[:assign], do: Plug.Conn.assign(conn, opts[:assign], result), else: conn

        {:error, _} ->
          conn =
            if opts[:assign],
              do: %{conn | assigns: Map.delete(conn.assigns, opts[:assign])},
              else: conn

          case opts[:on_reject] do
            :continue -> conn
            {:halt, status} -> conn |> Plug.Conn.send_resp(status, "") |> Plug.Conn.halt()
          end
      end
    end
  end
end
