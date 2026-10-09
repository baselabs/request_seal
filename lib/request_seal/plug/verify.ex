if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Verify do
    @moduledoc """
    Verify the immutable captured request under an explicit policy and label.

    `:policy` accepts a valid `RequestSeal.Policy`, a zero-arity function, or an
    exported `{module, function, args}`. Functions and MFAs return a policy directly
    and run once per eligible request, after capture and parser checks, before
    key resolution. Their returned policy is validated; invalid policies reject
    with `:invalid_options`. Exceptions, throws, and exits reject with the bounded
    `:response_rejected` error. No callback diagnostics are retained. Resolution
    runs synchronously; callers own deadlines for external work.

    Requires `:policy`, `:label`, and `:on_reject` (`:continue` or
    `{:halt, status}` with final status in 200..599). Optional `:assign` is an atom
    or nil; only success is assigned. Private state retains `{:ok, verification}`
    or `{:error, adapter_error}`. No authenticated identity is implicitly authorized.
    Missing capture returns `:not_captured`; a prior attempt returns
    `:already_verified` before any resolver or replay callback. Core rejections
    are `:request_rejected` with a bounded `RequestSeal.Error` source.
    Replacing the captured replay adapter, a partially drained replay, or a
    handed-out digest inconsistent with the full captured body rejects with
    `:parser_order` before resolver or replay callbacks. The RequestSeal reader's
    invocation is tracked separately from adapter reads. Pass-through parsers
    that leave the body unread do not impose a replay requirement, even when
    they fetch empty body params. Wrapper transformations after a read remain
    caller-controlled and cannot be observed by this check. Unexpected exceptions
    return a bounded `:response_rejected` adapter error without source details.
    Required or selected covered `@request-target`, `@target-uri`, and `@query`
    reject with `:unsupported_component` before resolver, freshness, or replay
    callbacks: the captured Plug values do not establish exact target evidence.
    """
    @behaviour Plug
    alias RequestSeal.{Policy, SignatureFields}
    alias RequestSeal.Adapter.{Error, Signing}
    alias RequestSeal.Plug.{Delivery, State, Target}

    @impl Plug
    def init(opts) do
      case Signing.protect(:plug, :attach, 0, fn ->
             Signing.options(opts, [:policy, :label, :on_reject, :assign])

             Signing.ensure(
               policy_source?(opts[:policy]) and SignatureFields.label?(opts[:label]) and
                 is_atom(opts[:assign]) and rejection?(opts[:on_reject]),
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

    defp rejection?(:continue), do: true
    defp rejection?({:halt, status}), do: is_integer(status) and status in 200..599
    defp rejection?(_), do: false

    @impl Plug
    def call(conn, opts) do
      state = State.get(conn)

      result =
        Signing.protect(:plug, :verify, 0, fn ->
          cond do
            state.verification != nil ->
              {:error, Error.new(:already_verified, :plug, :verify, 0)}

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

      conn = State.put(conn, %{state | verification: result})

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
