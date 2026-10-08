defmodule RequestSeal.Ash.Scope do
  @moduledoc """
  Caller-bound actor, tenant, and bounded verification context for Ash actions.

  Construct with `RequestSeal.Ash.scope/2`. `principal` is a classification only;
  the opaque identity value stays in caller-selected actor/tenant values.
  Default inspection exposes only `principal` and `authorize?`.

  `to_opts/1` works without Ash installed. When Ash is present at compilation,
  the guarded `Ash.Scope.ToOpts` implementation also enables `scope: scope`.
  When adding Ash to a consumer that already compiled RequestSeal without it,
  run `mix deps.compile request_seal --force` to compile the protocol implementation.
  """

  @derive {Inspect, only: [:principal, :authorize?]}
  defstruct [:actor, :tenant, :context, :principal, authorize?: true]

  @type t :: %__MODULE__{
          actor: term() | nil,
          tenant: term() | nil,
          context: %{
            request_seal: %{
              label: binary(),
              profile:
                %{name: :rfc9421}
                | %{name: :web_bot_auth, revision: binary()},
              principal: :attributed | :unattributed,
              covered: [binary()],
              content: :not_required | :checked,
              freshness: :not_evaluated | :evaluated,
              replay: :not_required
            }
          },
          authorize?: true,
          principal: :attributed | :unattributed
        }

  @doc "Returns explicit actor, tenant, context, and `authorize?: true` options."
  @spec to_opts(t()) :: keyword()
  def to_opts(%__MODULE__{} = scope),
    do: [actor: scope.actor, tenant: scope.tenant, context: scope.context, authorize?: true]
end

if Code.ensure_loaded?(Ash.Scope.ToOpts) do
  defimpl Ash.Scope.ToOpts, for: RequestSeal.Ash.Scope do
    def get_actor(scope), do: {:ok, scope.actor}
    def get_tenant(scope), do: {:ok, scope.tenant}
    def get_context(scope), do: {:ok, scope.context}
    def get_authorize?(_), do: {:ok, true}
    def get_tracer(_), do: :error
  end
end
