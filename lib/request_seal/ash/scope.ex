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
              replay: :not_required | :claimed
            }
          },
          authorize?: true,
          principal: :attributed | :unattributed
        }

  @doc """
  Returns explicit actor, tenant, context, and `authorize?: true` options for Ash calls.

  Works without Ash installed. Pass the result as Ash action options, or pass
  `scope: scope` when Ash's scope protocol is compiled in.

  ## Parameters

    * `scope` - a `RequestSeal.Ash.Scope` from `RequestSeal.Ash.scope/2`.

  ## Returns

    * keyword list - `[actor: actor, tenant: tenant, context: context, authorize?: true]`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
      iex> {:ok, message} = RequestSeal.Message.request("GET", "https://docs.example.com/reports/7", [], nil)
      iex> {:ok, signed} =
      ...>   RequestSeal.sign(message, %{
      ...>     label: "sig",
      ...>     algorithm: "ed25519",
      ...>     components: ~s[("@method" "@path")],
      ...>     expires_in: 60
      ...>   }, handle)
      iex> {:ok, policy} =
      ...>   RequestSeal.Policy.new(%{
      ...>     algorithms: ["ed25519"],
      ...>     components: ~s[("@method" "@path")],
      ...>     key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
      ...>     freshness: :not_evaluated,
      ...>     content: :not_required,
      ...>     replay: :not_required
      ...>   })
      iex> {:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
      iex> {:ok, scope} =
      ...>   RequestSeal.Ash.scope(verification, %{
      ...>     actor: fn _principal -> :error end,
      ...>     unattributed: :anonymous,
      ...>     tenant: :none
      ...>   })
      iex> opts = RequestSeal.Ash.Scope.to_opts(scope)
      iex> Keyword.keys(opts)
      [:actor, :tenant, :context, :authorize?]
      iex> {opts[:actor], opts[:tenant], opts[:authorize?], opts[:context].request_seal.label}
      {nil, nil, true, "sig"}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok

  Fragment (requires an Ash resource with a data layer; not executed here):

      Ash.read(MyApp.Docs.Report, RequestSeal.Ash.Scope.to_opts(scope))
  """
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
