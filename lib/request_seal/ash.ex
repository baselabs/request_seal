defmodule RequestSeal.Ash do
  @moduledoc """
  Explicit caller-owned identity mapping for Ash policies and actions.

  `scope/2` accepts a successful generic or Web Bot Auth `RequestSeal.Verification` and a map
  containing exactly three required choices, with no defaults or extra keys:

  * `:actor` — a one-argument function receiving only the opaque attributed
    principal. It must return `{:ok, actor}` with a non-nil actor, or `:error`.
    It never receives signature key identifiers, parameters, or labels.
  * `:unattributed` — `:anonymous` maps an unattributed verification to a nil
    actor without calling the actor function; `:reject` rejects it.
  * `:tenant` — `:none`, `{:value, tenant}`, or a one-argument principal function
    returning `{:ok, tenant}` or `:error`. The function runs only for attributed
    principals; anonymous scopes otherwise have a nil tenant. An explicit value
    is caller-trusted: do not derive it from untrusted forwarded headers.

  Principal attribution belongs to the selected discovery and custody contract.
  This adapter neither establishes identity from key possession nor defines the
  principal's shape. Attributed values remain opaque caller-owned terms; `nil`
  and `false` are not attributed values and reject with `:invalid_verification`.
  Only the atom `:unattributed` selects anonymous mapping; other opaque values,
  including similarly named strings or atoms, are attributed. The generic
  verifier returns `:unattributed`. Pass only a result from trusted verification
  code; a caller-constructed or modified struct
  cannot establish cryptographic validity or trusted identity.

  The returned `RequestSeal.Ash.Scope` always requests `authorize?: true`.
  Actor mapping grants no authority: Ash policies decide whether an action runs.
  Per [Ash's scope contract](https://hexdocs.pm/ash/3.34.5/Ash.Scope.html), explicit
  actor, tenant, and authorization options take precedence over scope values;
  passing `authorize?: false` explicitly is the caller's own authorization bypass.
  Explicit context is deep merged by Ash, so callers also own any overrides.

  Tenant scoping constrains queries, not records already loaded under another
  tenant on primary-key data layers such as ETS. A loaded foreign-tenant record
  can still be destroyed by primary key. `Ash.destroy` can seed an explicit
  tenant from loaded-record metadata before resolving the scope; pass the
  intended `tenant:` explicitly (or use `Scope.to_opts/1`). For destroy and update
  actions, add a caller-owned policy check for the `tenant_id == ^tenant()`
  condition alongside
  the action's permission checks. Check the original record's tenant against the
  action tenant before mutation, for example with an `Ash.Policy.SimpleCheck`;
  a query filter alone does not enforce that check on a loaded record. See
  [Ash policies](https://hexdocs.pm/ash/3.34.5/policies.html) and
  [tenant expressions](https://hexdocs.pm/ash/3.34.5/Ash.Expr.html#tenant/0).

  The caller owns the actor value. RequestSeal's default scope inspection,
  projected context, and binding errors exclude it; actor options intentionally
  carry it into Ash. Ash's own Forbidden `inspect` and enabled policy-breakdown
  messages and logs can show the actor. Map principals to a minimal non-secret
  actor or give the actor a custom `Inspect` implementation. Configure
  [Ash policy breakdowns](https://hexdocs.pm/ash/3.34.5/policies.html#policy-breakdowns)
  with that disclosure in mind.

  Context contains only `request_seal` facts: selected `label`, `profile`, the
  `:attributed` or `:unattributed` principal classification, canonical `covered`
  identifier strings, `content: :not_required | :checked`,
  `freshness: :not_evaluated | :evaluated`, and `replay: :not_required | :claimed`.
  A `RequestSeal.Replay.Receipt` projects only to `:claimed`; context never includes
  receipt contents, the principal value, keyid, parameters, message bytes, or keys.
  Label and covered identifiers retain the core's 256-byte label, 256-component,
  and 65,536-byte aggregate limits. These facts are policy input, not an
  authorization decision or telemetry labels.

  Errors use the `:binding` layer: `:invalid_verification`, `:invalid_binding`,
  `:unattributed`, `:actor_unbound`, or `:tenant_unbound`. Callback errors, malformed
  results, raises, throws, and exits retain no callback text. See `RequestSeal.Error`.

  The core mapping and `RequestSeal.Ash.Scope.to_opts/1` require no Ash dependency.
  The optional protocol implementation follows the public
  [Ash scope protocol](https://hexdocs.pm/ash/3.34.5/Ash.Scope.ToOpts.html).
  """

  alias RequestSeal.{Error, SignatureFields, Verification}
  alias RequestSeal.Ash.Scope
  alias RequestSeal.Replay.Receipt

  @type binding :: %{
          actor: (term() -> {:ok, term()} | :error),
          unattributed: :anonymous | :reject,
          tenant: :none | {:value, term()} | (term() -> {:ok, term()} | :error)
        }

  @doc "Maps verified facts and explicit caller bindings to an authorization-enabled scope."
  @spec scope(Verification.t(), binding()) :: {:ok, Scope.t()} | {:error, Error.t()}
  def scope(verification, binding) do
    cond do
      not valid_verification?(verification) ->
        error(:invalid_verification)

      not valid_binding?(binding) ->
        error(:invalid_binding)

      verification.principal == :unattributed and binding.unattributed == :reject ->
        error(:unattributed)

      true ->
        with {:ok, actor} <- actor(verification.principal, binding.actor),
             {:ok, tenant} <- tenant(verification.principal, binding.tenant) do
          principal =
            if verification.principal == :unattributed, do: :unattributed, else: :attributed

          {:ok,
           %Scope{
             actor: actor,
             tenant: tenant,
             principal: principal,
             authorize?: true,
             context: %{
               request_seal: %{
                 label: verification.label,
                 profile: verification.profile,
                 principal: principal,
                 covered: verification.signature.covered,
                 content:
                   if(verification.content == :not_required, do: :not_required, else: :checked),
                 freshness:
                   if(verification.freshness == :not_evaluated,
                     do: :not_evaluated,
                     else: :evaluated
                   ),
                 replay:
                   if(verification.replay == :not_required, do: :not_required, else: :claimed)
               }
             }
           }}
        end
    end
  end

  defp valid_verification?(%Verification{
         signature: %{crypto: :valid, covered: covered},
         authorization: :not_evaluated,
         label: label,
         profile: profile,
         content: content,
         freshness: freshness,
         principal: principal,
         replay: replay
       }) do
    principal not in [nil, false] and
      SignatureFields.label?(label) and profile?(profile) and
      covered?(covered, 0, 0) and
      (replay == :not_required or match?(%Receipt{}, replay)) and
      (content == :not_required or
         match?(
           %{kind: kind, checked: [_ | _], bytes: _, unsupported: _}
           when kind in [:content, :representation],
           content
         )) and
      (freshness == :not_evaluated or
         match?(
           %{now: now, created: _, expires: _, max_age: _, skew: _}
           when is_integer(now),
           freshness
         ))
  end

  defp valid_verification?(_), do: false

  defp profile?(%{name: :rfc9421} = p), do: map_size(p) == 1

  defp profile?(
         %{name: :web_bot_auth, revision: "draft-ietf-webbotauth-httpsig-protocol-00"} = p
       ),
       do: map_size(p) == 2

  defp profile?(_), do: false

  defp covered?([], _, _), do: true

  defp covered?([identifier | rest], count, bytes)
       when is_binary(identifier) and count < 256 and byte_size(identifier) > 0 and
              bytes + byte_size(identifier) <= 65_536,
       do: covered?(rest, count + 1, bytes + byte_size(identifier))

  defp covered?(_, _, _), do: false

  defp valid_binding?(%{actor: actor, unattributed: choice, tenant: tenant} = binding) do
    map_size(binding) == 3 and is_function(actor, 1) and choice in [:anonymous, :reject] and
      (tenant == :none or match?({:value, _}, tenant) or is_function(tenant, 1))
  end

  defp valid_binding?(_), do: false

  defp actor(:unattributed, _), do: {:ok, nil}

  defp actor(principal, fun) do
    case callback(fun, principal, :actor_unbound) do
      {:ok, actor} when not is_nil(actor) -> {:ok, actor}
      _ -> error(:actor_unbound)
    end
  end

  defp tenant(_, :none), do: {:ok, nil}
  defp tenant(_, {:value, tenant}), do: {:ok, tenant}
  defp tenant(:unattributed, _), do: {:ok, nil}

  defp tenant(principal, fun) do
    case callback(fun, principal, :tenant_unbound) do
      {:ok, tenant} -> {:ok, tenant}
      _ -> error(:tenant_unbound)
    end
  end

  defp callback(fun, principal, reason) do
    fun.(principal)
  catch
    _, _ -> error(reason)
  end

  defp error(reason), do: {:error, Error.new(reason, :binding)}
end
