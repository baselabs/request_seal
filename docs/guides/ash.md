# Map verified requests to Ash actors and tenants

**What you will build:** An Ash resource with tenant isolation and a reader policy, plus a scope that maps a verified Web Bot Auth key to the actor and tenant for a read. Install Ash (`>= 3.38.1 and < 4.0.0`) and RequestSeal; all keys and request values are defined below. This example uses the public [Ash scope contract](https://hexdocs.pm/ash/3.37.2/Ash.Scope.html) and [Ash policies](https://hexdocs.pm/ash/3.37.2/policies.html).

## Before you start

In a Mix project with RequestSeal installed, add `{:ash, ">= 3.38.1 and < 4.0.0"}` and a SAT solver, which Ash policies need, such as `{:simple_sat, "~> 0.1"}`, then run `mix deps.get`. `simple_sat` keeps this example portable. See the [Ash policy authorizer](https://hexdocs.pm/ash/Ash.Policy.Authorizer.html) for solver choices in production. Ash requires an explicit string-length setting. Add `config :ash, default_string_length_count: :codepoints` to `config/config.exs` after `import Config` ([Ash configuration](https://hexdocs.pm/ash/backwards-compatibility-config.html#default_string_length_count)). Put the resource and domain modules in step 1 in files under `lib/`, and run the rest in `iex -S mix`.

## Verify the caller

Generate an example Ed25519 key. In your application, reuse a long-lived key handle and configure trust in its public key independently.

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = handle
```

Build the request once, retaining its exact JSON bytes and digest. This held-key policy leaves body integrity unchecked:

```elixir
{:ok, message} =
  RequestSeal.Message.request(
    "POST",
    "https://api.example.com/webhooks",
    [],
    ~s({"event":"created"}),
    digest: ["sha-256"]
  )
```

Sign the request as an agent:

```elixir
now = System.system_time(:second)

{:ok, agent_request} =
  RequestSeal.WebBotAuth.sign(
    message,
    %{
      label: "agent",
      agent: %{location: "https://agent.example", type: :directory},
      key: key,
      algorithm: "ed25519",
      created: now,
      expires: now + 60,
      nonce: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    },
    signer
  )
```

Trust the held key by its thumbprint, then verify the agent request:

```elixir
{:ok, agent_policy} =
  RequestSeal.WebBotAuth.Policy.new(%{
    algorithms: ["ed25519"],
    agents: fn _ -> :error end,
    cache: nil,
    unresolved:
      {:held_keys,
       fn
         %{keyid: ^thumbprint} -> {:ok, %{algorithm: "ed25519", key: key}}
         _ -> :error
       end},
    freshness: %{clock: fn -> System.system_time(:second) end, max_age: 60, skew: 5},
    content: :not_required,
    replay: :not_required
  })

{:ok, envelope} = RequestSeal.WebBotAuth.verify(agent_request, agent_policy)
verification = envelope.signatures["agent"]
```

## 1. Define a resource with a read policy

```elixir
defmodule AshApp.Document do
  use Ash.Resource,
    domain: AshApp.Documents,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(false)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:tenant_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:tenant_id, :string, allow_nil?: false)
  end

  actions do
    defaults([:read])
  end

  policies do
    policy action_type(:read) do
      authorize_if(actor_attribute_equals(:role, :reader))
    end
  end
end
```

Register the resource in an Ash domain:

```elixir
defmodule AshApp.Documents do
  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(AshApp.Document)
  end
end
```

This ETS resource stores documents by tenant and permits reads by a reader actor. Replace it with your resource and your access rules.

For a Plug connection with an accepted [signed-path binding](phoenix-and-plug.md),
call `RequestSeal.Plug.Scope.ash_scope(conn, binding)` with the usual actor and
unattributed choices. The tenant comes from the bound path and still flows through
the resource's multitenancy and policy checks. Tenant agreement does not
create an attributed signer. For loaded records, use `Scope.to_opts/1` or
pass the bound tenant explicitly so record metadata cannot select a different
tenant. Keep a resource policy that checks the original record's tenant.

## 2. Map the trusted principal and run an authorized read

```elixir
{:ok, scope} =
  RequestSeal.Ash.scope(verification, %{
    actor: fn
      %{kind: :key, thumbprint: ^thumbprint} -> {:ok, %{role: :reader}}
      _ -> :error
    end,
    tenant: {:value, "demo"},
    unattributed: :reject
  })

documents = Ash.read!(AshApp.Document, scope: scope, authorize?: true)
```

A held-key Web Bot Auth result binds only the trusted thumbprint; URL attribution requires trusted discovery. Never construct or modify a verification struct to manufacture attribution. Generic RFC 9421 returns `:unattributed`; `unattributed: :anonymous` creates a nil actor without invoking your actor callback, while `:reject` rejects it. Tenant choices are `:none`, `{:value, tenant}`, or a function of an attributed principal. The explicit tenant here is application configuration.

## Options and policy boundaries

The scope always requests `authorize?: true`. `RequestSeal.Ash.Scope.to_opts/1` produces actor, tenant, context, and authorization options without requiring Ash; when Ash is compiled in, `scope: scope` uses its protocol. If you add Ash after compiling RequestSeal, run `mix deps.compile request_seal --force`.

Ash's explicit actor, tenant, and authorization options override scope values; do not pass `authorize?: false` on an authenticated action. Context contains only bounded verification facts, excluding principal values, parameters, key IDs, bytes, keys, and receipt contents. A replay receipt becomes `replay: :claimed`.

Tenant filters constrain reads, not records already loaded under another tenant. For update/destroy actions, enforce the original record's tenant against the action tenant in your policies, and pass the intended `tenant:` explicitly or use `Scope.to_opts/1`. A query filter alone cannot guard a loaded record mutation. Map principals to minimal non-secret actors: Ash Forbidden inspection and enabled policy-breakdown logs can expose your actor.

## Errors

| Reason | Meaning and action |
| --- | --- |
| `:unattributed` | Select anonymous access explicitly or use trusted identity attribution. |
| `:actor_unbound` | Your actor mapping rejected or returned a malformed/nil actor. |
| `:tenant_unbound` | Your tenant mapping failed. |
| `:invalid_binding` | Provide exactly actor, tenant, and unattributed choices. |
| `:invalid_verification` | Pass a successful trusted core result with valid bounded facts. |

These errors use the `:binding` layer and retain no callback text. `Ash.Error.Forbidden` is a separate authorization denial by your resource's policies.

Module docs: `RequestSeal.Ash`, `RequestSeal.Ash.Scope`, `RequestSeal.Verification`, `RequestSeal.Error`.
