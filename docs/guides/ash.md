<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Map verified requests to Ash actors and tenants

**What you will build:** An Ash resource with tenant isolation and a reader policy, plus a scope that maps a verified Web Bot Auth key to the actor and tenant for a read. Install Ash (`~> 3.34`) and RequestSeal; all keys and request values are defined below. This example uses the public [Ash scope contract](https://hexdocs.pm/ash/3.34.5/Ash.Scope.html) and [Ash policies](https://hexdocs.pm/ash/3.34.5/policies.html).

## Verify the caller

Generate an example Ed25519 key. In your application, reuse a long-lived key handle and configure trust in its public key independently.

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
```

Retain a JSON request body and include its digest header. The held-key example below verifies the signing key; its policy leaves body integrity unchecked:

```elixir
{:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ~s({"event":"created"})})
{:ok, digest} = RequestSeal.Digest.compute(body, ["sha-256"])
{:ok, digest_wire} = RequestSeal.Digest.serialize(digest)

{:ok, digest_field} =
  RequestSeal.FieldOccurrence.new(%{
    name: "content-digest",
    value: digest_wire,
    section: :headers
  })
```

Construct the request message:

```elixir
{:ok, transport} = RequestSeal.TransportFacts.new(%{})

{:ok, message} =
  RequestSeal.Message.new(%{
    kind: :request,
    method: "POST",
    raw_target: "/webhooks",
    target_form: :origin,
    scheme: "https",
    authority: "api.example.com",
    fields: [digest_field],
    trailers: :unavailable,
    body: body,
    transport: transport
  })
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
