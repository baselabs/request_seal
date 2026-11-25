# Verifying a signature quorum

Use a quorum when several trusted signers must approve the same request.
Give each signer slot its own full verification policy. One signature cannot
satisfy two slots, and two labels for the same key cannot count twice. Use a
shared nonce when the signers coordinate on an attempt. Use mandatory operation
components when independent signatures should approve the same single-use
operation.

This example requires two distinct Ed25519 signers and claims the operation
once, using its method and target. It uses an empty GET request so there is no
body to authenticate.

```elixir
alias RequestSeal.{Custody, Message, Policy, Quorum, Replay}

now = System.system_time(:second)
clock = fn -> now end
components = ~s[("@method" "@target-uri")]
{:ok, message} = Message.request("GET", "https://api.example.test/jobs/7", [], nil)
{:ok, store} = Replay.ETS.start_link(max_entries: 100)

{signed, slots, handles} =
  Enum.reduce([:build, :review], {message, [], []}, fn id, {message, slots, handles} ->
    {:ok, handle} = Custody.Local.generate("ed25519", [])
    {:ok, key} = Custody.public_key(handle)
    label = Atom.to_string(id)
    spec = %{label: label, components: components, algorithm: "ed25519", expires_in: 60}
    {:ok, message} = RequestSeal.sign(message, spec, handle, clock: clock)

    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: components,
        key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
        freshness: %{clock: clock, max_age: 60, skew: 0, require_expires: true},
        content: :not_required,
        replay: :not_required
      })

    slot = %{id: id, label: label, required: true, policy: policy}
    {message, [slot | slots], [handle | handles]}
  end)

{:ok, quorum} =
  Quorum.new(%{
    slots: slots,
    mode: :all,
    unit: :key,
    invalid: :reject,
    unexpected: :reject,
    replay: %{
      identifier: {:operation, [~s["@method"], ~s["@target-uri"]]},
      scope: :namespace,
      namespace: "jobs",
      retain_until: now + 120,
      store: Replay.ETS.store(store),
      timeout: 1_000
    }
  })

{:ok, %Quorum.Verification{count: 2}} = RequestSeal.verify_quorum(signed, quorum, [])
{:error, %RequestSeal.Error{reason: :replayed}} =
  RequestSeal.verify_quorum(signed, quorum, [])
Enum.each(handles, fn handle -> :ok = Custody.Local.release(handle) end)
:ok = GenServer.stop(store)
```

Every required slot must qualify. In a threshold policy, `:unit` says whether
to count distinct keys, configured principals, or roles. Every assigned
signature needs a known key identity in all counting modes. Use
`{:role, shared_principal: false}` to require distinct principals across
counted roles. Principal and role facts come from a slot's trusted resolver
configuration. HMAC handles need explicit opaque equivalence identities for
independent signing. Nested bindings can require the outer signer to cover both inner
signature dictionary members. Same-parameter bindings require a common
authenticated value among their referenced slots. Pass parsed
`Accept-Signature` requests as `:accept_signature` to require a qualifying
candidate for each challenge before the claim.

Choose a namespace that names the verifier trust boundary. Under
`scope: :principals`, scope additionally commits to the complete configured
principal set, even for an optional slot that supplies no signature.
The retention end is fixed for the boundary. Share that setting across all
verifiers and account for clock skew and in-flight verification when sweeping.

With shared nonce replay, confirm all signers cover the intended scope and
payload, and coordinate so they use the same unique nonce. For operation
replay, require the same complete operation-defining coverage in every slot,
including a checked Content-Digest for requests with bodies. Set the same
schema in every slot for each structured operation field. Adding an optional
signer cannot change the replay key of an otherwise accepted request.
Give every slot the same trusted clock function. The verifier reads it once,
after wire admission, and applies each slot's freshness rules at that instant.
Any two signatures assigned together must be fresh at that instant under
their slot policies.

Verification admits up to 128 eligible label-slot pairs. Construction checks
required and bound slots, distinct counted units, and label and tag selectors
to determine whether a satisfying assignment can fit that limit. Extra signatures on the
wire can exhaust it even when the policy is valid. Use label or tag selectors
to constrain matching. A supplied absolute monotonic deadline bounds
callbacks and assignment, and caps the replay store deadline. A remaining
interval above 4,294,967,295 milliseconds is invalid.
The replay store refuses a claim whose retention ends at or before its
greatest sweep cutoff, even if verification started before the sweep. The verifier
returns a replay receipt after the quorum verdict. Application
authorization and effect uniqueness remain separate decisions.
