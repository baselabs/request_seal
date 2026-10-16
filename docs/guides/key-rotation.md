<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture · Review when: custody, key resolution, or discovery cache behavior changes -->

# Rotate signing keys

**What you will build:** A sender that moves from one Ed25519 key to the next without rejected requests, and a verifier that accepts both keys during the overlap and then retires the old one. Prerequisite: RequestSeal installed; no framework or network is needed. Keys live in a supervised `RequestSeal.Custody.Local.Owner`, as [key custody](key-custody.md) describes.

Rotation has four steps: add the new key next to the old one, trust both on the verifier, switch the signer, then stop trusting and holding the old key.

## 1. Add the new key next to the old one

The Owner reads seed files with mode 0600 or stricter. This example writes two generated seeds to a temporary directory; in production you provision the files separately and never generate them in the application.

```elixir
alias RequestSeal.Custody.Local.Owner

seed_dir = Path.join(System.tmp_dir!(), "rotation-#{System.unique_integer([:positive])}")
File.mkdir_p!(seed_dir)

write_seed = fn name ->
  {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
  path = Path.join(seed_dir, name)
  File.write!(path, Base.url_encode64(seed, padding: false))
  File.chmod!(path, 0o600)
  path
end

current_file = write_seed.("current.seed")
next_file = write_seed.("next.seed")

{:ok, supervisor} =
  Supervisor.start_link(
    [
      {Owner,
       name: Rotation.Custody,
       keys: [
         current: {"ed25519", {:file, current_file, :base64url}},
         next: {"ed25519", {:file, next_file, :base64url}}
       ]}
    ],
    strategy: :one_for_one
  )

%{current: :ready, next: :ready} = Owner.status(Rotation.Custody)
```

Publish the new public key wherever verifiers find keys. For a JWKS or a Web Bot Auth key directory, export it as a JWK; its thumbprint is the Web Bot Auth key ID:

```elixir
{:ok, next_handle} = RequestSeal.Custody.Local.Owner.fetch(Rotation.Custody, :next)
{:ok, next_key} = RequestSeal.Custody.public_key(next_handle)
{:ok, next_jwk} = RequestSeal.PublicKey.export(next_key, :jwk)
{:ok, next_thumbprint} = RequestSeal.PublicKey.thumbprint(next_key)
%{"kty" => "OKP", "crv" => "Ed25519"} = next_jwk
```

## 2. Trust both keys on the verifier

The verifier's resolver maps each key ID to a configured key. During the overlap it accepts either:

```elixir
{:ok, current_handle} = RequestSeal.Custody.Local.Owner.fetch(Rotation.Custody, :current)
{:ok, current_key} = RequestSeal.Custody.public_key(current_handle)
components = ~s[("@method" "@scheme" "@authority" "@path")]

policy_for = fn trusted ->
  {:ok, policy} =
    RequestSeal.Policy.new(%{
      algorithms: ["ed25519"],
      components: components,
      key_resolver: fn %{keyid: keyid} ->
        case Map.fetch(trusted, keyid) do
          {:ok, key} -> {:ok, %{algorithm: "ed25519", key: key}}
          :error -> :error
        end
      end,
      freshness: %{
        clock: fn -> System.system_time(:second) end,
        max_age: 60,
        skew: 5,
        require_expires: true
      },
      content: :not_required,
      replay: :not_required
    })

  policy
end

overlap_policy = policy_for.(%{"build-2" => current_key, "build-3" => next_key})
```

## 3. Switch the signer

Fetch the handle for each signing operation and change the key ID together with the key. Requests signed before the switch still verify during the overlap:

```elixir
sign_with = fn name, keyid ->
  {:ok, handle} = RequestSeal.Custody.Local.Owner.fetch(Rotation.Custody, name)
  {:ok, message} = RequestSeal.Message.request("POST", "https://ci.example.com/artifacts", [], nil)
  spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60, keyid: keyid}
  RequestSeal.sign(message, spec, handle)
end

{:ok, before_switch} = sign_with.(:current, "build-2")
{:ok, after_switch} = sign_with.(:next, "build-3")
{:ok, _} = RequestSeal.verify(before_switch, overlap_policy, label: "sig")
{:ok, _} = RequestSeal.verify(after_switch, overlap_policy, label: "sig")
```

Keep trusting the old key until no signature it made can still be accepted. A signature created at second `C` with the signer's `expires_in` passes the expiry check while the verifier's clock is below `C + expires_in + skew`, and, when the policy sets `max_age`, passes the age check while the clock is at most `C + max_age + skew`. Both checks apply, so the tighter one governs: keep the overlap for at least `min(expires_in, max_age) + skew` seconds after the last request signed with the old key (`expires_in + skew` when the policy has no `max_age`). In this example that is `min(60, 60) + 5`, or 65 seconds.

## 4. Retire the old key

Remove the old key ID from the verifier. A request still signed with it now rejects as an unknown key:

```elixir
retired_policy = policy_for.(%{"build-3" => next_key})
{:ok, _} = RequestSeal.verify(after_switch, retired_policy, label: "sig")

{:error, %{reason: :unknown_key, layer: :key}} =
  RequestSeal.verify(before_switch, retired_policy, label: "sig")
```

Then remove the old seed from the Owner's configuration and restart the Owner. A restart rereads every source and ends every handle it issued, so a cached handle reports `:key_not_found`; fetch a new one:

```elixir
:ok = Supervisor.terminate_child(supervisor, Rotation.Custody)
File.rm!(current_file)
{:ok, _} = Supervisor.restart_child(supervisor, Rotation.Custody)

%{current: :unconfigured, next: :ready} = RequestSeal.Custody.Local.Owner.status(Rotation.Custody)

{:error, %{reason: :signing_failed, source: %{reason: :key_not_found}}} =
  RequestSeal.sign(before_switch, %{label: "late", algorithm: "ed25519", components: components, expires_in: 60}, next_handle)

{:ok, _} = sign_with.(:next, "build-3")
:ok = Supervisor.stop(supervisor)
File.rm_rf!(seed_dir)
```

In a deployment, remove the `current` entry from the child specification instead of leaving it unconfigured.

## Discovered keys

When verifiers fetch keys from a JWKS URI or a key directory, publish the new key before signing with it, and remove the old key after the overlap. Verifiers using `RequestSeal.Discovery.Cache` pick up changes on refresh; `RequestSeal.Discovery.Cache.refresh/2` forces one, and `RequestSeal.Discovery.Cache.remove/3` revokes a thumbprint immediately. [Key discovery](key-discovery.md) shows both against a real HTTPS publisher.

For decryption keys, import the new recipient handle, check it with `RequestSeal.Custody.public_key/1`, let your JWE key resolver choose among the configured handles, and release the old handle once no message for it can still arrive. See [JOSE](jose.md).
