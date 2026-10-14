<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture and accepted ADRs · Review when: the signing, verification, Plug, or replay API changes -->

# Test your integration

**What you will build:** Deterministic tests for an application that signs or verifies requests with RequestSeal: generated keys per test, a fixed clock, golden signature bytes, boundary checks without sleeping, and a Plug receiver driven without a server. Prerequisite: RequestSeal and ExUnit; the Plug section also needs `:plug`. Use real keys and the real library in your tests; nothing here replaces RequestSeal with a stand-in.

## Generate keys per test

Create keys inside the test and release them when it ends. In an ExUnit `setup` block, call `RequestSeal.Custody.Local.release/1` from `on_exit/1`. The examples below check results with pattern matches so they run anywhere; in your tests, write the same checks with `assert`:

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]
```

## Fix the clock and the nonce

Signing accepts `clock:` and `nonce:`; the policy's freshness takes its own clock. With both fixed, Ed25519 signing is deterministic, so a test can compare exact header bytes. Use a fixed nonce only in tests: production signing must use fresh entropy for every request.

```elixir
created = 1_790_000_000
nonce = :binary.copy(<<7>>, 32)

{:ok, message} =
  RequestSeal.Message.request(
    "POST",
    "https://inventory.example.com/restock",
    [{"content-type", "application/json"}],
    ~s({"sku":"LAMP-9","quantity":12}),
    digest: ["sha-256"]
  )

spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60, keyid: "test-key"}
sign = fn -> RequestSeal.sign(message, spec, handle, clock: fn -> created end, nonce: nonce) end

{:ok, first} = sign.()
{:ok, second} = sign.()
true = first.fields == second.fields

[signature_input] = for f <- first.fields, f.name == "Signature-Input", do: f.value
true = signature_input =~ ";created=1790000000;expires=1790000060;"
```

Store such a header as a golden value when you want to catch any change in what your application signs.

## Test acceptance and freshness boundaries

Build the policy from a clock argument so each test chooses the verifier's time. The expiration is exclusive: a request is accepted before `expires` and rejected at it, after allowing for skew:

```elixir
policy_at = fn now ->
  {:ok, policy} =
    RequestSeal.Policy.new(%{
      algorithms: ["ed25519"],
      components: components,
      key_resolver: fn
        %{keyid: "test-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
        _ -> :error
      end,
      freshness: %{clock: fn -> now end, max_age: 60, skew: 0, require_expires: true},
      content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
      replay: :not_required
    })

  policy
end

{:ok, verification} = RequestSeal.verify(first, policy_at.(created + 59), label: "sig")
:valid = verification.signature.crypto
["sha-256"] = verification.content.checked
:not_evaluated = verification.authorization

{:error, %RequestSeal.Error{reason: :expired, layer: :freshness}} =
  RequestSeal.verify(first, policy_at.(created + 60), label: "sig")
```

For every other rejection your application must handle, the [errors guide](errors.md) has a table of changes and the exact `reason` and `layer` each produces; copy the rows you rely on into your own tests.

## Drive a Plug receiver without a server

`Plug.Test` connections run through `RequestSeal.Plug.Capture` and `RequestSeal.Plug.Verify` in the test process. Put the signed headers on the connection with the same body:

```elixir
deliver = fn request, body ->
  conn =
    Enum.reduce(request.fields, Plug.Test.conn(:post, "https://inventory.example.com/restock", body), fn field, conn ->
      Plug.Conn.put_req_header(conn, String.downcase(field.name), field.value)
    end)

  RequestSeal.Plug.Capture.call(conn, RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: 65_536, read_timeout: 5_000))
  |> RequestSeal.Plug.Verify.call(
    RequestSeal.Plug.Verify.init(policy: policy_at.(created + 1), label: "sig", on_reject: {:halt, 401})
  )
end

accepted = deliver.(first, ~s({"sku":"LAMP-9","quantity":12}))
false = accepted.halted
{:ok, %RequestSeal.Verification{}} = RequestSeal.Plug.verification(accepted)

rejected = deliver.(first, ~s({"sku":"LAMP-9","quantity":120}))
{true, 401} = {rejected.halted, rejected.status}
```

In your application, call your own endpoint or router module the same way so the test covers your plug order, including `Plug.Parsers` with Capture's body reader.

## Test single use with a per-test store

Start an ETS replay store in the test and stop it at the end. A second verification of the same request must reject:

```elixir
{:ok, store} = RequestSeal.Replay.ETS.start_link(max_entries: 100)

replay = %{
  identifier: :nonce,
  namespace: "inventory-tests",
  commitment: fn facts -> {:ok, facts.identifier} end,
  store: RequestSeal.Replay.ETS.store(store),
  timeout: 5_000
}

{:ok, once} = RequestSeal.Policy.new(%{Map.from_struct(policy_at.(created + 1)) | replay: replay})
{:ok, _} = RequestSeal.verify(first, once, label: "sig")
{:error, %RequestSeal.Error{reason: :replayed}} = RequestSeal.verify(first, once, label: "sig")

GenServer.stop(store)
:ok = RequestSeal.Custody.Local.release(handle)
```

These tests show your code and RequestSeal agree with each other. They do not show that a deployed peer accepts your requests; [testing and evidence](testing.md) explains what each kind of evidence establishes.
