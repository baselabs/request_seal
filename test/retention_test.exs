defmodule RequestSeal.RetentionTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Crypto, Message, Policy, PublicKey, Replay, WebBotAuth}
  alias RequestSeal.Replay.{Claim, ETS, Store}
  @max 253_402_300_799

  # Count actual adapter calls while retaining the real ETS claim semantics.
  defmodule CountingStore do
    @behaviour Replay
    def claim({pid, calls}, claim, context) do
      :atomics.add(calls, 1, 1)
      ETS.claim(pid, claim, context)
    end

    def sweep({pid, _}, now, context), do: ETS.sweep(pid, now, context)
  end

  setup do
    pid = start_supervised!({ETS, max_entries: 32})
    calls = :atomics.new(2, [])
    store = %Store{adapter: CountingStore, ref: {pid, calls}}
    {:ok, key} = PublicKey.import(File.read!("test/fixtures/crypto/ed25519_public.pem"), :pem)
    [store: store, calls: calls, key: key]
  end

  test "generic and Web Bot Auth policies bound maximum age and skew", ctx do
    for kind <- [:generic, :web_bot_auth], {field, max} <- [max_age: @max, skew: 86_400] do
      attrs = attrs(kind, ctx, 100, nil, 0)
      inside = put_in(attrs, [:freshness, field], max)
      assert {:ok, _} = new_policy(kind, inside)
      outside = put_in(attrs, [:freshness, field], max + 1)
      assert {:error, %{reason: :invalid_policy, layer: :input}} = new_policy(kind, outside)
    end
  end

  test "generic retention checks expiration, inclusive age, and skew before storage", ctx do
    for {created, expires, age, skew, retain} <- [
          {100, @max, nil, 0, @max},
          {100, @max + 1, nil, 0, @max + 1},
          {100, nil, @max - 101, 0, @max},
          {100, nil, @max - 100, 0, @max + 1},
          {100, @max - 1, nil, 1, @max},
          {100, @max, nil, 1, @max + 1},
          {100, @max + 1, 60, 0, 161}
        ] do
      :atomics.put(ctx.calls, 1, 0)
      :atomics.put(ctx.calls, 2, 0)
      message = signed(ctx.key, created, expires, "generic-#{retain}-#{skew}-#{age}")
      {:ok, policy} = new_policy(:generic, attrs(:generic, ctx, created, age, skew))
      result = RequestSeal.verify(message, policy, label: "s")

      if retain > @max do
        assert {:error, %{reason: :retention_exceeded, layer: :replay}} = result
        assert :atomics.get(ctx.calls, 1) == 0
        assert :atomics.get(ctx.calls, 2) == 0
      else
        assert {:ok, %{replay: %{retain_until: ^retain}}} = result
        assert :atomics.get(ctx.calls, 1) == 1
        assert :atomics.get(ctx.calls, 2) == 1
      end
    end
  end

  test "Web Bot Auth applies the same expiration and skew retention bound", ctx do
    for {expires, skew, retain} <- [
          {@max, 0, @max},
          {@max + 1, 0, @max + 1},
          {@max - 1, 1, @max},
          {@max, 1, @max + 1}
        ] do
      :atomics.put(ctx.calls, 1, 0)
      :atomics.put(ctx.calls, 2, 0)
      created = @max - 60
      message = signed(ctx.key, created, expires, "wba-#{expires}-#{skew}", :web_bot_auth)
      {:ok, policy} = new_policy(:web_bot_auth, attrs(:web_bot_auth, ctx, created, nil, skew))
      result = WebBotAuth.verify(message, policy)

      if retain > @max do
        assert {:error, %{reason: :retention_exceeded, layer: :replay}} = result
        assert :atomics.get(ctx.calls, 1) == 0
        assert :atomics.get(ctx.calls, 2) == 0
      else
        assert {:ok, %{replay: %{retain_until: ^retain}}} = result
        assert :atomics.get(ctx.calls, 1) == 1
        assert :atomics.get(ctx.calls, 2) == 1
      end
    end
  end

  test "direct invalid claims keep the existing port and store failures", ctx do
    claim = %Claim{namespace: "direct", key: "nonce", retain_until: @max + 1}
    refute Claim.valid?(claim)
    assert {:error, %{reason: :invalid_claim}} = Replay.claim(ctx.store, claim, timeout: 5000)
    assert :atomics.get(ctx.calls, 1) == 0

    context = %RequestSeal.Custody.Context{
      owner: self(),
      deadline: System.monotonic_time(:millisecond) + 5000
    }

    {pid, _} = ctx.store.ref
    assert {:error, :failure} = ETS.claim(pid, claim, context)

    if Code.ensure_loaded?(Replay.Postgres) do
      assert {:error, :failure} = Replay.Postgres.claim({self(), "replay"}, claim, context)
    end
  end

  defp attrs(kind, ctx, now, age, skew) do
    replay = %{
      identifier: :nonce,
      namespace: Atom.to_string(kind),
      store: ctx.store,
      commitment: fn facts ->
        :atomics.add(ctx.calls, 2, 1)
        nonce = if kind == :generic, do: facts.identifier, else: hd(facts.signatures).identifier
        {:ok, nonce}
      end,
      timeout: 5000
    }

    common = %{
      algorithms: ["ed25519"],
      content: :not_required,
      replay: replay,
      freshness: %{clock: fn -> now end, max_age: age, skew: skew}
    }

    if kind == :generic do
      Map.merge(common, %{
        components: "()",
        key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: ctx.key}} end,
        freshness: Map.put(common.freshness, :require_expires, age == nil)
      })
    else
      Map.merge(common, %{
        agents: fn _ -> :error end,
        cache: nil,
        test_keys: :allow,
        unresolved: {:held_keys, fn _ -> {:ok, %{algorithm: "ed25519", key: ctx.key}} end}
      })
    end
  end

  defp new_policy(:generic, attrs), do: Policy.new(attrs)
  defp new_policy(:web_bot_auth, attrs), do: WebBotAuth.Policy.new(attrs)

  defp signed(key, created, expires, nonce, kind \\ :generic) do
    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)
    {:ok, thumbprint} = PublicKey.thumbprint(key)

    input =
      ~s[("@method" "@authority");created=#{created};nonce="#{nonce}"] <>
        if(expires, do: ";expires=#{expires}", else: "") <>
        if(kind == :web_bot_auth, do: ~s[;keyid="#{thumbprint}";tag="web-bot-auth"], else: "")

    [entry] = :public_key.pem_decode(File.read!("test/fixtures/crypto/ed25519_private.pem"))
    material = {:ed25519, elem(:public_key.pem_entry_decode(entry), 2)}

    {:ok, signed} =
      RequestSeal.sign(message, %{label: "s", algorithm: "ed25519", signature_input: input}, fn a,
                                                                                                b ->
        Crypto.sign(a, b, material)
      end)

    signed
  end
end
