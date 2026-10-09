defmodule RequestSeal.ReplayClaimTest do
  use ExUnit.Case, async: true
  alias RequestSeal.Replay.Claim

  test "validates byte and signed integer bounds without clock evaluation" do
    for bytes <- [<<255>>, :binary.copy(<<0>>, 256)],
        until <- [-9_223_372_036_854_775_808, -1, 0, 9_223_372_036_854_775_807] do
      assert Claim.valid?(%Claim{namespace: bytes, key: bytes, retain_until: until})
    end
  end

  test "rejects malformed claims without changing the existing predicate" do
    claim = %Claim{namespace: "scope", key: "nonce", retain_until: 0}

    for field <- [:namespace, :key], invalid <- ["", :binary.copy(<<0>>, 257), nil, [], :scope] do
      refute Claim.valid?(Map.put(claim, field, invalid))
    end

    for until <- [-9_223_372_036_854_775_809, 9_223_372_036_854_775_808, nil, 0.0, "0"] do
      refute Claim.valid?(%{claim | retain_until: until})
    end

    for invalid <- [nil, %Claim{}, Map.from_struct(claim), Map.put(claim, :extra, true)] do
      refute Claim.valid?(invalid)
    end
  end
end
