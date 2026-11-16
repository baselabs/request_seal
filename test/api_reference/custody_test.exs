defmodule RequestSeal.APIReference.CustodyTest do
  use ExUnit.Case, async: true

  doctest RequestSeal.Custody.Context
  doctest RequestSeal.Custody.Local
  doctest RequestSeal.Custody.Local.Owner
  doctest RequestSeal.Custody.SSHAgent
  doctest RequestSeal.Crypto
  doctest RequestSeal.PublicKey
  doctest RequestSeal.KeyIdentity
end
