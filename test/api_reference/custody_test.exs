defmodule RequestSeal.APIReference.CustodyTest do
  use ExUnit.Case, async: true

  # RequestSeal.Custody is doctested by test/public_api_documentation_test.exs.
  doctest RequestSeal.Custody.Context
  doctest RequestSeal.Custody.Local
  doctest RequestSeal.Custody.Local.Owner
  doctest RequestSeal.Custody.SSHAgent
  doctest RequestSeal.Crypto
  doctest RequestSeal.PublicKey
  doctest RequestSeal.KeyIdentity
end
