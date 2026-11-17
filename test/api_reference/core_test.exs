defmodule RequestSeal.APIReference.CoreTest do
  use ExUnit.Case, async: true

  doctest RequestSeal.Policy
  doctest RequestSeal.AcceptSignature
  doctest RequestSeal.SignatureBase
  doctest RequestSeal.Telemetry
end
