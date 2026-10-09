defmodule RequestSeal.PublicAPIDocumentationTest do
  use ExUnit.Case, async: true
  doctest RequestSeal.Custody
  doctest RequestSeal.Replay.Claim
  doctest RequestSeal.Profile
  doctest RequestSeal.JOSE.JWS
  doctest RequestSeal.JOSE.JWE
end
