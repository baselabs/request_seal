defmodule RequestSeal.DiscoveryBodyTest do
  use ExUnit.Case, async: true
  alias RequestSeal.Discovery
  alias RequestSeal.PropertySupport, as: P

  test "trailing JSON whitespace excludes vertical tab, form feed, and Unicode spaces" do
    body = P.jwks(1)

    for type <- [:jwks_uri, :directory] do
      source = P.source(type)

      for suffix <- [" ", "\t", "\r", "\n"] do
        assert {:ok, _} = Discovery.parse_body(body <> suffix, source, 100)
      end

      for suffix <- ["\v", "\f", "\u00a0", "\u2003"] do
        assert {:error, %Discovery.Error{reason: :invalid_response}} =
                 Discovery.parse_body(body <> suffix, source, 100)
      end
    end
  end
end
