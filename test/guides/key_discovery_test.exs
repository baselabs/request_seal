defmodule RequestSeal.GuideKeyDiscoveryTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
    {:ok, key} = RequestSeal.Custody.public_key(handle)
    binding = E.publisher(key: key)

    binding =
      E.eval(
        ~S'''
        {:ok, _apps} = Application.ensure_all_started(:ssl)

        {:ok, source} =
          RequestSeal.Discovery.Source.new(%{
            type: :jwks_uri,
            location: jwks_url,
            cacerts: trust_roots,
            permitted_addresses: permitted_addresses,
            timeout: 5_000
          })

        {:ok, key_set} = RequestSeal.Discovery.fetch(source)
        ''',
        binding,
        "docs/guides/key-discovery.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {thumbprint, _entry} = Enum.at(key_set.keys, 0)
        resolver = RequestSeal.Discovery.resolver(key_set, algorithms: ["ed25519"])
        {:ok, %{key: discovered_key}} = resolver.(%{keyid: thumbprint})

        {:ok, discovered_policy} =
          RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: ~s[("@method" "@authority" "@path" "content-digest")],
            key_resolver: resolver,
            freshness: %{
              clock: fn -> System.system_time(:second) end,
              max_age: 60,
              skew: 5,
              require_expires: true
            },
            content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
            replay: :not_required
          })
        ''',
        binding,
        "docs/guides/key-discovery.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, cache} = RequestSeal.Discovery.Cache.start_link(max_sources: 8)
        {:ok, _snapshot} = RequestSeal.Discovery.Cache.refresh(cache, source)

        {:ok, resolution} =
          RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint, algorithms: ["ed25519"])

        RequestSeal.Discovery.Cache.remove(cache, source, thumbprint)
        # => :ok
        RequestSeal.Discovery.Cache.invalidate(cache, source)
        # => :ok
        RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint, algorithms: ["ed25519"])
        # => {:error, %RequestSeal.Discovery.Error{reason: :revoked_key, ...}}
        ''',
        binding,
        "docs/guides/key-discovery.md",
        3
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert {:error, %RequestSeal.Discovery.Error{reason: :revoked_key}} = example_result
    assert Keyword.fetch!(binding, :resolution).thumbprint == Keyword.fetch!(binding, :thumbprint)
    E.assert_fences("docs/guides/key-discovery.md", 3)
    assert is_list(binding)
  end
end
