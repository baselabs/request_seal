defmodule RequestSeal.GuideKeyDiscoveryTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []
    {_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
    {:ok, key} = RequestSeal.Custody.public_key(handle)
    {:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
    binding = Keyword.merge(binding, key: key, thumbprint: thumbprint)
    binding = E.publisher(binding)
    E.configure(:my_app, :jwks_url, Keyword.fetch!(binding, :jwks_url))
    E.configure(:my_app, :trusted_key_thumbprint, Keyword.fetch!(binding, :thumbprint))
    E.configure(:my_app, :jwks_ca_roots, Keyword.fetch!(binding, :trust_roots))
    E.configure(:my_app, :jwks_permitted_addresses, Keyword.fetch!(binding, :permitted_addresses))
    code = ~S'
jwks_url = Application.fetch_env!(:my_app, :jwks_url)
thumbprint = Application.fetch_env!(:my_app, :trusted_key_thumbprint)
trust_roots = Application.fetch_env!(:my_app, :jwks_ca_roots)
permitted_addresses = Application.fetch_env!(:my_app, :jwks_permitted_addresses)
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
'
    binding = E.eval(code, binding)
    code = ~S'
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
'
    binding = E.eval(code, binding)
    code = ~S'
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
'
    {example_result, binding} = Code.eval_string(code, binding)
    assert {:error, %RequestSeal.Discovery.Error{reason: :revoked_key}} = example_result
    assert Keyword.fetch!(binding, :resolution).thumbprint == Keyword.fetch!(binding, :thumbprint)
    assert is_list(binding)
  end
end
