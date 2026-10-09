Code.require_file("support/discovery_peer_helper.exs", __DIR__)

defmodule RequestSeal.WebBotAuthTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Body, Message, PublicKey, SignatureBase, SignatureFields, WebBotAuth}
  alias RequestSeal.WebBotAuth.Policy
  alias RequestSeal.Discovery.{Source, KeySet, Resolution, Cache}
  alias RequestSeal.DiscoveryPeer, as: Peer
  alias RequestSeal.MultiSignatureSupport, as: S
  alias RequestSeal.Replay.ETS
  @root Path.join(__DIR__, "fixtures/web_bot_auth")
  @published :json.decode(File.read!(Path.join(@root, "protocol-00.json")))
  @requests :json.decode(File.read!(Path.join(@root, "requests.json")))
  @implementation :json.decode(File.read!(Path.join(@root, "web_bot_auth_architecture_v2.json")))
  @now 1_735_689_600
  @revision "draft-ietf-webbotauth-httpsig-protocol-00"

  # Protocol-00 E.1.1 and E.2.1 use sig2 with agent2, contradicting Section
  # 5.2.1's member keyed to the signature label. Their 3,153,600,000-second
  # lifetimes exceed this policy's ceiling and Section 5.2's recommended 24 hours.
  # Keep the published bytes for generic cryptography and profile rejection.
  test "published bases and signatures remain exact through generic verification" do
    for v <- Enum.filter(@published, &(&1["section"] in ["E.1.1", "E.2.1"])) do
      m = published(v)
      input = input(m, "sig2")
      assert {:ok, v["base"]} == SignatureBase.build(m, input, field_schemas: schemas())

      p =
        S.policy(
          key_resolver: fn _ ->
            {:ok, %{algorithm: v["algorithm"], key: public(v["algorithm"])}}
          end,
          field_schemas: schemas()
        )

      assert {:ok, %{signature: %{crypto: :valid}, principal: :unattributed}} =
               RequestSeal.verify(m, p, label: "sig2")

      assert_error(WebBotAuth.verify(m, policy()), :agent_unresolved, :key, :missing_member)

      corrected =
        resign(
          S.rewrite(m, fn _, b -> String.replace(b, "agent2", "sig2") end),
          "sig2",
          v["algorithm"]
        )

      assert_error(WebBotAuth.verify(corrected, policy()), :lifetime_exceeded, :freshness)
    end

    v = Enum.find(@published, &(&1["section"] == "E.2.1"))
    scratch = Path.join(System.tmp_dir!(), "wba-base-#{System.unique_integer([:positive])}")
    File.write!(scratch, v["base"])
    on_exit(fn -> File.rm!(scratch) end)

    {signature, 0} =
      System.cmd("openssl", [
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        "test/fixtures/crypto/ed25519_private.pem",
        "-in",
        scratch
      ])

    assert "sig2=:" <> Base.encode64(signature) <> ":" ==
             Enum.at(Enum.find(v["fields"], fn [n, _] -> n == "Signature" end), 1)
  end

  test "independent signer requests expose complete source-bound layered facts" do
    for name <- ~w(directory jwks_uri cimd target-uri rsa content nested) do
      m = request(name)

      p =
        if name == "content",
          do: policy(content: %{kind: :content, algorithms: ["sha-256"], section: :headers}),
          else: policy()

      assert {:ok, result} = WebBotAuth.verify(m, p)
      assert result.profile == %{name: :web_bot_auth, revision: @revision}
      assert result.authorization == :not_evaluated
      assert result.replay == :not_required
      assert result.ignored == []

      for {label, verification} <- result.signatures do
        assert verification.label == label
        assert verification.profile == result.profile
        assert verification.signature.crypto == :valid
        assert verification.principal.kind == :agent

        assert verification.principal.identifier in [
                 "https://signature-agent.test/.well-known/http-message-signatures-directory",
                 "https://signature-agent.test/keys",
                 "https://browser.example/.well-known/http-message-signatures-directory"
               ]

        assert verification.principal.provenance.proof == :unsigned
        assert verification.principal.provenance.revision == "independent-key-set"
        assert verification.freshness.created == @now
        assert verification.freshness.expires == @now + 3600
        assert verification.authorization == :not_evaluated

        {:ok, scope} =
          RequestSeal.Ash.scope(verification, %{
            actor: fn principal -> {:ok, principal.kind} end,
            tenant: :none,
            unattributed: :reject
          })

        assert scope.actor == :agent
        assert scope.context.request_seal.profile == result.profile
      end

      if name == "nested", do: assert(result.evidence["browser"] == ["agent"])
      if name == "content", do: assert(result.signatures["agent"].content.checked == ["sha-256"])
      assert inspect(result) =~ "labels:"
      assert inspect(result) =~ "\"agent\""
      refute inspect(result) =~ "signatures:"
      refute inspect(result) =~ "signature-agent.test"
      refute inspect(result) =~ "poqkLG"
    end
  end

  test "independent signer bases match every stored byte" do
    for v <- @requests do
      m = request(v["name"])
      label = if v["name"] in ["nested", "nested-incomplete"], do: "browser", else: "agent"
      assert SignatureBase.build(m, input(m, label), field_schemas: schemas()) == {:ok, v["base"]}

      p =
        S.policy(
          key_resolver: fn _ ->
            {:ok, %{algorithm: v["algorithm"], key: public(v["algorithm"])}}
          end,
          field_schemas: schemas()
        )

      assert {:ok, %{signature: %{crypto: :valid}}} = RequestSeal.verify(m, p, label: label)
    end
  end

  test "independent implementation vectors without identity coverage reject" do
    for i <- [0, 2] do
      v = Enum.at(@implementation, i)

      m =
        build(v["target_url"], [
          ["Signature-Input", v["signature_input"]],
          ["Signature", v["signature"]]
        ])

      assert_error(
        WebBotAuth.verify(
          m,
          policy(
            unresolved:
              {:held_keys,
               fn _ ->
                 {:ok,
                  %{
                    algorithm: if(i == 0, do: "rsa-pss-sha512", else: "ed25519"),
                    key: public(if(i == 0, do: "rsa-pss-sha512", else: "ed25519"))
                  }}
               end}
          )
        ),
        :lifetime_exceeded,
        :freshness
      )

      m = S.add(m, "Signature-Agent", v["label"] <> "=\"https://signature-agent.test\"")
      assert_error(WebBotAuth.verify(m, policy()), :missing_required_component, :policy)
    end
  end

  test "legacy string fields and mismatched member labels reject" do
    for v <- Enum.filter(@published, &(&1["section"] in ["E.1.2", "E.2.2"])) do
      assert_error(
        WebBotAuth.verify(published(v), policy()),
        :invalid_signature_agent,
        :fields,
        :legacy_string
      )
    end

    m = request("directory")

    assert_error(
      WebBotAuth.verify(
        S.rewrite(m, fn n, b ->
          if n == "signature-agent", do: String.replace(b, "agent=", "other="), else: b
        end),
        policy()
      ),
      :agent_unresolved,
      :key,
      :missing_member
    )

    assert_error(
      WebBotAuth.verify(S.add(m, "Signature-Agent", "agent=\"https://other.example\""), policy()),
      :invalid_signature_agent,
      :fields,
      :duplicate_member
    )

    for field <- [
          "broken",
          "agent=?1",
          "agent=\"http://signature-agent.test\"",
          "agent=\"https://signature-agent.test\";type=\"directory\""
        ] do
      assert {:error, %{reason: :invalid_signature_agent, retryable: false}} =
               WebBotAuth.verify(agent_field(m, field), policy())
    end

    assert_error(
      WebBotAuth.verify(agent_field(m, "agent=\"https://signature-agent.test/path\""), policy()),
      :agent_unresolved,
      :key,
      :not_an_origin
    )

    assert_error(
      WebBotAuth.verify(
        agent_field(m, "agent=\"https://signature-agent.test\";type=unknown"),
        policy()
      ),
      :agent_unresolved,
      :key,
      :unsupported_type
    )
  end

  test "required parameters targets coverage and bounded lifetimes reject" do
    m = request("directory")

    for {parameter, reason, layer} <- [
          {"created", :missing_created, :freshness},
          {"expires", :missing_expires, :freshness},
          {"keyid", :invalid_keyid, :policy},
          {"tag", :no_web_bot_auth_signature, :fields}
        ] do
      altered =
        S.rewrite(m, fn n, b ->
          if n == "signature-input",
            do: Regex.replace(Regex.compile!(";#{parameter}=(?:\"[^\"]*\"|[0-9]+)"), b, ""),
            else: b
        end)

      assert_error(WebBotAuth.verify(altered, policy()), reason, layer)
    end

    assert_error(
      WebBotAuth.verify(
        change_input(m, &String.replace(&1, "\"@authority\"", "\"@path\"")),
        policy()
      ),
      :missing_required_component,
      :policy
    )

    assert_error(
      WebBotAuth.verify(
        change_input(m, &String.replace(&1, ~s( "signature-agent";key="agent"), "")),
        policy()
      ),
      :missing_required_component,
      :policy
    )

    assert_error(
      WebBotAuth.verify(
        change_input(m, &Regex.replace(~r/keyid="[^"]+"/, &1, "keyid=\"untrusted-id\"")),
        policy()
      ),
      :invalid_keyid,
      :policy
    )

    long =
      change_input(m, &String.replace(&1, "expires=1735693200", "expires=1735776001"))
      |> resign("agent")

    assert_error(WebBotAuth.verify(long, policy()), :lifetime_exceeded, :freshness)
    assert_error(WebBotAuth.verify(m, policy(test_keys: :reject)), :test_key_rejected, :policy)

    assert_error(
      WebBotAuth.verify(m, policy(agents: fn _ -> :error end)),
      :agent_unresolved,
      :key,
      :untrusted_agent
    )

    assert_error(
      WebBotAuth.verify(
        m,
        policy(agents: fn a -> {:ok, snapshot(%{a | location: "https://other.example"})} end)
      ),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    assert_error(
      WebBotAuth.verify(m, policy(agents: fn a -> {:ok, %{snapshot(a) | keys: %{}}} end)),
      :agent_unresolved,
      :key,
      :unknown_key
    )

    assert_error(
      WebBotAuth.verify(
        m,
        policy(
          agents: fn _ ->
            Process.sleep(100)
            :error
          end
        ),
        timeout: 1
      ),
      :agent_unresolved,
      :key,
      :timeout
    )

    assert_error(WebBotAuth.verify(m, policy(), timeout: 0), :invalid_options, :input)

    assert_error(
      WebBotAuth.verify(m, %{policy() | max_lifetime: 604_801}),
      :invalid_policy,
      :input
    )
  end

  test "directory tags are ignored explicitly and nested coverage cannot pool omissions" do
    relabeled =
      S.rewrite(request("directory"), fn _, bytes ->
        bytes
        |> String.replace("agent=", "other=")
        |> String.replace(~s(key="agent"), ~s(key="other"))
      end)

    assert_error(WebBotAuth.verify(relabeled, policy()), :invalid_signature, :crypto)

    m = request("directory")

    unrelated =
      change_input(m, &String.replace(&1, "web-bot-auth", "http-message-signatures-directory"))

    assert_error(WebBotAuth.verify(unrelated, policy()), :no_web_bot_auth_signature, :fields)

    assert_error(
      WebBotAuth.verify(unrelated, policy(untagged: :reject)),
      :unexpected_signature,
      :policy
    )

    assert_error(
      WebBotAuth.verify(request("nested-incomplete"), policy()),
      :nested_coverage_incomplete,
      :policy
    )

    assert_error(
      WebBotAuth.verify(
        agent_field(m, "agent=\"https://browser.example\";type=directory"),
        policy(
          agents: fn _ ->
            {:ok, snapshot(%{type: :directory, location: "https://signature-agent.test"})}
          end
        )
      ),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    assert_error(
      WebBotAuth.verify(
        agent_field(m, "agent=\"https://browser.example\";type=directory"),
        policy(agents: fn a -> {:ok, %{snapshot(a) | keys: %{}}} end)
      ),
      :agent_unresolved,
      :key,
      :unknown_key
    )
  end

  test "held keys are explicit and never attribute an unresolved URL" do
    m = request("held-key")
    assert_error(WebBotAuth.verify(m, policy()), :agent_unresolved, :key, :missing_member)

    resolver = fn %{label: "agent", keyid: kid, tag: "web-bot-auth"} ->
      assert kid == thumbprint("ed25519")
      {:ok, %{algorithm: "ed25519", key: public("ed25519")}}
    end

    assert {:ok, result} = WebBotAuth.verify(m, policy(unresolved: {:held_keys, resolver}))

    assert result.signatures["agent"].principal == %{
             kind: :key,
             thumbprint: thumbprint("ed25519")
           }

    assert {:ok, result} =
             WebBotAuth.verify(
               request("directory"),
               policy(agents: fn _ -> :error end, unresolved: {:held_keys, resolver})
             )

    assert result.signatures["agent"].principal.kind == :key
  end

  test "directory-assigned IDs cannot misattribute the signing key" do
    wire_id = thumbprint("ed25519")
    actual_id = thumbprint("rsa-pss-sha512")
    refute wire_id == actual_id

    m =
      request("rsa")
      |> agent_field(~s(agent="https://signature-agent.test/keys";type=jwks_uri))
      |> change_input(&String.replace(&1, actual_id, wire_id))
      |> resign("agent", "rsa-pss-sha512")

    set = snapshot(%{type: :jwks_uri, location: "https://signature-agent.test/keys"})
    entry = %{set.keys[actual_id] | key_id: wire_id}
    {:ok, source} = Source.new(Map.from_struct(%{set.source | key_id: :directory}))
    set = %{set | source: source, keys: %{wire_id => entry}}
    assert {:ok, %{key: key}} = KeySet.lookup_at(set, wire_id, ["rsa-pss-sha512"], @now)
    assert PublicKey.thumbprint(key) == {:ok, actual_id}

    assert {:ok, %{signature: %{crypto: :valid}}} =
             RequestSeal.verify(
               m,
               S.policy(
                 key_resolver: fn %{keyid: ^wire_id} ->
                   {:ok, %{algorithm: "rsa-pss-sha512", key: key}}
                 end,
                 field_schemas: schemas()
               ),
               label: "agent"
             )

    owner = self()

    p =
      policy(
        agents: fn a ->
          assert a.type == :jwks_uri
          assert a.location == source.location
          {:ok, set}
        end,
        unresolved:
          {:held_keys,
           fn _ ->
             send(owner, :held_invoked)
             {:ok, %{algorithm: "rsa-pss-sha512", key: public("rsa-pss-sha512")}}
           end}
      )

    assert_error(WebBotAuth.verify(m, p), :agent_unresolved, :key, :source_mismatch)
    refute_received :held_invoked

    # A non-test key's thumbprint cannot disguise a published test signing key.
    {bytes, _private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, alias_key} = PublicKey.import({:ed25519, bytes}, :raw)
    {:ok, alias_id} = PublicKey.thumbprint(alias_key)

    altered =
      change_input(m, &String.replace(&1, wire_id, alias_id)) |> resign("agent", "rsa-pss-sha512")

    aliases = fn a ->
      set = snapshot(a)
      entry = %{set.keys[actual_id] | key_id: alias_id}
      {:ok, %{set | source: %{set.source | key_id: :directory}, keys: %{alias_id => entry}}}
    end

    assert_error(
      WebBotAuth.verify(altered, policy(agents: aliases, test_keys: :reject)),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    revoked = fn a ->
      {:ok, set} = aliases.(a)
      {:ok, %{set | source: %{set.source | revoked: [actual_id]}}}
    end

    assert_error(
      WebBotAuth.verify(altered, policy(agents: revoked)),
      :agent_unresolved,
      :key,
      :unknown_key
    )
  end

  test "directory agents reject directory-assigned IDs before verification" do
    m = request("rsa")
    actual_id = thumbprint("rsa-pss-sha512")
    set = snapshot(%{type: :directory, location: "https://signature-agent.test"})
    entry = %{set.keys[actual_id] | key_id: actual_id}
    set = %{set | keys: %{actual_id => entry}}

    assert {:ok, %{signatures: %{"agent" => %{signature: %{crypto: :valid}}}}} =
             WebBotAuth.verify(m, policy(agents: fn _ -> {:ok, set} end))

    set = %{set | source: %{set.source | key_id: :directory}}
    assert {:error, %{reason: :invalid_source}} = Source.new(Map.from_struct(set.source))
    assert :error = KeySet.lookup_at(set, actual_id, ["rsa-pss-sha512"], @now)
    owner = self()

    p =
      policy(
        agents: fn a ->
          send(owner, {:directory_agent, a.type})
          {:ok, set}
        end,
        unresolved:
          {:held_keys,
           fn _ ->
             send(owner, :held_invoked)
             {:ok, %{algorithm: "rsa-pss-sha512", key: entry.key}}
           end}
      )

    assert_error(WebBotAuth.verify(m, p), :agent_unresolved, :key, :source_mismatch)
    assert_received {:directory_agent, :directory}
    refute_received :held_invoked
  end

  test "held-key resolution enforces the actual signing key thumbprint" do
    p =
      policy(
        unresolved:
          {:held_keys,
           fn _ ->
             {:ok, %{algorithm: "rsa-pss-sha512", key: public("rsa-pss-sha512")}}
           end}
      )

    m =
      request("held-key")
      |> change_input(&String.replace(&1, ~s(alg="ed25519"), ~s(alg="rsa-pss-sha512")))
      |> resign("agent", "rsa-pss-sha512")

    assert_error(WebBotAuth.verify(m, p), :agent_unresolved, :key, :unknown_key)
  end

  test "held keys waive only an absent Signature-Agent field" do
    m = request("held-key")
    owner = self()

    resolver = fn _ ->
      send(owner, :held_invoked)
      {:ok, %{algorithm: "ed25519", key: public("ed25519")}}
    end

    p = policy(unresolved: {:held_keys, resolver})

    assert {:ok, %{signatures: %{"agent" => %{principal: %{kind: :key}}}}} =
             WebBotAuth.verify(m, p)

    assert_received :held_invoked

    for value <- ["", "other=\"https://signature-agent.test\";type=directory"] do
      assert_error(
        WebBotAuth.verify(agent_field(m, value), p),
        :agent_unresolved,
        :key,
        :missing_member
      )

      refute_received :held_invoked
    end
  end

  test "non-directory principals retain distinct exact locations without fragments" do
    locations = [
      "https://signature-agent.test/keys?tenant=a",
      "https://signature-agent.test/keys?tenant=b",
      "https://signature-agent.test./keys",
      "https://signature-agent.test:443/keys"
    ]

    for type <- [:jwks_uri, :cimd] do
      identifiers =
        for location <- locations do
          m =
            request(Atom.to_string(type))
            |> agent_field("agent=\"#{location}#fragment\";type=#{type}")
            |> resign("agent")

          p = policy(agents: fn a -> {:ok, snapshot(%{a | location: location})} end)
          assert {:ok, result} = WebBotAuth.verify(m, p)
          identifier = result.signatures["agent"].principal.identifier
          assert identifier == location
          identifier
        end

      assert length(Enum.uniq(identifiers)) == 4
    end
  end

  test "Web Bot Auth rejects a cryptographically valid synthetic profile signature" do
    original = request("held-key")
    input = input(original, "agent")

    {:ok, wire} =
      RequestSeal.StructuredFields.serialize(
        %RequestSeal.StructuredFields.Value{type: :list, value: [input]},
        SignatureFields.schema(:list)
      )

    synthetic_input = String.replace(wire, ~s(;tag="web-bot-auth"), ~s(;tag="synthetic"))
    refute synthetic_input == wire

    assert {:ok, signed} =
             RequestSeal.sign(
               S.strip(original),
               %{
                 label: "agent",
                 signature_input: synthetic_input,
                 algorithm: "ed25519"
               },
               S.signer("ed25519")
             )

    generic =
      S.policy(key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public("ed25519")}} end)

    assert {:ok, {entries, signatures}} = RequestSeal.Profile.dictionaries(signed, 16)

    assert {:ok, result} =
             RequestSeal.Profile.verify_label(
               signed,
               generic,
               "agent",
               Map.new(entries)["agent"],
               signatures["agent"],
               %{name: {:test_pkg, :synthetic}}
             )

    assert result.profile.name == {:test_pkg, :synthetic}
    assert result.signature.crypto == :valid

    p =
      policy(
        unresolved:
          {:held_keys, fn _ -> {:ok, %{algorithm: "ed25519", key: public("ed25519")}} end}
      )

    assert_error(WebBotAuth.verify(signed, p), :no_web_bot_auth_signature, :fields)
    assert {:ok, _} = WebBotAuth.verify(original, p)
  end

  test "whole envelope replay follows every signature and uses profile facts" do
    pid = start_supervised!({ETS, max_entries: 20})
    owner = self()

    replay = %{
      identifier: :nonce,
      namespace: "webbot",
      timeout: 5000,
      store: ETS.store(pid),
      commitment: fn facts ->
        send(owner, {:facts, facts})
        {:ok, "authenticated-envelope"}
      end
    }

    p = policy(replay: replay)

    broken =
      S.rewrite(request("nested"), fn n, b ->
        if n == "signature", do: String.replace(b, "browser=:", "browser=:AAAA"), else: b
      end)

    assert {:error, _} = WebBotAuth.verify(broken, p)
    refute_received {:facts, _}
    assert {:ok, result} = WebBotAuth.verify(request("nested"), p)
    assert_received {:facts, facts}
    assert facts.profile == %{name: :web_bot_auth, revision: @revision}
    assert Enum.map(facts.signatures, & &1.label) == ["agent", "browser"]
    assert Enum.all?(facts.signatures, &(&1.identifier == input_nonce()))
    assert result.replay.retain_until == @now + 3600
    assert_error(WebBotAuth.verify(request("nested"), p), :replayed, :replay)
    GenServer.stop(pid)
    assert_error(WebBotAuth.verify(request("nested"), p), :store_unavailable, :replay)
  end

  test "signer matches independent bytes and validates its contract" do
    m =
      request("directory")
      |> S.strip()
      |> agent_field("agent=\"https://signature-agent.test\";type=directory")

    spec = %{
      label: "agent",
      agent: %{location: "https://signature-agent.test", type: :directory},
      key: public("ed25519"),
      algorithm: "ed25519",
      created: @now,
      expires: @now + 3600,
      nonce: input_nonce()
    }

    assert {:ok, signed} = WebBotAuth.sign(m, spec, S.signer("ed25519"))
    assert {:ok, _} = WebBotAuth.verify(signed, policy())
    assert List.last(signed.fields).value == List.last(request("directory").fields).value

    for spec <- [
          %{spec | expires: @now},
          %{spec | agent: nil},
          %{spec | algorithm: "hmac-sha256"},
          Map.put(spec, :unknown, true),
          %{spec | agent: %{location: "http://agent.example", type: :directory}}
        ] do
      assert {:error, _} = WebBotAuth.sign(m, spec, S.signer("ed25519"))
    end

    for attrs <- [
          %{algorithms: ["hmac-sha256"]},
          %{max_lifetime: 0},
          %{max_lifetime: 604_801},
          %{agents: nil},
          %{freshness: :not_evaluated},
          %{test_keys: :yes},
          %{untagged: :yes},
          %{unresolved: :yes},
          %{unknown: true}
        ] do
      assert {:error, %{reason: :invalid_policy}} = Policy.new(Map.merge(policy_attrs(), attrs))
    end
  end

  test "published and independently signed directory responses verify base body and key" do
    published = Enum.find(@published, &(&1["section"] == "E.2.3"))
    generated = :json.decode(File.read!(Path.join(@root, "directory.json")))

    for v <- [published, generated] do
      m = directory_response(v)
      label = if v == published, do: "binding", else: "directory"
      assert SignatureBase.build(m, input(m, label)) == {:ok, v["base"]}

      p =
        S.policy(
          components: "(\"@authority\";req \"content-digest\")",
          key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: public("ed25519")}} end,
          freshness: %{clock: fn -> @now end, max_age: nil, skew: 0, require_expires: true},
          content: %{kind: :content, algorithms: ["sha-256"], section: :headers}
        )

      assert {:ok, %{signature: %{crypto: :valid}, content: %{checked: ["sha-256"]}}} =
               RequestSeal.verify(m, p, label: label)
    end
  end

  test "real TLS directory refresh preserves replay commitment facts" do
    Peer.public_jwk()
    fetches = :atomics.new(1, [])
    # The cache checks the directory proof against this clock, so the peer signs
    # with it too; a wall-clock second ticking between capture and fetch would
    # otherwise date the proof in the cache's future.
    time = :atomics.new(1, [])
    :atomics.put(time, 1, System.system_time(:second))

    p =
      Peer.start(fn socket, req ->
        suffix = if :atomics.add_get(fetches, 1, 1) == 1, do: "", else: "\n"
        created = :atomics.get(time, 1)

        Peer.signed(socket, req, Peer.directory() <> suffix, nil,
          created: created,
          expires: created + 60
        )
      end)

    on_exit(fn -> Peer.stop(p) end)
    location = "https://localhost:#{p.port}"

    {:ok, source} =
      Source.new(%{
        type: :directory,
        location: location,
        cacerts: p.cacerts,
        permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
      })

    cache = start_supervised!({Cache, clock: fn -> :atomics.get(time, 1) end})
    store = start_supervised!({ETS, max_entries: 10})
    owner = self()

    replay = %{
      identifier: :nonce,
      namespace: "directory-refresh",
      store: ETS.store(store),
      timeout: 5000,
      commitment: fn facts ->
        send(owner, {:facts, facts})
        {:ok, :crypto.hash(:sha256, :erlang.term_to_binary(facts))}
      end
    }

    {:ok, handle} =
      RequestSeal.Custody.Local.import(
        "ed25519",
        :json.decode(File.read!("test/fixtures/custody/rfc8037.json")),
        :jwk
      )

    {:ok, key} = RequestSeal.Custody.public_key(handle)
    now = System.system_time(:second)
    :atomics.put(time, 1, now)

    spec = %{
      label: "agent",
      agent: %{location: location, type: :directory},
      key: key,
      algorithm: "ed25519",
      created: now,
      expires: now + 60,
      nonce: "real-directory-request"
    }

    {:ok, m} =
      WebBotAuth.sign(build("https://example.com/resource", []), spec, fn _, base ->
        RequestSeal.Custody.sign(handle, base)
      end)

    policy =
      policy(
        cache: cache,
        replay: replay,
        agents: fn a ->
          assert a.identifier == location <> "/.well-known/http-message-signatures-directory"
          {:ok, source}
        end,
        freshness: %{clock: fn -> now end, skew: 0, max_age: nil}
      )

    assert {:ok, result} = WebBotAuth.verify(m, policy)
    principal = result.signatures["agent"].principal
    assert principal.provenance.proof == :signed
    assert is_binary(principal.provenance.revision)
    assert principal.identifier == location <> "/.well-known/http-message-signatures-directory"
    assert_received {:facts, first}
    [facts] = first.signatures
    assert facts.identifier == spec.nonce
    assert facts.keyid == principal.thumbprint

    :atomics.add(time, 1, 1)
    assert {:ok, refreshed} = Cache.refresh(cache, source)
    assert refreshed.fetched_at != principal.provenance.fetched_at
    assert refreshed.revision != principal.provenance.revision
    assert :atomics.get(fetches, 1) == 2
    assert_error(WebBotAuth.verify(m, policy), :replayed, :replay)
    assert_received {:facts, second}
    assert second == first
    assert facts.agent == Map.take(principal, [:kind, :identifier, :type, :origin, :thumbprint])

    assert :ok = Cache.remove(cache, source, principal.thumbprint)
    assert_error(WebBotAuth.verify(m, policy), :agent_unresolved, :key, :revoked_key)
  end

  test "cache key from one directory cannot authenticate another directory" do
    draft_jwk =
      :json.decode(File.read!(Path.join(@root, "directory.json")))["body"]
      |> :json.decode()
      |> Map.fetch!("keys")
      |> hd()

    a =
      Peer.start(fn socket, _ ->
        Peer.reply(socket, Peer.directory([draft_jwk]), [
          {"Content-Type", "application/http-message-signatures-directory+json"},
          {"Cache-Control", "max-age=60"}
        ])
      end)

    b =
      Peer.start(fn socket, req ->
        Peer.signed(socket, req, Peer.directory(), nil, created: @now, expires: @now + 3600)
      end)

    on_exit(fn ->
      Peer.stop(a)
      Peer.stop(b)
    end)

    # Explicit self-resolved unsigned discovery supplies A's association.
    source = fn p ->
      {:ok, s} =
        Source.new(%{
          type: :directory,
          location: "https://localhost:#{p.port}",
          cacerts: p.cacerts,
          permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}],
          require_signed_directory: false
        })

      s
    end

    sa = source.(a)
    sb = source.(b)
    cache = start_supervised!({Cache, []})
    pa = policy(cache: cache, agents: fn _ -> {:ok, sa} end)

    ma =
      request("directory")
      |> agent_field("agent=\"https://localhost:#{a.port}\";type=directory")
      |> resign("agent")

    assert {:ok, _} = WebBotAuth.verify(ma, pa)

    mb =
      ma |> agent_field("agent=\"https://localhost:#{b.port}\";type=directory") |> resign("agent")

    pb = policy(cache: cache, agents: fn _ -> {:ok, sb} end)
    assert_error(WebBotAuth.verify(mb, pb), :agent_unresolved, :key, :unknown_key)
  end

  test "unknown members are ignored while selected type URL and query remain bound" do
    m = request("jwks_uri")

    value =
      "agent=\"HTTPS://SIGNATURE-AGENT.TEST.:443/%6beys?selector=1#fragment\";type=jwks_uri, unused=\"https://other.example\";type=unknown"

    m = agent_field(m, value) |> resign("agent")
    owner = self()

    p =
      policy(
        agents: fn a ->
          send(owner, {:agent, a})
          {:ok, snapshot(%{a | location: String.replace(a.location, "#fragment", "")})}
        end
      )

    assert {:ok, result} = WebBotAuth.verify(m, p)

    assert_received {:agent,
                     %{
                       identifier: "https://signature-agent.test/keys",
                       location: "HTTPS://SIGNATURE-AGENT.TEST.:443/%6beys?selector=1#fragment"
                     }}

    assert result.signatures["agent"].principal.identifier ==
             "HTTPS://SIGNATURE-AGENT.TEST.:443/%6beys?selector=1"

    mismatched =
      policy(
        agents: fn a ->
          {:ok, snapshot(%{a | location: "HTTPS://SIGNATURE-AGENT.TEST.:443/%6beys?selector=2"})}
        end
      )

    assert_error(WebBotAuth.verify(m, mismatched), :agent_unresolved, :key, :source_mismatch)

    assert {:ok, _} =
             WebBotAuth.verify(
               request("directory"),
               policy(field_schemas: %{"signature-agent" => SignatureFields.schema(:item)})
             )
  end

  test "field pairing duplicate parameters and invalid signatures fail closed" do
    m = request("directory")

    for name <- ~w(signature signature-input) do
      duplicate = Enum.find(m.fields, &(String.downcase(&1.name) == name))

      assert_error(
        WebBotAuth.verify(%{m | fields: m.fields ++ [duplicate]}, policy()),
        :duplicate_label,
        :fields
      )
    end

    altered =
      change_input(
        m,
        &String.replace(&1, "created=1735689600", "created=1735689600;created=1735689600")
      )

    assert_error(WebBotAuth.verify(altered, policy()), :duplicate_parameter, :fields)

    altered =
      S.rewrite(m, fn name, bytes ->
        if name == "signature", do: String.replace(bytes, "agent=:", "agent=:AAAA"), else: bytes
      end)

    assert_error(WebBotAuth.verify(altered, policy()), :invalid_signature, :crypto)

    assert_error(
      WebBotAuth.verify(m, policy(agents: fn a -> {:ok, %{snapshot(a) | expires_at: @now}} end)),
      :agent_unresolved,
      :key,
      :unknown_key
    )

    assert_error(
      WebBotAuth.verify(
        m,
        policy(
          agents: fn a ->
            set = snapshot(a)
            {:ok, %{set | source: %{set.source | revoked: [thumbprint("ed25519")]}}}
          end
        )
      ),
      :agent_unresolved,
      :key,
      :revoked_key
    )
  end

  test "mandatory metadata and coverage reject before trust is invoked" do
    owner = self()

    p =
      policy(
        agents: fn a ->
          send(owner, :trust_invoked)
          {:ok, snapshot(a)}
        end
      )

    m = request("directory")

    for altered <- [
          change_input(m, &Regex.replace(~r/;expires=[0-9]+/, &1, "")),
          change_input(m, &Regex.replace(~r/;created=[0-9]+/, &1, "")),
          change_input(m, &String.replace(&1, ~s( "signature-agent";key="agent"), ""))
        ] do
      assert {:error, _} = WebBotAuth.verify(altered, p)
      refute_received :trust_invoked
    end

    for {changes, reason} <- [
          {[freshness: %{clock: fn -> @now + 3600 end, skew: 0, max_age: nil}], :expired},
          {[freshness: %{clock: fn -> @now - 1 end, skew: 0, max_age: nil}], :created_in_future},
          {[freshness: %{clock: fn -> @now + 121 end, skew: 0, max_age: 120}], :too_old},
          {[freshness: %{clock: fn -> @now + 131 end, skew: 10, max_age: 120}], :too_old},
          {[max_lifetime: 3599], :lifetime_exceeded}
        ] do
      p = policy(Keyword.merge([agents: p.agents], changes))
      assert_error(WebBotAuth.verify(m, p), reason, :freshness)
      refute_received :trust_invoked
    end

    for expires <- [@now, @now - 1] do
      altered = change_input(m, &String.replace(&1, "expires=1735693200", "expires=#{expires}"))
      assert_error(WebBotAuth.verify(altered, p), :lifetime_exceeded, :freshness)
      refute_received :trust_invoked
    end

    # The recording callback must observe an accepted request too.
    assert {:ok, _} = WebBotAuth.verify(m, p)
    assert_received :trust_invoked
  end

  test "freshness accepts inclusive creation and exclusive expiration with skew" do
    m = request("directory")

    for {now, skew, reason} <- [
          {@now - 10, 10, :ok},
          {@now - 11, 10, :created_in_future},
          {@now + 3609, 10, :ok},
          {@now + 3610, 10, :expired}
        ] do
      owner = self()

      p =
        policy(
          freshness: %{clock: fn -> now end, skew: skew, max_age: nil},
          agents: fn a ->
            send(owner, :trust_invoked)
            {:ok, snapshot(a)}
          end
        )

      if reason == :ok do
        assert {:ok, _} = WebBotAuth.verify(m, p)
        assert_received :trust_invoked
      else
        assert_error(WebBotAuth.verify(m, p), reason, :freshness)
        refute_received :trust_invoked
      end
    end
  end

  test "maximum age is inclusive with skew before trust" do
    m = request("directory")
    owner = self()

    for {now, skew, max_age, reason} <- [
          {@now + 1, 0, 1, :ok},
          {@now + 2, 0, 1, :too_old},
          {@now + 120, 0, 120, :ok},
          {@now + 121, 0, 120, :too_old},
          {@now + 130, 10, 120, :ok},
          {@now + 131, 10, 120, :too_old}
        ] do
      p =
        policy(
          freshness: %{clock: fn -> now end, skew: skew, max_age: max_age},
          agents: fn a ->
            send(owner, :trust_invoked)
            {:ok, snapshot(a)}
          end
        )

      if reason == :ok do
        assert {:ok, _} = WebBotAuth.verify(m, p)
        assert_received :trust_invoked
      else
        assert_error(WebBotAuth.verify(m, p), reason, :freshness)
        refute_received :trust_invoked
      end
    end
  end

  test "origin serialization and path normalization retain valid root semantics" do
    dotted =
      request("directory")
      |> agent_field("agent=\"https://signature-agent.test.\";type=directory")
      |> resign("agent")

    assert {:ok, result} = WebBotAuth.verify(dotted, policy())

    assert result.signatures["agent"].principal.identifier ==
             "https://signature-agent.test/.well-known/http-message-signatures-directory"

    owner = self()

    m =
      request("jwks_uri")
      |> agent_field("agent=\"https://signature-agent.test/../%6beys\";type=jwks_uri")
      |> resign("agent")

    assert_error(
      WebBotAuth.verify(
        m,
        policy(
          agents: fn a ->
            send(owner, {:identifier, a.identifier})
            :error
          end
        )
      ),
      :agent_unresolved,
      :key,
      :untrusted_agent
    )

    assert_received {:identifier, "https://signature-agent.test/keys"}
  end

  test "snapshot proof obeys caller signed-directory requirements" do
    p =
      policy(
        agents: fn a ->
          set = snapshot(a)
          {:ok, %{set | source: %{set.source | require_signed_directory: true}}}
        end
      )

    assert_error(
      WebBotAuth.verify(request("directory"), p),
      :agent_unresolved,
      :key,
      :source_unavailable
    )
  end

  test "lifetime policy permits its bounds and ignored labels remain explicit" do
    m = request("directory")

    short =
      change_input(m, &String.replace(&1, "expires=1735693200", "expires=1735689601"))
      |> resign("agent")

    assert {:ok, _} = WebBotAuth.verify(short, policy(max_lifetime: 1))

    long =
      change_input(m, &String.replace(&1, "expires=1735693200", "expires=1735776001"))
      |> resign("agent")

    assert {:ok, _} = WebBotAuth.verify(long, policy(max_lifetime: 604_800))
    assert_error(WebBotAuth.verify(m, policy(max_lifetime: 1)), :lifetime_exceeded, :freshness)

    extra = %{
      label: "extra",
      signature_input: "(\"@authority\");keyid=\"test-key-ed25519\";tag=\"other\"",
      algorithm: "ed25519"
    }

    {:ok, m} = RequestSeal.sign(m, extra, S.signer("ed25519"))
    assert {:ok, %{ignored: ["extra"], signatures: signatures}} = WebBotAuth.verify(m, policy())
    assert Map.keys(signatures) == ["agent"]
    assert_error(WebBotAuth.verify(m, policy(untagged: :reject)), :unexpected_signature, :policy)
  end

  test "construction and source bounds remain explicit at verification" do
    m = request("directory")

    assert_error(
      WebBotAuth.verify(
        m,
        policy(
          agents: fn a ->
            set = snapshot(a)
            {:ok, %{set | source: %{set.source | max_redirects: 1}}}
          end
        )
      ),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    assert_error(
      WebBotAuth.verify(
        m,
        policy(
          agents: fn a ->
            set = snapshot(a)
            {:ok, %{set | source: %{set.source | max_keys: 257}}}
          end
        )
      ),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    assert_error(
      WebBotAuth.verify(
        m,
        policy(
          agents: fn a ->
            set = snapshot(a)
            kid = thumbprint("ed25519")

            {:ok,
             %{set | keys: Map.update!(set.keys, kid, &%{&1 | origin: "https://other.example"})}}
          end
        )
      ),
      :agent_unresolved,
      :key,
      :source_mismatch
    )

    assert_error(
      WebBotAuth.verify(
        m,
        policy(
          agents: fn a -> {:ok, elem(Source.new(%{type: a.type, location: a.location}), 1)} end
        )
      ),
      :agent_unresolved,
      :key,
      :source_unavailable
    )

    assert_error(
      WebBotAuth.verify(m, policy(freshness: %{clock: fn -> -1 end, skew: 0, max_age: nil})),
      :invalid_clock,
      :freshness
    )

    assert_error(
      WebBotAuth.verify(m, policy(), timeout: 5000, timeout: 5000),
      :invalid_options,
      :input
    )

    assert_error(WebBotAuth.verify(m, policy(), unexpected: true), :invalid_options, :input)

    for p <- [
          %{policy() | algorithms: ["hmac-sha256"]},
          %{policy() | unresolved: :allow},
          %{policy() | test_keys: :unknown}
        ] do
      assert_error(WebBotAuth.verify(m, p), :invalid_policy, :input)
    end
  end

  test "fixture manifest pins independent bytes" do
    for line <- File.read!(Path.join(@root, "SHA256SUMS")) |> String.split("\n", trim: true) do
      [hash, name] = String.split(line, "  ", parts: 2)

      assert Base.encode16(:crypto.hash(:sha256, File.read!(Path.join(@root, name))),
               case: :lower
             ) == hash
    end
  end

  test "signer rejects incomplete nested coverage before invoking custody" do
    owner = self()
    m = request("inner")

    spec = %{
      label: "browser",
      agent: %{location: "https://browser.example", type: :directory},
      key: public("ed25519"),
      algorithm: "ed25519",
      created: @now,
      expires: @now + 3600,
      nonce: input_nonce(),
      components: "(\"signature-input\";key=\"agent\" \"signature\";key=\"agent\")"
    }

    signer = fn algorithm, base ->
      send(owner, :signed)
      S.signer("ed25519").(algorithm, base)
    end

    assert_error(WebBotAuth.sign(m, spec, signer), :nested_coverage_incomplete, :policy)
    refute_received :signed

    complete = %{
      spec
      | components:
          "(\"@method\" \"@path\" \"signature-agent\";key=\"agent\" \"signature-input\";key=\"agent\" \"signature\";key=\"agent\")"
    }

    missing_input = %{
      complete
      | components: String.replace(complete.components, ~s( "signature-input";key="agent"), "")
    }

    assert_error(WebBotAuth.sign(m, missing_input, signer), :nested_coverage_incomplete, :policy)
    refute_received :signed
    assert {:ok, signed} = WebBotAuth.sign(m, complete, signer)
    assert {:ok, %{evidence: %{"browser" => ["agent"]}}} = WebBotAuth.verify(signed, policy())
  end

  test "replay requires authenticated nonces and uses the earliest acceptance end" do
    pid = start_supervised!({ETS, max_entries: 10})
    owner = self()

    replay = %{
      identifier: :nonce,
      namespace: "earliest",
      store: ETS.store(pid),
      timeout: 5000,
      commitment: fn facts ->
        send(owner, {:commitment, facts})
        {:ok, "earliest-envelope"}
      end
    }

    absent =
      request("directory")
      |> change_input(&Regex.replace(~r/;nonce="[^"]*"/, &1, ""))
      |> resign("agent")

    assert_error(
      WebBotAuth.verify(absent, policy(replay: replay)),
      :missing_replay_identifier,
      :replay
    )

    refute_received {:commitment, _}

    assert_error(
      WebBotAuth.verify(request("nested-incomplete"), policy(replay: replay)),
      :nested_coverage_incomplete,
      :policy
    )

    refute_received {:commitment, _}

    assert {:ok, result} =
             WebBotAuth.verify(
               request("nested"),
               policy(replay: replay, freshness: %{clock: fn -> @now end, skew: 10, max_age: 120})
             )

    assert result.replay.retain_until == @now + 131
    assert_received {:commitment, facts}
    assert length(facts.signatures) == 2
    refute_received {:commitment, _}

    assert_error(
      WebBotAuth.verify(
        request("directory"),
        policy(replay: %{replay | commitment: fn _ -> :error end})
      ),
      :commitment_failed,
      :replay
    )
  end

  @tag :live_source
  test "deployed directory snapshot remains source-bound input" do
    Mix.ensure_application!(:ssl)
    {:ok, _} = Application.ensure_all_started(:ssl)

    roots =
      case System.get_env("REQUESTSEAL_DISCOVERY_CACERTS") do
        nil ->
          :os

        file ->
          :public_key.pem_decode(File.read!(file))
          |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)
      end

    {:ok, source} =
      Source.new(%{
        type: :directory,
        location: "https://chatgpt.com",
        cacerts: roots,
        require_signed_directory: false
      })

    assert {:ok, set} = RequestSeal.Discovery.fetch(source, timeout: 5000)
    assert map_size(set.keys) > 0

    # A max-age=0 response is a real fetch, not a reusable fresh snapshot.
    now = System.system_time(:second)

    for {kid, resolution} <- set.keys do
      assert PublicKey.thumbprint(resolution.key) == {:ok, kid}

      if set.expires_at <= now do
        assert :error = KeySet.lookup_at(set, kid, RequestSeal.Crypto.algorithms(), now)
      else
        assert {:ok, _} = KeySet.lookup_at(set, kid, RequestSeal.Crypto.algorithms(), now)
      end
    end

    IO.puts(
      "Deployed directory: keys=#{map_size(set.keys)}; proof=#{set.proof}; freshness_seconds=#{set.expires_at - set.fetched_at}; decoded_sha256=#{set.revision}"
    )

    m =
      request("directory")
      |> agent_field("agent=\"https://chatgpt.com\";type=directory")
      |> resign("agent")

    assert_error(
      WebBotAuth.verify(m, policy(agents: fn _ -> {:ok, set} end)),
      :agent_unresolved,
      :key,
      :unknown_key
    )
  end

  defp directory_response(v) do
    {:ok, body} = Body.new(%{state: :retained, bytes: v["body"]})

    {:ok, m} =
      Message.new(%{
        kind: :response,
        status: 200,
        fields: Enum.map(v["fields"], fn [n, b] -> S.field(n, b) end),
        body: body,
        trailers: [],
        transport: elem(RequestSeal.TransportFacts.new(%{}), 1),
        related_request:
          build("https://signature-agent.test/.well-known/http-message-signatures-directory", [])
      })

    m
  end

  defp policy_attrs,
    do: %{
      algorithms: ["ed25519", "rsa-pss-sha512"],
      agents: fn a -> {:ok, snapshot(a)} end,
      cache: nil,
      freshness: %{clock: fn -> @now end, skew: 0, max_age: nil},
      content: :not_required,
      replay: :not_required,
      test_keys: :allow
    }

  defp policy(opts \\ []) do
    {:ok, p} = Policy.new(Map.merge(policy_attrs(), Map.new(opts)))
    p
  end

  defp snapshot(a) do
    {:ok, source} =
      Source.new(%{type: a.type, location: a.location, require_signed_directory: false})

    keys =
      Map.new(["ed25519", "rsa-pss-sha512"], fn alg ->
        kid = thumbprint(alg)

        {kid,
         %Resolution{
           key: public(alg),
           thumbprint: kid,
           algorithm: alg,
           asserted_algorithm: alg,
           origin: Source.origin(URI.parse(a.location)),
           source_type: a.type,
           location: source.location,
           fetched_at: @now,
           expires_at: @now + 7200,
           proof: :unsigned
         }}
      end)

    %KeySet{
      source: source,
      origin: Source.origin(URI.parse(a.location)),
      keys: keys,
      fetched_at: @now,
      expires_at: @now + 7200,
      revision: "independent-key-set",
      proof: :unsigned
    }
  end

  defp public("ed25519"), do: S.public("ed25519")
  defp public("rsa-pss-sha512"), do: S.public("rsa_pss")

  defp thumbprint(algorithm) do
    {:ok, kid} = PublicKey.thumbprint(public(algorithm))
    kid
  end

  defp request(name) do
    v = Enum.find(@requests, &(&1["name"] == name))
    build(v["target"], v["fields"])
  end

  defp published(v), do: build("https://example.com/resource", v["fields"])

  defp build(target, fields) do
    uri = URI.parse(target)
    {:ok, body} = Body.new(%{state: :retained, bytes: ""})

    {:ok, m} =
      Message.new(%{
        kind: :request,
        method: "GET",
        raw_target: (uri.path || "/") <> if(uri.query, do: "?" <> uri.query, else: ""),
        target_form: :origin,
        scheme: uri.scheme,
        authority: uri.authority,
        transport: elem(RequestSeal.TransportFacts.new(%{}), 1),
        trailers: [],
        fields: Enum.map(fields, fn [n, v] -> S.field(n, v) end),
        body: body
      })

    m
  end

  defp schemas,
    do:
      Map.put(
        S.schemas(),
        "signature-agent",
        SignatureFields.schema(:dictionary, [:string], false)
      )

  defp input(m, label) do
    {:ok, {entries, _}} = RequestSeal.Authentication.dictionaries(m, 16)
    Map.new(entries)[label]
  end

  defp change_input(m, fun),
    do: S.rewrite(m, fn n, b -> if n == "signature-input", do: fun.(b), else: b end)

  defp agent_field(m, value),
    do: %{
      m
      | fields:
          Enum.reject(m.fields, &(String.downcase(&1.name) == "signature-agent")) ++
            [S.field("Signature-Agent", value)]
    }

  defp resign(m, label, algorithm \\ "ed25519") do
    {:ok, signed} =
      RequestSeal.sign(
        S.strip(m),
        %{label: label, signature_input: input(m, label), algorithm: algorithm},
        S.signer(if algorithm == "ed25519", do: "ed25519", else: "rsa_pss"),
        field_schemas: schemas()
      )

    signed
  end

  defp input_nonce, do: Base.encode64(:binary.copy(<<42>>, 64))

  defp assert_error(result, reason, layer, detail \\ nil) do
    assert {:error, %{reason: ^reason, layer: ^layer, detail: ^detail, retryable: false} = error} =
             result

    refute inspect(error) =~ "https://"
    refute inspect(error) =~ "poqkLG"
    error
  end
end
