defmodule RequestSeal.ProfileTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Error, Profile}
  alias RequestSeal.MultiSignatureSupport, as: S
  @profile %{name: {:test_pkg, :synthetic}}

  setup do
    message = S.signed(["sig-b26"])
    {:ok, {entries, signatures}} = RequestSeal.Authentication.dictionaries(message, 16)
    {_, input} = hd(entries)
    %{message: message, input: input, signature: signatures["sig-b26"], policy: S.policy()}
  end

  test "core-owned names, bare atoms and malformed profile maps are refused", c do
    for profile <- [
          %{name: :web_bot_auth, revision: "draft-ietf-webbotauth-httpsig-protocol-00"},
          %{name: :rfc9421},
          %{name: :synthetic},
          %{name: {:request_seal, :x}},
          Map.merge(@profile, Map.new(~w(a b c d e f g h)a, &{&1, true})),
          Map.put(@profile, "revision", "1"),
          %{name: {"test_pkg", :synthetic}},
          %{name: {:test_pkg, "synthetic"}},
          %{},
          nil
        ] do
      assert {:error, %Error{reason: :invalid_profile, layer: :input}} = verify(c, profile)
    end
  end

  test "selected verification enforces the policy signature limit", c do
    message = S.signed()
    policy = S.policy(max_signatures: 1)
    assert {:ok, {entries, signatures}} = Profile.dictionaries(message, 64)
    input = Map.new(entries)["sig-b26"]

    assert {:error, %Error{reason: :limit, layer: :input}} =
             RequestSeal.verify(message, policy, label: "sig-b26")

    assert {:error, %Error{reason: :limit, layer: :input}} =
             verify(
               %{
                 c
                 | message: message,
                   policy: policy,
                   input: input,
                   signature: signatures["sig-b26"]
               },
               @profile
             )
  end

  test "selected verification rejects a label absent from the message", c do
    assert {:error, %Error{reason: :unknown_label, layer: :fields}} =
             verify(c, @profile, "not-in-message")
  end

  test "selected input must equal the message entry before key resolution", c do
    owner = self()

    policy =
      S.policy(
        key_resolver: fn facts ->
          send(owner, :resolved)
          S.resolver(facts)
        end
      )

    input = %{c.input | parameters: c.input.parameters ++ [{"tag", {:string, "different"}}]}

    assert {:error, %Error{reason: :invalid_signature_input, layer: :fields}} =
             verify(%{c | policy: policy, input: input}, @profile)

    refute_received :resolved
  end

  test "selected signature must equal the message entry", c do
    signature = %{c.signature | parameters: [{"extra", {:boolean, true}}]}

    assert {:error, %Error{reason: :invalid_signature_field, layer: :fields}} =
             verify(%{c | signature: signature}, @profile)
  end

  test "core profile atoms are reserved as extension package names", c do
    for package <- [:rfc9421, :web_bot_auth] do
      assert {:error, %Error{reason: :invalid_profile, layer: :input}} =
               verify(c, %{name: {package, :synthetic}})
    end

    # Kind atoms remain local to an independently named extension package.
    assert {:ok, _} = verify(c, %{name: {:test_pkg, :rfc9421}})
  end

  test "integer profile metadata has symmetric magnitude bounds", c do
    for value <- [-999_999_999_999_999, 999_999_999_999_999] do
      profile = Map.put(@profile, :metadata, value)
      assert {:ok, %{profile: ^profile}} = verify(c, profile)
    end

    for value <- [
          -1_000_000_000_000_000,
          1_000_000_000_000_000,
          -Integer.pow(10, 100),
          Integer.pow(10, 100)
        ] do
      assert {:error, %Error{reason: :invalid_profile, layer: :input}} =
               verify(c, Map.put(@profile, :metadata, value))
    end
  end

  test "a package profile verifies published bytes and stamps its selected name", c do
    assert {:ok, verification} = verify(c, @profile)
    assert verification.profile == @profile
    assert verification.signature.crypto == :valid
    assert verification.principal == :unattributed
    assert verification.authorization == :not_evaluated
    # Eight atom keys are permitted; the ninth is rejected above.
    profile = Map.merge(@profile, Map.new(~w(a b c d e f g)a, &{&1, true}))
    assert {:ok, %{profile: ^profile}} = verify(c, profile)
  end

  test "profile metadata rejects unbounded or compound values with a safe error", c do
    for value <- [
          String.duplicate("PROFILE-CANARY", 100),
          1.5,
          [],
          %{},
          {:other, :tuple},
          self(),
          fn -> :ok end
        ] do
      assert {:error, %Error{reason: :invalid_profile, layer: :input} = error} =
               verify(c, Map.put(@profile, :metadata, value))

      refute inspect(error) =~ "PROFILE-CANARY"
    end
  end

  test "profile metadata accepts atoms, integers and binaries through 256 bytes", c do
    for value <- [:revision, true, nil, -1, 0, 1, "", :binary.copy(<<255>>, 256)] do
      profile = Map.put(@profile, :metadata, value)
      assert {:ok, %{profile: ^profile}} = verify(c, profile)
    end

    assert {:error, %Error{reason: :invalid_profile, layer: :input}} =
             verify(c, Map.put(@profile, :metadata, :binary.copy(<<255>>, 257)))
  end

  test "generic verification refuses profile and principal stamps with a bounded error", c do
    for option <- [:profile, :principal] do
      assert {:error, %Error{reason: :invalid_profile, layer: :input} = error} =
               RequestSeal.verify(c.message, c.policy, [
                 {:label, "sig-b26"},
                 {option, %{name: "STAMP-CANARY"}}
               ])

      refute inspect(error) =~ "STAMP-CANARY"
    end
  end

  test "dictionaries and preflight retain pairing, coverage and freshness checks", c do
    assert {:ok, {[{"sig-b26", input}], signatures}} = Profile.dictionaries(c.message, 16)
    assert input == c.input
    assert signatures["sig-b26"] == c.signature
    assert {:ok, :not_evaluated} = Profile.preflight(input, "()", :allow, :not_evaluated)

    assert {:error, %Error{reason: :missing_required_component, layer: :policy}} =
             Profile.preflight(input, ~s[("@query")], :allow, :not_evaluated)

    assert {:error, %Error{reason: :missing_signature, layer: :fields}} =
             Profile.dictionaries(
               %{
                 c.message
                 | fields:
                     Enum.reject(c.message.fields, &(String.downcase(&1.name) == "signature"))
               },
               16
             )
  end

  test "Ash rejects a successful synthetic profile before invoking caller bindings", c do
    assert {:ok, verification} = verify(c, @profile)
    owner = self()

    bind = fn principal ->
      send(owner, {:bound, principal})
      {:ok, principal}
    end

    binding = %{actor: bind, tenant: bind, unattributed: :anonymous}

    assert {:error, %Error{reason: :invalid_verification, layer: :binding}} =
             RequestSeal.Ash.scope(verification, binding)

    refute_received {:bound, _}
  end

  test "the same nonce has distinct claims by profile name and rejects its second claim" do
    now = System.system_time(:second)
    store = start_supervised!({RequestSeal.Replay.ETS, max_entries: 16})
    owner = self()

    replay = %{
      identifier: :nonce,
      namespace: "profile-test",
      commitment: fn facts ->
        send(owner, {:facts, facts})

        {:ok,
         :crypto.hash(:sha256, :erlang.term_to_binary({facts.profile.name, facts.identifier}))}
      end,
      store: RequestSeal.Replay.ETS.store(store),
      timeout: 1000
    }

    policy =
      S.policy(
        freshness: %{clock: fn -> now end, skew: 0, max_age: nil, require_expires: true},
        replay: replay
      )

    message =
      S.local_sign(
        S.unsigned(),
        "s",
        ~s[("@method");created=#{now};expires=#{now + 60};nonce="same-nonce"]
      )

    assert {:ok, generic} = RequestSeal.verify(message, policy, label: "s")
    assert generic.profile == %{name: :rfc9421}
    assert_receive {:facts, %{identifier: "same-nonce", profile: %{name: :rfc9421}}}
    assert {:ok, {entries, signatures}} = Profile.dictionaries(message, 16)

    c = %{
      message: message,
      policy: policy,
      input: entries |> Map.new() |> Map.fetch!("s"),
      signature: signatures["s"]
    }

    assert {:ok, synthetic} = verify(c, @profile, "s")
    assert synthetic.profile == @profile
    assert_receive {:facts, %{identifier: "same-nonce", profile: @profile}}
    assert {:error, %Error{reason: :replayed, layer: :replay}} = verify(c, @profile, "s")
    assert_receive {:facts, %{identifier: "same-nonce", profile: @profile}}

    other_profile = %{name: {:other_pkg, :synthetic}}
    assert {:ok, %{profile: ^other_profile}} = verify(c, other_profile, "s")
    assert_receive {:facts, %{identifier: "same-nonce", profile: ^other_profile}}
    assert {:error, %Error{reason: :replayed, layer: :replay}} = verify(c, other_profile, "s")
    assert_receive {:facts, %{identifier: "same-nonce", profile: ^other_profile}}
  end

  defp verify(c, profile, label \\ "sig-b26"),
    do: Profile.verify_label(c.message, c.policy, label, c.input, c.signature, profile)
end
