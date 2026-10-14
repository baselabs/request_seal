defmodule RequestSeal.GuideKeyRotationTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography" do
    binding = []

    binding =
      E.eval(
        ~S'''
        alias RequestSeal.Custody.Local.Owner

        seed_dir = Path.join(System.tmp_dir!(), "rotation-#{System.unique_integer([:positive])}")
        File.mkdir_p!(seed_dir)

        write_seed = fn name ->
          {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
          path = Path.join(seed_dir, name)
          File.write!(path, Base.url_encode64(seed, padding: false))
          File.chmod!(path, 0o600)
          path
        end

        current_file = write_seed.("current.seed")
        next_file = write_seed.("next.seed")

        {:ok, supervisor} =
          Supervisor.start_link(
            [
              {Owner,
               name: Rotation.Custody,
               keys: [
                 current: {"ed25519", {:file, current_file, :base64url}},
                 next: {"ed25519", {:file, next_file, :base64url}}
               ]}
            ],
            strategy: :one_for_one
          )

        %{current: :ready, next: :ready} = Owner.status(Rotation.Custody)
        ''',
        binding,
        "docs/guides/key-rotation.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, next_handle} = RequestSeal.Custody.Local.Owner.fetch(Rotation.Custody, :next)
        {:ok, next_key} = RequestSeal.Custody.public_key(next_handle)
        {:ok, next_jwk} = RequestSeal.PublicKey.export(next_key, :jwk)
        {:ok, next_thumbprint} = RequestSeal.PublicKey.thumbprint(next_key)
        %{"kty" => "OKP", "crv" => "Ed25519"} = next_jwk
        ''',
        binding,
        "docs/guides/key-rotation.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, current_handle} = RequestSeal.Custody.Local.Owner.fetch(Rotation.Custody, :current)
        {:ok, current_key} = RequestSeal.Custody.public_key(current_handle)
        components = ~s[("@method" "@scheme" "@authority" "@path")]

        policy_for = fn trusted ->
          {:ok, policy} =
            RequestSeal.Policy.new(%{
              algorithms: ["ed25519"],
              components: components,
              key_resolver: fn %{keyid: keyid} ->
                case Map.fetch(trusted, keyid) do
                  {:ok, key} -> {:ok, %{algorithm: "ed25519", key: key}}
                  :error -> :error
                end
              end,
              freshness: %{
                clock: fn -> System.system_time(:second) end,
                max_age: 60,
                skew: 5,
                require_expires: true
              },
              content: :not_required,
              replay: :not_required
            })

          policy
        end

        overlap_policy = policy_for.(%{"build-2" => current_key, "build-3" => next_key})
        ''',
        binding,
        "docs/guides/key-rotation.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        sign_with = fn name, keyid ->
          {:ok, handle} = RequestSeal.Custody.Local.Owner.fetch(Rotation.Custody, name)
          {:ok, message} = RequestSeal.Message.request("POST", "https://ci.example.com/artifacts", [], nil)
          spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60, keyid: keyid}
          RequestSeal.sign(message, spec, handle)
        end

        {:ok, before_switch} = sign_with.(:current, "build-2")
        {:ok, after_switch} = sign_with.(:next, "build-3")
        {:ok, _} = RequestSeal.verify(before_switch, overlap_policy, label: "sig")
        {:ok, _} = RequestSeal.verify(after_switch, overlap_policy, label: "sig")
        ''',
        binding,
        "docs/guides/key-rotation.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        retired_policy = policy_for.(%{"build-3" => next_key})
        {:ok, _} = RequestSeal.verify(after_switch, retired_policy, label: "sig")

        {:error, %{reason: :unknown_key, layer: :key}} =
          RequestSeal.verify(before_switch, retired_policy, label: "sig")
        ''',
        binding,
        "docs/guides/key-rotation.md",
        5
      )

    binding =
      E.eval(
        ~S'''
        :ok = Supervisor.terminate_child(supervisor, Rotation.Custody)
        File.rm!(current_file)
        {:ok, _} = Supervisor.restart_child(supervisor, Rotation.Custody)

        %{current: :unconfigured, next: :ready} = RequestSeal.Custody.Local.Owner.status(Rotation.Custody)

        {:error, %{reason: :signing_failed, source: %{reason: :key_not_found}}} =
          RequestSeal.sign(before_switch, %{label: "late", algorithm: "ed25519", components: components, expires_in: 60}, next_handle)

        {:ok, _} = sign_with.(:next, "build-3")
        :ok = Supervisor.stop(supervisor)
        File.rm_rf!(seed_dir)
        ''',
        binding,
        "docs/guides/key-rotation.md",
        6
      )

    assert Keyword.fetch!(binding, :next_thumbprint) |> byte_size() == 43
    refute File.exists?(Keyword.fetch!(binding, :seed_dir))
    E.assert_fences("docs/guides/key-rotation.md", 6)
  end
end
