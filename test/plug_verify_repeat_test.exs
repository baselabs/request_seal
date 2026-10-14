defmodule RequestSeal.PlugVerifyRepeatTest do
  use ExUnit.Case, async: true
  alias RequestSeal.Adapter.Error
  alias RequestSeal.Plug.{Capture, Verify}

  @url "https://messages.example.com/inbox"

  setup do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
    {:ok, key} = RequestSeal.Custody.public_key(handle)
    on_exit(fn -> RequestSeal.Custody.Local.release(handle) end)

    {:ok, message} = RequestSeal.Message.request("POST", @url, [], "hello")

    {:ok, signed} =
      RequestSeal.sign(
        message,
        %{
          label: "sig",
          algorithm: "ed25519",
          components: ~s[("@method" "@path")],
          expires_in: 60
        },
        handle
      )

    policy = fn components ->
      {:ok, policy} =
        RequestSeal.Policy.new(%{
          algorithms: ["ed25519"],
          components: components,
          key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
          freshness: :not_evaluated,
          content: :not_required,
          replay: :not_required
        })

      policy
    end

    conn =
      Enum.reduce(signed.fields, Plug.Test.conn(:post, @url, "hello"), fn f, conn ->
        Plug.Conn.put_req_header(conn, String.downcase(f.name), f.value)
      end)
      |> Capture.call(
        Capture.init(origin: :connection, max_body_bytes: 1_024, read_timeout: 5_000)
      )

    %{conn: conn, loose: policy.(~s[("@method")]), strict: policy.(~s[("@method" "@authority")])}
  end

  defp verify(conn, policy, opts \\ []) do
    options = Keyword.merge([policy: policy, label: "sig", on_reject: :continue], opts)
    Verify.call(conn, Verify.init(options))
  end

  test "a stricter second Verify under :continue fails closed", c do
    first = verify(c.conn, c.loose, assign: :loose)
    assert {:ok, _} = RequestSeal.Plug.verification(first)

    second = verify(first, c.strict, assign: :strict)
    refute match?({:ok, _}, RequestSeal.Plug.verification(second))
    assert :error = RequestSeal.Plug.verification(second)
    assert {:error, %Error{reason: :already_verified}} = second.private.request_seal.verification
    refute Map.has_key?(second.assigns, :loose)
    refute Map.has_key?(second.assigns, :strict)
    refute second.halted
  end

  test "a different label also fails closed and halts when asked", c do
    first = verify(c.conn, c.loose)
    second = verify(first, c.loose, label: "other", on_reject: {:halt, 401})
    assert {second.status, second.halted} == {401, true}
    assert :error = RequestSeal.Plug.verification(second)
  end

  test "an identical repeat keeps the first result", c do
    first = verify(c.conn, c.loose, assign: :sig)
    {:ok, verified} = RequestSeal.Plug.verification(first)
    again = verify(first, c.loose, assign: :sig)
    assert {:ok, ^verified} = RequestSeal.Plug.verification(again)
    assert again.assigns.sig == verified
    refute again.halted
    assert again.private.request_seal.error == nil
  end

  test "an identical repeat of a rejection rejects again", c do
    first = verify(c.conn, c.strict, label: "missing", on_reject: {:halt, 401})
    assert {first.status, first.halted} == {401, true}

    again =
      verify(%{first | halted: false, state: :unset, status: nil}, c.strict,
        label: "missing",
        on_reject: {:halt, 403}
      )

    assert {:error, %Error{reason: :request_rejected}} = again.private.request_seal.verification
    assert {again.status, again.halted} == {403, true}
  end
end
