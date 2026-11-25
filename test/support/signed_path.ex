defmodule RequestSeal.SignedPathTestSupport do
  @moduledoc false
  alias RequestSeal.{Custody, Message, Policy}
  alias RequestSeal.Custody.Local
  alias RequestSeal.Plug.{Capture, Verify}

  def verified(target, components) do
    url = "https://example.test" <> target
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = Local.new("ed25519", {:ed25519, seed})

    try do
      {:ok, key} = Custody.public_key(handle)
      {:ok, message} = Message.request("GET", url, [], "")

      {:ok, signed} =
        RequestSeal.sign(
          message,
          %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60},
          handle
        )

      {:ok, policy} =
        Policy.new(%{
          algorithms: ["ed25519"],
          components: components,
          key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
          freshness: :not_evaluated,
          content: :not_required,
          replay: :not_required
        })

      capture = Capture.init(origin: :connection, max_body_bytes: 1_024, read_timeout: 1_000)
      verify = Verify.init(policy: policy, label: "sig", on_reject: :continue)

      conn =
        Enum.reduce(signed.fields, Plug.Test.conn(:get, url), fn field, conn ->
          Plug.Conn.put_req_header(conn, String.downcase(field.name), field.value)
        end)
        |> Capture.call(capture)
        |> Verify.call(verify)

      {:ok, _} = RequestSeal.Plug.verification(conn)
      conn
    after
      :ok = Local.release(handle)
    end
  end
end
