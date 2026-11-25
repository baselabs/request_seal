defmodule RequestSeal.SignedPathTestSupport do
  @moduledoc false
  alias RequestSeal.{Custody, Message, Policy}
  alias RequestSeal.Custody.Local
  alias RequestSeal.Plug.{Capture, Verify}

  def verified(target, components, opts \\ []) do
    url = "https://example.test" <> target
    body = Keyword.get(opts, :body, "")
    method = if body == "", do: :get, else: :post
    body_headers = if body == "", do: [], else: [{"content-type", "application/json"}]
    headers = body_headers ++ Keyword.get(opts, :headers, [])
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = Local.new("ed25519", {:ed25519, seed})

    try do
      {:ok, key} = Custody.public_key(handle)
      {:ok, message} = Message.request(method |> Atom.to_string() |> String.upcase(), url, headers, body)

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
        Enum.reduce(signed.fields, Plug.Test.conn(method, url, body), fn field, conn ->
          Plug.Conn.put_req_header(conn, String.downcase(field.name), field.value)
        end)
        |> Capture.call(capture)
        |> parse_body(Keyword.get(opts, :parse_body, body != ""))
        |> Verify.call(verify)

      {:ok, _} = RequestSeal.Plug.verification(conn)
      conn
    after
      :ok = Local.release(handle)
    end
  end

  defp parse_body(conn, true) do
    parser = Plug.Parsers.init(parsers: [:json], json_decoder: Jason)
    Plug.Parsers.call(conn, parser)
  end

  defp parse_body(conn, false), do: conn

end
