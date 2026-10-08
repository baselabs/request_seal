defmodule RequestSeal.PlugPhoenixController do
  use Phoenix.Controller, formats: [:json]
  def create(conn, params), do: json(conn, params)

  def session(conn, _params) do
    conn =
      conn
      |> Plug.Conn.fetch_session()
      |> Plug.Conn.put_session("visited", true)
      |> Plug.Conn.put_resp_header("set-cookie", "control=header")
      |> json(%{"visited" => true})

    opts = Application.fetch_env!(:request_seal, :plug_phoenix)
    send(opts[:owner], {:phoenix_session_sent, conn})
    conn
  end

  def raw(conn, _params) do
    {:ok, bytes, conn} = Plug.Conn.read_body(conn)
    {:ok, "", conn} = Plug.Conn.read_body(conn)
    Plug.Conn.send_resp(conn, 200, bytes)
  end
end

defmodule RequestSeal.PlugPhoenixRouter do
  use Phoenix.Router

  pipeline :signed do
    plug(:verify_signature)
  end

  scope "/", RequestSeal do
    pipe_through(:signed)
    post("/foo", PlugPhoenixController, :create)
    post("/raw", PlugPhoenixController, :raw)
    post("/session", PlugPhoenixController, :session)
  end

  defp verify_signature(conn, _) do
    opts = Application.fetch_env!(:request_seal, :plug_phoenix)

    RequestSeal.Plug.Verify.call(
      conn,
      RequestSeal.Plug.Verify.init(
        policy: opts[:policy],
        label: "sig",
        on_reject: {:halt, 401},
        assign: :verified
      )
    )
  end
end

defmodule RequestSeal.PlugPhoenixEndpoint do
  use Phoenix.Endpoint, otp_app: :request_seal
  plug(:capture_request)
  plug(Plug.Session, store: :cookie, key: "_request_seal_session", signing_salt: "session-test")

  plug(Plug.Parsers,
    parsers: [:json],
    pass: ["*/*"],
    json_decoder: Jason,
    body_reader: {RequestSeal.Plug.Capture, :read_body, []}
  )

  plug(:sign_response)
  plug(RequestSeal.PlugPhoenixRouter)

  defp capture_request(conn, _) do
    RequestSeal.Plug.Capture.call(
      conn,
      RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: 4096, read_timeout: 1000)
    )
  end

  defp sign_response(conn, _) do
    opts = Application.fetch_env!(:request_seal, :plug_phoenix)

    components =
      if conn.request_path == "/session",
        do: ~s[("@status" "set-cookie" "content-digest")],
        else: RequestSeal.PlugTransport.response_components()

    conn =
      RequestSeal.Plug.SignResponse.call(
        conn,
        RequestSeal.Plug.SignResponse.init(
          sign: %{
            RequestSeal.PlugTransport.spec(components)
            | label: "res"
          },
          signer: opts[:handle],
          signing_timeout: 1000,
          clock: fn -> System.system_time(:second) end,
          on_failure: {:respond, 503}
        )
      )

    Plug.Conn.register_before_send(conn, fn c ->
      send(opts[:owner], {:phoenix, c, RequestSeal.Plug.verification(c)})
      c
    end)
  end
end

defmodule RequestSeal.PlugForwarder do
  @moduledoc false
  def init(opts), do: opts

  def call(conn, opts) do
    {:ok, bytes, conn} = Plug.Conn.read_body(conn)
    uri = URI.parse(opts[:backend])

    fields =
      Enum.reject(conn.req_headers, fn {name, _} ->
        name in [
          "host",
          "forwarded",
          "x-forwarded-proto",
          "x-forwarded-host",
          "connection",
          "content-length"
        ]
      end)

    forwarded =
      "for=127.0.0.1;proto=https;host=\"" <>
        conn.host <> ":" <> Integer.to_string(conn.port) <> "\""

    fields =
      fields ++ [{"forwarded", "for=192.0.2.43;proto=http;host=ignored.example, " <> forwarded}]

    target =
      conn.request_path <> if(conn.query_string == "", do: "", else: "?" <> conn.query_string)

    req = Finch.build(conn.method, "http://127.0.0.1:#{uri.port}" <> target, fields, bytes)
    {:ok, res} = Finch.request(req, opts[:pool])
    Plug.Conn.send_resp(conn, res.status, res.body)
  end
end
