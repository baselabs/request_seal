if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.State do
    @moduledoc false
    @derive {Inspect, only: []}
    defstruct [:capture, :verification, :error, :replay_id, reader_called?: false]

    def get(conn), do: Map.get(conn.private, :request_seal, %__MODULE__{})
    def put(conn, state), do: Plug.Conn.put_private(conn, :request_seal, state)
    def error(conn, error), do: put(conn, %{get(conn) | error: error})
  end

  defmodule RequestSeal.Plug do
    @moduledoc """
    Optional Plug/Phoenix integration with explicit origin and verification policy.

    Run `RequestSeal.Plug.Capture` before body parsers, origin rewriting, or
    remote-IP rewriting. Its request-local adapter replays retained bytes to
    every Plug reader, including multipart. The optional
    `body_reader: {RequestSeal.Plug.Capture, :read_body, []}` records its
    invocation in request-local state and delegates to that adapter. Reads honor
    `:length`, returning `:more` until the retained body is
    drained. `RequestSeal.Plug.Verify` uses only the captured message.
    Pass-through parsers can leave the raw body unread for application readers,
    including requests without a content type. Fetched empty params do not
    establish body consumption.
    The captured replay must remain installed in the Delivery adapter; replacing
    or rewrapping it rejects with `:parser_order` before key resolution. Once any
    replay read occurs, verification requires full draining and a digest of all
    handed-out bytes matching the full captured body. Partial reads and mismatches
    reject with `:parser_order` before key resolution. A custom wrapper reader must
    return the replayed bytes unchanged. Transformations made after the adapter
    returns are outside its observation: even a matching replay digest cannot
    prove that a wrapper or parser used those bytes unchanged. Intentional
    content decoding belongs after capture, under caller control.
    A configured wrapper that returns substitute bytes without calling either
    `Capture.read_body/2` or the adapter leaves both read signals unset. Verify
    cannot distinguish that configuration from a pass-through parser that leaves
    the body unread: fetched params alone do not prove a read. Such a wrapper can
    parse different bytes while the untouched captured request verifies. Callers
    must use the RequestSeal reader or adapter and return those bytes unchanged;
    verification does not authenticate parser outputs or enforce reader configuration.
    A manual `Plug.Conn.read_body` before Capture cannot be detected and must
    not be used.
    Verification grants no authorization; applications decide access themselves.

    Exact target evidence is required by
    [RFC 9421 Section 2.2.5](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.5).
    Plug's `request_path` and `query_string` cannot distinguish `/foo?` from `/foo`
    or recover the original HTTP/1 target form. OBSERVED with Plug 1.20.3,
    Bandit 1.12.5, and Phoenix 1.8.15 through actual socket tests:

    * Bandit HTTP/1.0 and HTTP/1.1 (TCP or TLS): the consumed request line is not
      retained in the Plug adapter payload.
    * Bandit HTTP/2 (TLS/ALPN or h2c): the consumed `:path` pseudo-header is not
      retained in the Plug adapter payload.
    * Phoenix on Bandit (HTTP/1.1 and h2c) and a TLS Bandit reverse proxy use
      those same lossy values; an explicit trusted origin does not restore them.

    Capture retains a reconstructed origin-form target for path derivation only.
    Verify refuses policies requiring or selected signatures covering
    `@request-target`, `@target-uri`, or `@query` with the nonretryable
    `RequestSeal.Adapter.Error` reason `:unsupported_component`, before any
    resolver or replay callback. This rule applies even with a nonempty query
    and to other Plug transports without proven exact evidence. It reads the
    selected Signature-Input label; unrelated labels do not impose coverage.
    Policies covering only `@path`, `@method`, `@authority`, fields, and retained
    content remain usable. SignResponse likewise refuses target-dependent
    request components selected with `req`. No forwarded field, private caller
    value, or reconstructed target is treated as raw transport evidence.

    Results live in redacted `conn.private[:request_seal]`. The `:assign` option
    on Verify explicitly copies successful verification into caller-selected assigns.
    `capture/1` and `verification/1` return `:error` when their result is unavailable.
    Read error values explicitly from private state's `:error` or `:verification`.
    Application plugs between Verify and SignResponse can replace captured state
    in `conn.private`; they are inside the server trust boundary. SignResponse
    binds to the captured state present when its callback runs.

    `RequestSeal.Plug.SignResponse` arranges its callback after other registered
    callbacks. Because Plug merges response cookies afterward, covering
    `set-cookie` with pending `resp_cookies` fails closed with
    `:unsupported_delivery`, including cookies set by session callbacks. Set
    explicit final `set-cookie` headers to sign cookie fields. Disable server-side
    transformations after signing (including Bandit's response compression) when
    covering response bytes. This adapter starts no server, pool, or process.
    """
    alias RequestSeal.Plug.State

    @doc "Return the retained capture; does not consume or verify anything."
    @spec capture(Plug.Conn.t()) :: {:ok, RequestSeal.Plug.Capture.t()} | :error
    def capture(%Plug.Conn{
          private: %{request_seal: %State{capture: %RequestSeal.Plug.Capture{} = capture}}
        }),
        do: {:ok, capture}

    def capture(_), do: :error

    @doc "Return successful verification only; failure never supplies partial facts."
    @spec verification(Plug.Conn.t()) :: {:ok, RequestSeal.Verification.t()} | :error
    def verification(%Plug.Conn{private: %{request_seal: %State{verification: {:ok, result}}}}),
      do: {:ok, result}

    def verification(_), do: :error
  end
end
