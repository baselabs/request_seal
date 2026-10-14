if Code.ensure_loaded?(Finch) do
  defmodule RequestSeal.Finch do
    @moduledoc """
    Optional finalized Finch translation and signing. No pool is started or owned.

    Requests preserve same-name header order and Finch's actual request target.
    No stream is silently read: a streaming body stays unavailable unless the
    caller explicitly retains it under a byte bound. Signing refuses unavailable
    body coverage, `host`, request `req`/`tr` components, conflicting digests, or
    unfaithful required fields. Cover `@authority` instead of `host`.

    Response helpers keep trailers separate from headers and associate the exact
    supplied request. Streaming callers withhold their own effects until the
    returned verification succeeds. Unknown or duplicate options reject. Errors use
    `RequestSeal.Adapter.Error` with adapter `:finch` and attempt 1; no framework
    exception text is retained.
    """
    alias RequestSeal.{Message, TransportFacts, Verification}
    alias RequestSeal.Adapter.{Error, Signing}

    @type spec ::
            RequestSeal.signing_spec()
            | %{
                label: binary(),
                components: binary(),
                algorithm: RequestSeal.Crypto.algorithm(),
                parameters: %{
                  created: boolean(),
                  expires_in: pos_integer() | nil,
                  nonce: :random | nil,
                  keyid: binary() | nil,
                  tag: binary() | nil,
                  alg: boolean()
                },
                digest: [binary()] | nil,
                field_schemas: map()
              }

    @doc """
    Translates a built Finch request into a lossless `RequestSeal.Message` without signing it.

    The message uses the request's method and scheme, Finch's request path as an
    origin-form target, and an authority that lowercases the host and omits the
    default port (80 for HTTP, 443 for HTTPS). Headers keep their order and
    spelling. Trailers are `:unavailable`. The request is not sent.

    ## Parameters

      * `request` - a `Finch.Request` from `Finch.build/4`. Its scheme must be
        `:http` or `:https`, with a binary host and a port in 1..65,535.
      * `opts` - keyword list of the options below.

    ## Options

      * `:body` - how the request body becomes message bytes. Default `:as_is`.
        * `:as_is` - nil becomes empty retained bytes; iodata becomes retained
          bytes of at most 16 MiB (16,777,216 bytes); a `{:stream, enumerable}`
          body is not read and the message body is `:unavailable`.
        * `{:retain, max}` - `max` is a nonnegative integer byte bound. A stream
          is enumerated once and its bytes are retained; iodata is retained. A
          body longer than `max` rejects. A stream given as a bare function is
          not enumerated and rejects.

    ## Returns

      * `{:ok, %RequestSeal.Message{kind: :request}}` - the translated message.
      * `{:error, %RequestSeal.Adapter.Error{stage: :sign}}` - reasons:
        `:invalid_options` (unknown, duplicate, or malformed option),
        `:invalid_request` (not a Finch request; unsupported scheme, host, or
        port; non-list headers; unsupported body shape; or a value
        `RequestSeal.Message.new/1` rejects, kept as `source`),
        `:body_unavailable` (a bare function stream under `{:retain, max}`),
        `:limit` (body over the bound), and `:signing_failed` (an exception
        while enumerating the body or translating). Meanings:
        `RequestSeal.Adapter.Error`.

    ## Examples

        iex> request =
        ...>   Finch.build(
        ...>     :post,
        ...>     "https://telemetry.example.com:8443/ingest?batch=7",
        ...>     [{"content-type", "application/json"}],
        ...>     ~s({"cpu":0.42})
        ...>   )
        iex> {:ok, message} = RequestSeal.Finch.request_message(request)
        iex> {message.method, message.authority, message.raw_target, message.body.state}
        {"POST", "telemetry.example.com:8443", "/ingest?batch=7", :retained}
        iex> streamed =
        ...>   Finch.build(:post, "https://telemetry.example.com/ingest", [], {:stream, ["a", "b"]})
        iex> {:ok, message} = RequestSeal.Finch.request_message(streamed)
        iex> message.body.state
        :unavailable
        iex> {:ok, message} = RequestSeal.Finch.request_message(streamed, body: {:retain, 16})
        iex> message.body.bytes
        "ab"
        iex> {:error, error} = RequestSeal.Finch.request_message(streamed, body: {:retain, 1})
        iex> error.reason
        :limit
    """
    @spec request_message(Finch.Request.t(), keyword()) ::
            {:ok, Message.t()} | {:error, Error.t()}
    def request_message(request, opts \\ []) do
      Signing.protect(:finch, :sign, 1, fn ->
        Signing.options(opts, [:body])
        option = Keyword.get(opts, :body, :as_is)
        Signing.body_option!(option)
        {_request, message} = prepare(request, option)
        {:ok, message}
      end)
    end

    @doc """
    Signs a built Finch request and returns it with signature headers appended.

    The request is translated as in `request_message/2`, signed once with fresh
    metadata, and returned with its headers replaced by the signed field list:
    the original headers in order, then any generated `content-digest` and
    `content-length`, then `Signature-Input` and `Signature`. Iodata bodies become
    a binary; a retained stream is replaced by its bytes. Nothing is sent.

    ## Parameters

      * `request` - a `Finch.Request`, with the same requirements as in
        `request_message/2`.
      * `spec` - a `t:RequestSeal.signing_spec/0` or a full `t:spec/0`:
        * `:label` (required) - signature label.
        * `:algorithm` (required) - exact supported HTTP signature algorithm or a
          `{:jws, name}` selection.
        * `:components` (required) - serialized Structured Fields Inner List
          without metadata parameters. `"host"`, `tr`, and `req` components
          reject; cover `"@authority"` instead of `"host"`.
        * `:expires_in` - positive integer seconds (at most
          999,999,999,999,999), required in the short form. It requires
          `created`.
        * `:created` (default `true`), `:nonce` (`:random` or nil, default
          `:random`), `:alg` (default `true`, `false` for JWS algorithm tuples,
          which require `false`), `:keyid` and `:tag` (nil or printable ASCII of
          at most 1,024 bytes, default nil). These may also sit in a nested
          `:parameters` map. A full spec carrying all six parameter keys,
          `:digest`, and `:field_schemas` is used unchanged, including
          `expires_in: nil`.
        * `:digest` - nil (default) or a unique list of `"sha-256"` and
          `"sha-512"`. Without a `content-digest` header one is computed from the
          retained bytes (at most 16 MiB) and appended; an existing one must
          match exactly those algorithms and the bytes.
        * `:field_schemas` - explicit field schema map, default `%{}`.
      * `signer` - a `RequestSeal.KeyHandle` whose algorithm equals the spec's,
        or an arity-two function `(algorithm, base)` returning
        `{:ok, signature}` or `{:error, term}`. Both run in custody's monitored
        workers; the deadline or the caller's exit terminates their work.
      * `opts` - keyword list of the options below.

    Parameters are emitted in the order created, expires, nonce, alg, keyid,
    tag. A selected nonce is 32 CSPRNG bytes, unpadded Base64url, fresh on every
    call. Covered `content-length` is supplied from the retained bytes; an
    existing different value rejects.

    ## Options

      * `:signing_timeout` - 1..300,000 ms for either signer form. Default 5,000.
      * `:clock` - arity-zero function returning integer Unix seconds from 0
        through 253,402,300,799. Default system seconds. Used only when
        `created` is selected.
      * `:body` - `:as_is` (default) or `{:retain, max}`, as in
        `request_message/2`. Covering content (`:digest`, `content-digest`,
        `repr-digest`, or `content-length`) needs retained bytes.

    ## Returns

      * `{:ok, %Finch.Request{}}` - the signed request.
      * `{:error, %RequestSeal.Adapter.Error{stage: :sign}}` - reasons:
        `:invalid_options` (option, spec, signer, or clock value; for a handle
        bound to another algorithm, `source` is a `:signer_algorithm_mismatch`
        core error), `:invalid_request` (request translation as in
        `request_message/2`, or a covered `content-length` that disagrees with
        the bytes), `:unsupported_component` (`host`, `tr`, or `req`
        components, or a component the message cannot supply),
        `:body_unavailable` (content coverage without retained bytes),
        `:digest_conflict` (an existing `content-digest` disagrees),
        `:limit` (body, component, digest, or signature base bound), and
        `:signing_failed` (signer or custody failure, with a bounded `source`
        when available, or an unexpected exception). Meanings:
        `RequestSeal.Adapter.Error`.

    ## Examples

        iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        iex> spec = %{
        ...>   label: "sig",
        ...>   algorithm: "ed25519",
        ...>   components: ~s[("@method" "@authority" "@path" "content-digest")],
        ...>   expires_in: 60,
        ...>   digest: ["sha-256"]
        ...> }
        iex> request =
        ...>   Finch.build(
        ...>     :put,
        ...>     "https://builds.example.org/artifacts/42",
        ...>     [{"content-type", "application/octet-stream"}],
        ...>     "artifact bytes"
        ...>   )
        iex> {:ok, signed} = RequestSeal.Finch.sign(request, spec, handle)
        iex> Enum.map(signed.headers, &elem(&1, 0))
        ["content-type", "content-digest", "Signature-Input", "Signature"]
        iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
        iex> {:ok, policy} =
        ...>   RequestSeal.Policy.new(%{
        ...>     algorithms: ["ed25519"],
        ...>     components: spec.components,
        ...>     key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
        ...>     freshness: :not_evaluated,
        ...>     content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
        ...>     replay: :not_required
        ...>   })
        iex> {:ok, message} = RequestSeal.Finch.request_message(signed)
        iex> {:ok, verification} = RequestSeal.verify(message, policy, label: "sig")
        iex> verification.label
        "sig"
        iex> streamed = Finch.build(:put, "https://builds.example.org/artifacts/43", [], {:stream, ["a"]})
        iex> {:error, error} = RequestSeal.Finch.sign(streamed, spec, handle)
        iex> error.reason
        :body_unavailable
        iex> {:error, error} = RequestSeal.Finch.sign(request, %{spec | components: ~s[("host")]}, handle)
        iex> error.reason
        :unsupported_component
        iex> RequestSeal.Custody.Local.release(handle)
        :ok
    """
    @spec sign(
            Finch.Request.t(),
            spec(),
            RequestSeal.Policy.signer() | RequestSeal.KeyHandle.t(),
            keyword()
          ) :: {:ok, Finch.Request.t()} | {:error, Error.t()}
    def sign(request, spec, signer, opts \\ []) do
      Signing.protect(:finch, :sign, 1, fn ->
        Signing.options(opts, [:signing_timeout, :clock, :body])
        Signing.sign_options!(opts)
        {request, message} = prepare(request, Keyword.get(opts, :body, :as_is))
        signed = Signing.sign(message, spec, signer, opts)
        {:ok, %{request | headers: Enum.map(signed.fields, &{&1.name, &1.value})}}
      end)
    end

    @doc """
    Translates a Finch response and the request that produced it into a response `RequestSeal.Message`.

    Status, headers, and trailers keep their order; trailers stay in their own
    section. The related request is translated as by `request_message/2` with
    `body: :as_is`, so `req` components resolve against exactly that request.

    ## Parameters

      * `response` - a `Finch.Response` with integer status and list headers
        and trailers.
      * `request` - the `Finch.Request` that produced the response, with the
        same requirements as in `request_message/2`.
      * `opts` - keyword list of the options below.

    ## Options

      * `:body` - `:retained` (default) uses the response's binary body as
        retained bytes. `:consumed` marks the body as consumed, for callers that
        feed a streaming body into their own `RequestSeal.Digest` state.

    ## Returns

      * `{:ok, %RequestSeal.Message{kind: :response}}` - the translated message.
      * `{:error, %RequestSeal.Adapter.Error{stage: :verify}}` - reasons:
        `:invalid_options` (unknown, duplicate, or unsupported option value),
        `:invalid_request` (not a Finch response, a request that cannot be
        translated, or a value `RequestSeal.Message.new/1` rejects),
        `:body_unavailable` (`:retained` with a non-binary response body),
        `:limit` (a related request body over 16 MiB), and
        `:response_rejected` (an unexpected exception). Meanings:
        `RequestSeal.Adapter.Error`.

    ## Examples

        iex> request = Finch.build(:get, "https://docs.example.com/guides/1")
        iex> response = %Finch.Response{
        ...>   status: 200,
        ...>   headers: [{"content-type", "text/plain"}],
        ...>   body: "guide text"
        ...> }
        iex> {:ok, message} = RequestSeal.Finch.response_message(response, request)
        iex> {message.kind, message.status, message.body.bytes, message.related_request.raw_target}
        {:response, 200, "guide text", "/guides/1"}
        iex> {:ok, message} = RequestSeal.Finch.response_message(response, request, body: :consumed)
        iex> message.body.state
        :consumed
        iex> {:error, error} = RequestSeal.Finch.response_message(response, request, body: :streamed)
        iex> error.reason
        :invalid_options
    """
    @spec response_message(Finch.Response.t(), Finch.Request.t(), keyword()) ::
            {:ok, Message.t()} | {:error, Error.t()}
    def response_message(response, request, opts \\ []) do
      Signing.protect(:finch, :verify, 1, fn ->
        Signing.options(opts, [:body])
        disposition = Keyword.get(opts, :body, :retained)
        Signing.ensure(disposition in [:retained, :consumed], :invalid_options)
        {_, related} = prepare(request, :as_is)
        {:ok, response_value(response, related, disposition)}
      end)
    end

    @doc """
    Verifies one labeled signature on a Finch response, bound to the exact request supplied.

    The response is translated as by `response_message/3` and passed to
    `RequestSeal.verify/3` with `policy` and the options below. A successful
    result grants no authorization.

    ## Parameters

      * `response` - a `Finch.Response`. Its body must be a binary unless
        `:digest_state` is given.
      * `request` - the `Finch.Request` that produced the response.
      * `policy` - a `RequestSeal.Policy` built with `RequestSeal.Policy.new/1`.
      * `opts` - keyword list of the options below.

    ## Options

      * `:label` - the signature label to verify. Required by the core verifier;
        omitting it returns `:response_rejected`.
      * `:digest_state` - a `RequestSeal.Digest` state the caller fed with a
        streamed body and finished at its own end of stream. When present the
        response body is treated as consumed and is not read.

    ## Returns

      * `{:ok, %RequestSeal.Verification{}}` - the verified facts.
      * `{:error, %RequestSeal.Adapter.Error{stage: :verify}}` - reasons:
        `:invalid_options` (unknown or duplicate option), `:invalid_request` (as
        in `response_message/3`), `:body_unavailable` (non-binary body without
        `:digest_state`), `:limit` (a related request body over 16 MiB), and
        `:response_rejected` (the core verifier rejected; its bounded
        `RequestSeal.Error` is kept as `source`, or an unexpected exception
        occurred). Meanings: `RequestSeal.Adapter.Error`.

    ## Examples

        iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
        iex> request = Finch.build(:get, "https://docs.example.com/guides/1")
        iex> response = %Finch.Response{
        ...>   status: 200,
        ...>   headers: [{"content-type", "text/plain"}],
        ...>   body: "guide text"
        ...> }
        iex> components = ~s[("@status" "content-type" "@path";req)]
        iex> {:ok, unsigned} = RequestSeal.Finch.response_message(response, request)
        iex> {:ok, signed} =
        ...>   RequestSeal.sign(unsigned, %{
        ...>     label: "res",
        ...>     algorithm: "ed25519",
        ...>     components: components,
        ...>     expires_in: 60
        ...>   }, handle)
        iex> response = %{response | headers: Enum.map(signed.fields, &{&1.name, &1.value})}
        iex> {:ok, policy} =
        ...>   RequestSeal.Policy.new(%{
        ...>     algorithms: ["ed25519"],
        ...>     components: components,
        ...>     key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
        ...>     freshness: :not_evaluated,
        ...>     content: :not_required,
        ...>     replay: :not_required
        ...>   })
        iex> {:ok, verification} = RequestSeal.Finch.verify(response, request, policy, label: "res")
        iex> verification.label
        "res"
        iex> other = Finch.build(:get, "https://docs.example.com/guides/2")
        iex> {:error, error} = RequestSeal.Finch.verify(response, other, policy, label: "res")
        iex> {error.reason, error.source.reason}
        {:response_rejected, :invalid_signature}
        iex> RequestSeal.Custody.Local.release(handle)
        :ok
    """
    @spec verify(Finch.Response.t(), Finch.Request.t(), RequestSeal.Policy.t(), keyword()) ::
            {:ok, Verification.t()} | {:error, Error.t()}
    def verify(response, request, policy, opts \\ []) do
      Signing.protect(:finch, :verify, 1, fn ->
        Signing.options(opts, [:label, :digest_state])
        disposition = if Keyword.has_key?(opts, :digest_state), do: :consumed, else: :retained
        {_, related} = prepare(request, :as_is)
        message = response_value(response, related, disposition)
        verify_value(message, policy, opts)
      end)
    end

    @doc false
    def verify_value(message, policy, opts) do
      case RequestSeal.verify(message, policy, opts) do
        {:ok, _} = result -> result
        {:error, source} -> Signing.fail(:response_rejected, source)
      end
    end

    @doc false
    def response_value(%Finch.Response{} = response, related, disposition) do
      body =
        case disposition do
          :retained ->
            Signing.ensure(is_binary(response.body), :body_unavailable)
            Signing.retained(response.body)

          :consumed ->
            %RequestSeal.Body{state: :consumed}
        end

      construct(%{
        kind: :response,
        status: response.status,
        fields: fields(response.headers, :headers),
        trailers: fields(response.trailers, :trailers),
        body: body,
        related_request: related,
        transport: %TransportFacts{}
      })
    end

    def response_value(_, _, _), do: Signing.fail(:invalid_request)

    @doc false
    def prepare(%Finch.Request{} = request, option) do
      Signing.ensure(
        request.scheme in [:http, :https] and is_binary(request.host) and is_integer(request.port) and
          request.port in 1..65535,
        :invalid_request
      )

      {body, snapshot} = Signing.body(request.body, option)
      authority = authority(request)

      message =
        construct(%{
          kind: :request,
          method: request.method,
          raw_target: Finch.Request.request_path(request),
          target_form: :origin,
          scheme: Atom.to_string(request.scheme),
          authority: authority,
          fields: fields(request.headers, :headers),
          trailers: :unavailable,
          body: snapshot,
          transport: %TransportFacts{}
        })

      {%{request | body: body}, message}
    end

    def prepare(_, _), do: Signing.fail(:invalid_request)

    defp authority(request) do
      normalized_host = String.downcase(request.host, :ascii)

      host =
        if String.contains?(normalized_host, ":"),
          do: "[#{normalized_host}]",
          else: normalized_host

      if (request.scheme == :http and request.port == 80) or
           (request.scheme == :https and request.port == 443),
         do: host,
         else: "#{host}:#{request.port}"
    end

    defp construct(attrs) do
      case Message.new(attrs) do
        {:ok, message} -> message
        {:error, source} -> Signing.fail(:invalid_request, source)
      end
    end

    defp fields(headers, section) do
      Signing.ensure(is_list(headers), :invalid_request)

      Enum.map(headers, fn {name, value} ->
        %RequestSeal.FieldOccurrence{name: name, value: value, section: section}
      end)
    end
  end
end
