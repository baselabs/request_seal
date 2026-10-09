if Code.ensure_loaded?(Finch) do
  defmodule RequestSeal.Finch do
    @moduledoc """
    Optional finalized Finch translation and signing. No pool is started or owned.

    Requests preserve same-name header order and Finch's actual request target.
    `body: :as_is` (default) converts iodata to binary; streaming bytes remain
    unavailable. `body: {:retain, max}` enumerates a stream once under an explicit
    byte bound and replaces it with replayable bytes. No stream is silently read.
    Signing refuses unavailable body coverage, `host`, request `req`/`tr`
    components, conflicting digests, or unfaithful required fields. Cover
    `@authority` instead of `host`. Nil content hashes as empty bytes.

    The signing specification is `t:RequestSeal.signing_spec/0`: required `label`,
    `algorithm`, serialized `components` Inner List, and positive `expires_in`.
    Defaults are `created: true`, `nonce: :random`, `alg: true` (false for JWS
    algorithm tuples), `keyid: nil`, `tag: nil`, `digest: nil`, and
    `field_schemas: %{}`. Explicit full specs with all six `parameters` keys,
    `digest`, and `field_schemas` retain their existing bytes, including nil expiry.
    Parameter order is created, expires, nonce, alg, keyid, tag. Nonces use 32
    CSPRNG bytes, fresh on every signing invocation. `signing_timeout` defaults
    to 5,000 ms (1–300,000) for both KeyHandle and function signers. Function
    signers use custody's monitored workers; expiry or caller death terminates
    their work. `clock` defaults to system seconds. Digest is nil or an explicit
    unique SHA-256/SHA-512 list. Covered content-length is supplied only for
    retained bytes. Iodata retention defaults to a 16 MiB bound; an explicit
    retention choice sets its own bound. Digest computation retains its core
    16 MiB limit.
    Unknown/duplicate options reject.

    `response_message/3` defaults to `body: :retained`; `:consumed` preserves
    unavailability for caller-fed streaming hashes. Trailers remain separate.
    `verify/4` requires `label`, optionally accepts `digest_state` at caller EOF,
    and associates the exact supplied request. Streaming callers withhold their
    own effects until the returned verification succeeds. Errors use
    `RequestSeal.Adapter.Error`; no framework exception text is retained.
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
