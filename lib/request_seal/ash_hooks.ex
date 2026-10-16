if Code.ensure_loaded?(AshHooks.Provider) do
  defmodule RequestSeal.AshHooks do
    @moduledoc """
    Optional ash_hooks inbound RFC 9421 verification bridge (Elixir 1.20).

    A consumer's `c:AshHooks.Provider.verify_signature/3` delegates to
    `verify_signature/4` with an explicit policy and label. RequestSeal never
    interprets the provider's secret/key reference as key material or
    authorizes an application action.

    The provider's headers map has already lost duplicate lines and ordering;
    the helper cannot recover them and returns only the provider's `:ok`/error
    contract.
    Prefer `RequestSeal.Plug.Capture` and `RequestSeal.Plug.Verify` before
    ash_hooks ingress to retain ordered headers, exact body bytes, and facts.
    The RequestSeal reader replays unchanged bytes to `AshHooks.BodyReader`.
    Provider errors never expose key references, body bytes, or callback errors.
    """
    @doc """
    Verifies a provider's exact body under an explicit policy and signature label.

    The request is rebuilt with `RequestSeal.Message.request/5` from the
    context's method, URI, and header map, with `body` as retained bytes, then
    checked with `RequestSeal.verify/3`.

    ## Parameters

      * `body` - the exact raw request body bytes.
      * `context` - an `t:AshHooks.Provider.verify_context/0` map. Its `:method`,
        absolute `:request_uri`, `:headers` map, and `:tenant` are used; other
        keys are ignored.
      * `reference` - the provider's nonempty binary secret/key reference. It is
        passed only to a policy function, never used as key material.
      * `opts` - keyword list of the options below. Unknown or duplicate
        options return `{:error, :invalid_signature}`.

    ## Options

      * `:policy` - a `RequestSeal.Policy`, or an arity-two function called as
        `fun.(context.tenant, reference)` that returns one.
      * `:label` - the signature label to verify.

    ## Returns

      * `:ok` - the signature verified. This grants no authorization.
      * `{:error, :no_webhook_secret}` - `reference` is not a nonempty binary.
      * `{:error, :invalid_signature}` - any other failure: invalid options, a
        policy function that raised, a context the message cannot be built
        from, or a verification rejection. No key reference, body bytes, or
        callback error is exposed.

    ## Examples

        iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
        iex> body = ~s({"build":"1842","state":"passed"})
        iex> url = "https://hooks.example.com/builds"
        iex> spec = %{
        ...>   label: "sig",
        ...>   algorithm: "ed25519",
        ...>   components: ~s[("@method" "@authority" "@path" "content-digest" "content-type")],
        ...>   expires_in: 300,
        ...>   digest: ["sha-256"]
        ...> }
        iex> {:ok, message} =
        ...>   RequestSeal.Message.request("POST", url, [{"content-type", "application/json"}], body)
        iex> {:ok, signed} = RequestSeal.sign(message, spec, handle)
        iex> headers = Map.new(signed.fields, &{String.downcase(&1.name), &1.value})
        iex> context = %{
        ...>   method: "POST",
        ...>   request_uri: url,
        ...>   headers: headers,
        ...>   signature: headers["signature"],
        ...>   tenant: nil
        ...> }
        iex> {:ok, policy} =
        ...>   RequestSeal.Policy.new(%{
        ...>     algorithms: ["ed25519"],
        ...>     components: spec.components,
        ...>     key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
        ...>     freshness: :not_evaluated,
        ...>     content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
        ...>     replay: :not_required
        ...>   })
        iex> opts = [policy: fn nil, "builds-key" -> policy end, label: "sig"]
        iex> RequestSeal.AshHooks.verify_signature(body, context, "builds-key", opts)
        :ok
        iex> RequestSeal.AshHooks.verify_signature(body <> " ", context, "builds-key", opts)
        {:error, :invalid_signature}
        iex> RequestSeal.AshHooks.verify_signature(body, context, "", opts)
        {:error, :no_webhook_secret}
        iex> RequestSeal.Custody.Local.release(handle)
        :ok
    """
    @spec verify_signature(binary(), AshHooks.Provider.verify_context(), binary(), keyword()) ::
            :ok | {:error, :invalid_signature | :no_webhook_secret}
    def verify_signature(body, context, reference, opts) do
      if not is_binary(reference) or reference == "" do
        {:error, :no_webhook_secret}
      else
        verify(body, context, reference, opts)
      end
    rescue
      _ -> {:error, :invalid_signature}
    catch
      _, _ -> {:error, :invalid_signature}
    end

    defp verify(body, context, reference, opts) do
      RequestSeal.Signing.options(opts, [:policy, :label])

      policy =
        case opts[:policy] do
          fun when is_function(fun, 2) -> fun.(context.tenant, reference)
          policy -> policy
        end

      with true <- is_map(context.headers),
           {:ok, message} <-
             RequestSeal.Message.request(
               context.method,
               context.request_uri,
               Map.to_list(context.headers),
               body
             ),
           {:ok, _} <- RequestSeal.verify(message, policy, label: opts[:label]) do
        :ok
      else
        _ -> {:error, :invalid_signature}
      end
    end
  end

  defmodule RequestSeal.AshHooks.Http do
    @moduledoc """
    ash_hooks HTTP adapter signing final method, URL, headers, and body bytes.

    Configure `http: RequestSeal.AshHooks.Http` and
    `http_opts: [request_seal: [spec: signing_spec, signer: custody_handle]]`;
    `request/5` lists every option. Each delivery attempt signs once with fresh
    metadata and hands the signed request to ash_hooks' bounded transport.
    ash_hooks continues to own SSRF resolve-and-pin, durable attempts, retries,
    secret references, rotation, and response classification.
    ash_hooks still requires its Standard Webhooks secret reference and emits
    those headers alongside RFC 9421 fields. Select the RFC label explicitly.
    Adapter options receive no endpoint or tenant identity; choose custody in
    static `http_opts` or its ash_hooks MFA resolver. No client or pool starts here.
    """
    @behaviour AshHooks.Http
    alias RequestSeal.{KeyHandle, Message, Signing}
    @required ["@method", "@authority", "@path", "content-digest", "content-type", "webhook-id"]
    @reserved [
      "host",
      "connection",
      "content-length",
      "transfer-encoding",
      "signature",
      "signature-input"
    ]
    @methods [:connect, :delete, :get, :head, :options, :patch, :post, :put, :trace]

    @doc """
    Signs a final webhook request and delegates it to ash_hooks' bounded transport.

    ash_hooks calls this as its `AshHooks.Http` adapter. Header names are
    lowercased, the request is signed with `RequestSeal.sign/4`, and the signed
    headers go to `AshHooks.Http.Bounded` with the remaining total
    timeout and otherwise unchanged transport options.

    ## Parameters

      * `method` - `:connect`, `:delete`, `:get`, `:head`, `:options`, `:patch`,
        `:post`, `:put`, `:trace`, or a binary method (uppercased).
      * `url` - the absolute target URL.
      * `headers` - a map of request headers. Names are lowercased; names that
        collide after lowercasing reject, as do `host`, `connection`,
        `content-length`, `transfer-encoding`, `signature`, and
        `signature-input`.
      * `body` - the exact body bytes, or nil.
      * `opts` - keyword list of the options below.

    ## Options

      * `:timeout` - total milliseconds for signing and transport, 1..300,000.
        Default 15,000.
      * `:request_seal` (required) - keyword list of these keys; others reject:
        * `:spec` (required) - a `t:RequestSeal.signing_spec/0`. `:digest`
          defaults to `["sha-256"]` and must not be nil. The components must
          include `"@method"`, `"@authority"`, `"@path"`, `"content-digest"`,
          `"content-type"`, and `"webhook-id"` without component parameters,
          plus `"@query"` when the URL has a query.
        * `:signer` (required) - a `RequestSeal.KeyHandle`; function signers
          reject.
        * `:clock` - arity-zero function returning Unix seconds.
        * `:signing_timeout` - milliseconds, default 5,000, capped at the time
          left before the total deadline.
      * any other option - passed unchanged to `AshHooks.Http.Bounded`, with
        `:timeout` replaced by the remaining time and `:request_seal` removed.

    Every attempt regenerates `created`, `expires`, and a random nonce. From 0.5.0,
    a nonce is required on every signed attempt: a spec with `nonce: nil` is
    refused as a signing failure before any request is sent.

    ## Returns

      * `{:ok, %{status: status, headers: headers, body: body}}` - the response
        from `AshHooks.Http.Bounded`.
      * `{:error, :timeout}` - `:timeout` is outside 1..300,000, or signing
        used up the whole deadline.
      * `{:error, {:terminal, :request_seal_signing_failed}}` - any signing
        failure: invalid `:request_seal` options or spec, missing coverage,
        a rejected header or method, or a `RequestSeal.sign/4` error. The
        terminal tag is for caller classification; ash_hooks 2.0 retries
        returned adapter errors other than `:unsafe_destination`.
      * `{:error, term}` - any other error returned by
        `AshHooks.Http.Bounded`, such as `:unsafe_destination`.
        Transport exceptions propagate unchanged.

    ## Examples

        iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        iex> spec = %{
        ...>   label: "sig",
        ...>   algorithm: "ed25519",
        ...>   components:
        ...>     ~s[("@method" "@authority" "@path" "content-digest" "content-type" "webhook-id")],
        ...>   expires_in: 300
        ...> }
        iex> url = "https://hooks.example.com/builds"
        iex> headers = %{"content-type" => "application/json", "webhook-id" => "msg-1"}
        iex> RequestSeal.AshHooks.Http.request(:post, url, headers, "{}", timeout: 0)
        {:error, :timeout}
        iex> RequestSeal.AshHooks.Http.request(:post, url <> "?page=2", headers, "{}",
        ...>   request_seal: [spec: spec, signer: handle]
        ...> )
        {:error, {:terminal, :request_seal_signing_failed}}
        iex> RequestSeal.AshHooks.Http.request(:post, url, Map.put(headers, "host", "other.example.com"), "{}",
        ...>   request_seal: [spec: spec, signer: handle]
        ...> )
        {:error, {:terminal, :request_seal_signing_failed}}
        iex> RequestSeal.Custody.Local.release(handle)
        :ok

    Fragment (requires an ash_hooks delivery resource with a PostgreSQL data layer and a reachable HTTPS receiver; not executed here):

        AshHooks.Delivery.run(%{"endpoint_id" => endpoint_id, "event_uuid" => event_id},
          deliveries: MyApp.Hooks.Delivery,
          endpoints: MyApp.Hooks.Endpoint,
          secret_resolver: secret_resolver,
          http: RequestSeal.AshHooks.Http,
          http_opts: [request_seal: [spec: spec, signer: handle]]
        )
    """
    @impl true
    @spec request(atom() | binary(), binary(), map(), binary() | nil, keyword()) ::
            {:ok, %{status: integer(), headers: list(), body: binary() | nil}} | {:error, term()}
    def request(method, url, headers, body, opts \\ []) do
      if Keyword.keyword?(opts) do
        timeout = Keyword.get(opts, :timeout, 15_000)

        if is_integer(timeout) and timeout in 1..300_000 do
          deadline = System.monotonic_time(:millisecond) + timeout

          with {:ok, signed} <- signed(method, url, headers, body, opts, deadline),
               {:ok, signed_headers} <- signed_headers(signed) do
            remaining = max(deadline - System.monotonic_time(:millisecond), 0)

            if remaining == 0 do
              {:error, :timeout}
            else
              transport =
                opts |> Keyword.delete(:request_seal) |> Keyword.put(:timeout, remaining)

              AshHooks.Http.Bounded.request(
                method,
                url,
                signed_headers,
                body,
                transport
              )
            end
          end
        else
          {:error, :timeout}
        end
      else
        # A malformed options container is bounded like every other signing-side
        # fault here, instead of raising out of the ash_hooks callback.
        {:error, {:terminal, :request_seal_signing_failed}}
      end
    end

    @doc false
    def signed_headers(%Message{fields: fields}) do
      names = Enum.map(fields, &String.downcase(&1.name))

      if length(names) == length(Enum.uniq(names)),
        do: {:ok, Map.new(fields, &{String.downcase(&1.name), &1.value})},
        else: {:error, {:terminal, :request_seal_signing_failed}}
    end

    defp signed(method, url, headers, body, opts, deadline) do
      signing = opts[:request_seal]
      Signing.options(signing, [:spec, :signer, :clock, :signing_timeout])

      Signing.ensure(
        not Keyword.has_key?(signing, :clock) or is_function(signing[:clock], 0),
        :invalid_options
      )

      Signing.ensure(match?(%KeyHandle{}, signing[:signer]), :invalid_options)
      spec = signing[:spec] |> Map.put_new(:digest, ["sha-256"]) |> Signing.normalize_spec!()
      input = Signing.spec!(spec)
      # A nonce is required on every signed attempt.
      Signing.ensure(spec.parameters.nonce == :random, :invalid_options)

      # @query preserves the core's query normalization while retaining the
      # existing method/authority/path contract, including percent-encoded bytes.
      required = if URI.parse(url).query == nil, do: @required, else: ["@query" | @required]

      Signing.ensure(
        spec.digest != nil and
          Enum.all?(required, fn name ->
            Enum.any?(input.value, &(&1.value == {:string, name} and &1.parameters == []))
          end),
        :invalid_options
      )

      Signing.ensure(is_map(headers), :invalid_request)
      fields = Enum.map(headers, fn {name, value} -> {String.downcase(name), value} end)
      names = Enum.map(fields, &elem(&1, 0))

      Signing.ensure(
        length(names) == length(Enum.uniq(names)) and not Enum.any?(names, &(&1 in @reserved)),
        :invalid_request
      )

      method =
        case method do
          m when m in @methods -> Atom.to_string(m) |> String.upcase()
          m when is_binary(m) -> String.upcase(m)
        end

      remaining = max(deadline - System.monotonic_time(:millisecond), 1)

      sign_opts =
        signing
        |> Keyword.take([:clock, :signing_timeout])
        |> Keyword.put(:signing_timeout, min(signing[:signing_timeout] || 5_000, remaining))

      with {:ok, message} <- Message.request(method, url, fields, body),
           {:ok, signed} <- RequestSeal.sign(message, spec, signing[:signer], sign_opts) do
        {:ok, signed}
      else
        _ -> {:error, {:terminal, :request_seal_signing_failed}}
      end
    rescue
      _ -> {:error, {:terminal, :request_seal_signing_failed}}
    catch
      _, _ -> {:error, {:terminal, :request_seal_signing_failed}}
    end
  end
end
