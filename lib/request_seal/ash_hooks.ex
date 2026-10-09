if Code.ensure_loaded?(AshHooks.Provider) do
  defmodule RequestSeal.AshHooks do
    @moduledoc """
    Optional ash_hooks inbound RFC 9421 verification bridge (Elixir 1.20).

    A consumer's `c:AshHooks.Provider.verify_signature/3` delegates to
    `verify_signature/4` with an explicit policy and label. `:policy` is a
    `RequestSeal.Policy` or an arity-two function resolving a policy from the
    provider context's tenant and nonempty binary secret/key reference.
    RequestSeal never interprets
    that reference as key material or authorizes an application action.

    The provider context must supply method, absolute request URI, and a headers
    map. This map has already lost duplicate lines and ordering; the helper
    cannot recover them and returns only the provider's `:ok`/error contract.
    Prefer `RequestSeal.Plug.Capture` and `RequestSeal.Plug.Verify` before
    ash_hooks ingress to retain ordered headers, exact body bytes, and facts.
    The RequestSeal reader replays unchanged bytes to `AshHooks.BodyReader`.
    Provider errors never expose key references, body bytes, or callback errors.
    """
    @doc "Verify a provider's exact body under an explicit policy and signature label."
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
    `http_opts: [request_seal: [spec: signing_spec, signer: custody_handle]]`.
    Optional signing options are `:clock` (a zero-arity function) and
    `:signing_timeout`. Nonces are freshly generated for every attempt.
    The spec must cover `@method`, `@authority`, `@path`, `content-digest`,
    `content-type`, and `webhook-id` without component parameters. The digest
    defaults to SHA-256. URLs with a query must also cover `@query`.
    Incoming signature fields and transport-owned headers
    reject; case-colliding headers reject before conversion to the transport map.

    Delegates one signed request to `AshHooks.Http.Bounded` with the remaining
    total timeout and unchanged transport options. ash_hooks continues to own
    SSRF resolve-and-pin, durable attempts, retries, secret references, rotation,
    and response classification. Signing failures return
    `{:error, {:terminal, :request_seal_signing_failed}}`; transport exceptions
    propagate unchanged. The terminal tag is for caller classification;
    ash_hooks 2.0 retries returned adapter errors other than `:unsafe_destination`.
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

    @doc "Sign a final webhook request and delegate it to ash_hooks' bounded transport."
    @impl true
    @spec request(atom() | binary(), binary(), map(), binary() | nil, keyword()) ::
            {:ok, %{status: integer(), headers: list(), body: binary() | nil}} | {:error, term()}
    def request(method, url, headers, body, opts \\ []) do
      timeout = Keyword.get(opts, :timeout, 15_000)

      if is_integer(timeout) and timeout in 1..300_000 do
        deadline = System.monotonic_time(:millisecond) + timeout

        with {:ok, signed} <- signed(method, url, headers, body, opts, deadline),
             {:ok, signed_headers} <- signed_headers(signed) do
          remaining = max(deadline - System.monotonic_time(:millisecond), 0)

          if remaining == 0 do
            {:error, :timeout}
          else
            transport = opts |> Keyword.delete(:request_seal) |> Keyword.put(:timeout, remaining)

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
