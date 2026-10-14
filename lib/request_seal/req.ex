if Code.ensure_loaded?(Req) do
  defmodule RequestSeal.Req.State do
    @moduledoc false
    @derive {Inspect, only: [:attempt]}
    defstruct [
      :options,
      :origin,
      :sent,
      :into,
      :digest,
      :delivery_error,
      attempt: 0,
      appended: [],
      chunks: [],
      bytes: 0
    ]
  end

  defmodule RequestSeal.Req do
    @moduledoc """
    Optional Req final-attempt signing and verification before body decoding.

    `attach/2` adds a signing step that runs last on every attempt and, unless
    `verify: :none`, a verification step that runs first on every response.
    Every attempt removes only this adapter's previously appended values, then
    regenerates parameters. Req's own redirect/retry choices still govern whether
    another attempt runs. Signing must remain the last request step; a later step
    rejects before transport. Only Req's Finch adapter is supported; framework
    hooks that can mutate transport bytes after signing reject. No pool, server,
    or background fetch starts.

    When required, verification is the first response step, before retry, HTTP errors,
    redirect, digest auth, decompression, or decoding. Each intermediate response
    must satisfy the selected policy: unsigned 3xx/5xx responses fail closed
    without redirecting or retrying. It uses the exact sent Message once per
    response. A rejection returns a bounded `RequestSeal.Adapter.Error` with
    `:response_rejected`, never a response body.

    All verified delivery, including synchronous responses, uses a collector with
    explicit `max_stream_bytes`: overflow stops transport before complete
    buffering with `:limit`. Chunks are buffered within that bound and hashed when
    policy requires content integrity; automatic streams refuse caller-selected
    representation hashing. The original destination receives chunks only after
    verification. Collectables are opened only after success. Req cache handling,
    `http_errors: :raise`, checksum wrappers on streaming destinations, and custom
    response steps before verification are refused under verification, since
    these can consume or expose unverified bodies.
    """
    alias RequestSeal.{Digest, Policy, SignatureFields, Verification}
    alias RequestSeal.Adapter.{Error, Signing}
    alias RequestSeal.Req.State

    @keys [
      :sign,
      :signer,
      :signing_timeout,
      :clock,
      :redirect,
      :request_body,
      :verify,
      :credential_headers
    ]
    @req_options [
      :user_agent,
      :compressed,
      :range,
      :base_url,
      :params,
      :path_params,
      :path_params_style,
      :auth,
      :form,
      :form_multipart,
      :json,
      :compress_body,
      :checksum,
      :raw,
      :http_errors,
      :decode_body,
      :decoders,
      :decode_json,
      :redirect,
      :redirect_trusted,
      :redirect_log_level,
      :max_redirects,
      :retry,
      :retry_delay,
      :retry_log_level,
      :max_retries,
      :cache,
      :cache_dir,
      :finch,
      :request_timeout,
      :receive_timeout,
      :pool_timeout,
      :follow_redirects,
      :location_trusted,
      :redact_auth
    ]

    @doc """
    Attaches final-attempt signing and optional response verification to a Req request.

    The returned request carries three added steps: an option check prepended
    to the request steps, a signing step appended as the last request step, and
    a response step. With a verification map the response step runs first;
    with `verify: :none` it runs just before Req's `:decompress_body` step and
    makes no verification claim. Nothing is sent and no process starts. Run the
    request with `Req.request/1` against a caller-started Finch pool.

    ## Parameters

      * `request` - a `Req.Request` built by `Req.new/1` that still has Req's
        `:decompress_body` response step and Req's Finch adapter. URL, method,
        headers, body, and `into` are Req struct fields. The request options
        may include only `user_agent`, `compressed`, `range`, `base_url`,
        `params`, `path_params`, `path_params_style`, `auth` (except digest),
        `form`, `form_multipart`, `json`, `compress_body`, `checksum`, `raw`,
        `http_errors`, `decode_body`, `decoders`, `decode_json`, `redirect`,
        `redirect_trusted`, `redirect_log_level`, `max_redirects`, `retry`,
        `retry_delay`, `retry_log_level`, `max_retries`, `cache`, `cache_dir`,
        `finch`, `request_timeout`, `receive_timeout`, `pool_timeout`,
        `follow_redirects`, `location_trusted`, and `redact_auth`. These are
        checked at attachment, before the request steps, and at final signing.
        `finch` accepts only an explicit caller-owned atom `name` and optional
        `pool_timeout`, `receive_timeout`, and `request_timeout`; configure
        trusted pool connections when starting the caller-owned pool.
        Caller-supplied Host, connection overrides, proxies, UNIX sockets, Finch
        private metadata and pool options, IPv6 overrides, and Req's
        `aws_sigv4` option reject with `:invalid_options`. `into: :self` and
        `into: :legacy_self` reject.
      * `opts` - keyword list of the options below. Unknown or duplicate
        options reject.

    ## Options

      * `:sign` (required) - the signing specification described in
        `RequestSeal.Finch.sign/4`.
      * `:signer` (required) - a `RequestSeal.KeyHandle` or an arity-two
        function signer, as in `RequestSeal.Finch.sign/4`.
      * `:verify` (required) - `:none`, or a map with exactly `:policy` (a valid
        `RequestSeal.Policy`), `:label` (the response signature label), and
        `:max_stream_bytes` (a nonnegative integer bound on buffered response
        bytes; any other value, including nil, rejects with `:invalid_options`). With a map, the request
        must keep `http_errors: :return` (the default), must not set
        `cache: true`, and must not have a response step ahead of
        verification. A non-nil `into` destination must be a two-arity
        function or a `Collectable`, must not be combined with Req's
        `checksum`, and requires a policy whose content is `:not_required` or
        of kind `:content`. With `:none`, ordinary synchronous delivery keeps
        Req's semantics.
      * `:signing_timeout` - 1..300,000 ms. Default 5,000.
      * `:clock` - arity-zero function returning Unix seconds. Default system
        seconds.
      * `:request_body` - `:as_is` (default) or `{:retain, max}` with a
        nonnegative integer `max`. Retention reads a Req function body or an
        enumerable stream once under `max` bytes and replaces it with
        replayable bytes before transport. With `:as_is` an enumerable stream
        is sent unread with its bytes unavailable for coverage, and a Req
        function body rejects at signing with `:body_unavailable`.
      * `:redirect` - `:same_origin` (default) rejects any attempt whose origin
        differs from the first attempt's. `{:allow, origins}` permits up to 64
        listed origins, each an `http` or `https` URL with a host and no path,
        query, fragment, or userinfo, at most 2,048 bytes. An origin is scheme,
        lowercased host, and port. Allowed cross-origin attempts strip
        `authorization`, `cookie`, `proxy-authorization`, and
        `:credential_headers`, even with Req's `redirect_trusted`.
      * `:credential_headers` - at most 64 HTTP header names of 1..256 token
        bytes, matched case insensitively, stripped on allowed cross-origin
        attempts. Default `[]`.

    ## Returns

      * `{:ok, %Req.Request{}}` - the request with RequestSeal steps attached.
      * `{:error, %RequestSeal.Adapter.Error{stage: :attach, attempt: 0}}` -
        reasons: `:invalid_options` (option, spec, signer, Req option, or
        Host value; a request already attached; or an unexpected exception),
        `:invalid_request` (not a `Req.Request`), `:unsupported_component`
        (`host`, `tr`, or `req` components in the spec, or a streaming
        destination with representation hashing), `:unsupported_delivery`
        (adapter, `into`, verification delivery restrictions, or a missing
        `:decompress_body` step), and `:limit` (component list bound).
        Meanings: `RequestSeal.Adapter.Error`.

    `Req.request/1` on the attached request returns
    `{:error, %RequestSeal.Adapter.Error{}}` with `attempt` set to the final
    signing attempt (starting at 1). At stage `:sign`: `:not_final_step`,
    `:cross_origin_redirect`, `:invalid_options`, `:invalid_request`,
    `:unsupported_component`, `:unsupported_delivery`, `:body_unavailable`,
    `:digest_conflict`, `:limit`, and `:signing_failed`, with the meanings of
    `RequestSeal.Finch.sign/4` and the checks above. At stage `:verify`:
    `:limit` (more than `max_stream_bytes`), `:invalid_request` (a response
    `RequestSeal.Message.new/1` rejects), and `:response_rejected` (the core
    verifier rejected, with its bounded `source`, or an unexpected exception).

    ## Examples

        iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        iex> spec = %{
        ...>   label: "sig",
        ...>   algorithm: "ed25519",
        ...>   components: ~s[("@method" "@authority" "@path")],
        ...>   expires_in: 60
        ...> }
        iex> request =
        ...>   Req.new(url: "https://crawler.example.com/pages", finch: [name: Example.Finch], retry: false)
        iex> {:ok, attached} = RequestSeal.Req.attach(request, sign: spec, signer: handle, verify: :none)
        iex> {attached.request_steps |> List.first() |> elem(0), attached.request_steps |> List.last() |> elem(0)}
        {:request_seal_options, :request_seal_sign}
        iex> {:error, error} = RequestSeal.Req.attach(attached, sign: spec, signer: handle, verify: :none)
        iex> {error.reason, error.stage, error.attempt}
        {:invalid_options, :attach, 0}
        iex> {:error, error} =
        ...>   RequestSeal.Req.attach(%{request | into: :self}, sign: spec, signer: handle, verify: :none)
        iex> error.reason
        :unsupported_delivery
        iex> RequestSeal.Custody.Local.release(handle)
        :ok

    Fragment (requires a running Finch pool and an HTTPS peer that signs its responses; not executed here):

        {:ok, _pid} = Finch.start_link(name: Example.Finch)

        request =
          Req.new(
            method: :post,
            url: "https://telemetry.example.com/ingest",
            body: ~s({"cpu":0.42}),
            finch: [name: Example.Finch]
          )

        {:ok, request} =
          RequestSeal.Req.attach(request,
            sign: spec,
            signer: handle,
            verify: %{policy: response_policy, label: "res", max_stream_bytes: 1_048_576}
          )

        {:ok, response} = Req.request(request)
        {:ok, verification} = RequestSeal.Req.verification(response)
    """
    @spec attach(Req.Request.t(), keyword()) :: {:ok, Req.Request.t()} | {:error, Error.t()}
    def attach(request, opts) do
      Signing.protect(:req, :attach, 0, fn ->
        Signing.options(opts, @keys)
        Signing.ensure(match?(%Req.Request{}, request), :invalid_request)

        opts = Keyword.put(opts, :sign, Signing.normalize_spec!(opts[:sign]))
        Signing.spec!(opts[:sign])
        Signing.sign_options!(sign_options(opts))

        Signing.ensure(
          is_function(opts[:signer], 2) or match?(%RequestSeal.KeyHandle{}, opts[:signer]),
          :invalid_options
        )

        credential_headers!(Keyword.get(opts, :credential_headers, []))
        validate_verify(opts[:verify])
        validate_redirect(Keyword.get(opts, :redirect, :same_origin))
        Signing.ensure(not Map.has_key?(request.private, :request_seal), :invalid_options)
        delivery!(request, opts)

        Signing.ensure(
          Enum.any?(request.response_steps, fn {name, _} -> name == :decompress_body end),
          :unsupported_delivery
        )

        state = %State{options: opts, into: request.into}
        request = Req.Request.put_private(request, :request_seal, state)
        request = Req.Request.append_request_steps(request, request_seal_sign: &sign_attempt/1)

        request =
          Req.Request.prepend_request_steps(request,
            request_seal_options: &validate_attempt/1
          )

        response_steps =
          if opts[:verify] == :none do
            {before, after_steps} =
              Enum.split_while(
                request.response_steps,
                fn {name, _} -> name != :decompress_body end
              )

            before ++ [request_seal_verify: &verify_response/1] ++ after_steps
          else
            [request_seal_verify: &verify_response/1] ++ request.response_steps
          end

        {:ok, %{request | response_steps: response_steps}}
      end)
    end

    @doc """
    Returns the verification stored in a response's private metadata by an attached request.

    Only a response that passed the verification step of `attach/2` carries a
    result. A rejected response is never returned by `Req.request/1`, so it has
    no partial facts to read.

    ## Parameters

      * `response` - a `Req.Response`, usually from `Req.request/1` on a request
        attached with a verification map.

    ## Returns

      * `{:ok, %RequestSeal.Verification{}}` - the stored verified facts.
      * `:error` - no verification is stored: any other response, including
        responses from requests attached with `verify: :none`, or a value
        that is not a `Req.Response`.

    ## Examples

        iex> RequestSeal.Req.verification(Req.Response.new(status: 200))
        :error

    Fragment (requires a running Finch pool and an HTTPS peer that signs its responses; not executed here):

        {:ok, response} = Req.request(attached_request)
        {:ok, verification} = RequestSeal.Req.verification(response)
        verification.label
        #=> "res"
    """
    @spec verification(Req.Response.t()) :: {:ok, Verification.t()} | :error
    def verification(%Req.Response{private: %{request_seal: %Verification{} = value}}),
      do: {:ok, value}

    def verification(_), do: :error

    defp validate_verify(:none), do: :ok

    defp validate_verify(%{policy: policy, label: label, max_stream_bytes: max} = v) do
      Signing.ensure(
        map_size(v) == 3 and Policy.valid?(policy) and SignatureFields.label?(label) and
          is_integer(max) and max >= 0,
        :invalid_options
      )
    end

    defp validate_verify(_), do: Signing.fail(:invalid_options)

    defp validate_redirect(:same_origin), do: :ok

    defp validate_redirect({:allow, origins}) do
      Signing.ensure(is_list(origins) and length(origins) <= 64, :invalid_options)
      Enum.each(origins, fn origin -> origin!(origin) end)
    end

    defp validate_redirect(_), do: Signing.fail(:invalid_options)

    defp origin!(origin) do
      Signing.ensure(is_binary(origin) and byte_size(origin) <= 2048, :invalid_options)
      uri = URI.parse(origin)

      Signing.ensure(
        uri.scheme in ["http", "https"] and is_binary(uri.host) and uri.host != "" and
          uri.path in [nil, ""] and uri.query == nil and uri.fragment == nil and
          uri.userinfo == nil and
          is_integer(uri.port) and uri.port in 1..65535,
        :invalid_options
      )

      {uri.scheme, String.downcase(uri.host), uri.port}
    end

    defp credential_headers!(headers) do
      Signing.ensure(is_list(headers) and length(headers) <= 64, :invalid_options)

      Enum.each(headers, fn name ->
        Signing.ensure(
          is_binary(name) and byte_size(name) in 1..256 and
            Regex.match?(~r/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/, name),
          :invalid_options
        )
      end)

      Enum.map(headers, &String.downcase/1)
    end

    defp transport_options!(r) do
      Signing.ensure(Enum.all?(Map.keys(r.options), &(&1 in @req_options)), :invalid_options)
      Signing.ensure(not match?({:digest, _}, r.options[:auth]), :invalid_options)

      case r.options[:finch] do
        nil ->
          :ok

        options when is_list(options) ->
          Signing.options(options, [:name, :pool_timeout, :receive_timeout, :request_timeout])
          Signing.ensure(is_atom(options[:name]) and options[:name] != nil, :invalid_options)

        _ ->
          Signing.fail(:invalid_options)
      end

      # Mint supplies Host from the URL; a caller-supplied Host would override it.
      Signing.ensure(Req.Request.get_header(r, "host") == [], :invalid_options)
    end

    @doc false
    def validate_attempt(request) do
      state = request.private.request_seal

      case Signing.protect(:req, :sign, state.attempt + 1, fn ->
             transport_options!(request)
             # A failed stream returns the internal collector. Restore the caller's
             # destination before Req re-applies checksum and other request steps.
             request =
               if request.into == (&buffer_chunk/2),
                 do: %{request | into: state.into},
                 else: request

             {:ok, request}
           end) do
        {:ok, r} -> r
        {:error, error} -> Req.Request.halt(request, error)
      end
    end

    defp delivery!(r, opts) do
      Signing.ensure(r.into not in [:self, :legacy_self], :unsupported_delivery)

      Signing.ensure(
        r.adapter == Req.Finch or r.adapter == (&Req.Finch.run/1),
        :unsupported_delivery
      )

      transport_options!(r)

      if opts[:verify] != :none do
        Signing.ensure(
          Map.get(r.options, :http_errors, :return) == :return and r.options[:cache] != true and
            safe_response_prelude?(r) and opts[:verify].max_stream_bytes != nil,
          :unsupported_delivery
        )
      end

      into = if r.into == (&buffer_chunk/2), do: r.private.request_seal.into, else: r.into

      if into != nil and opts[:verify] != :none do
        Signing.ensure(
          opts[:verify].policy.content == :not_required or
            opts[:verify].policy.content.kind == :content,
          :unsupported_component
        )

        Signing.ensure(
          opts[:verify].max_stream_bytes != nil and not Map.has_key?(r.options, :checksum),
          :unsupported_delivery
        )

        Signing.ensure(
          is_function(into, 2) or Collectable.impl_for(into) != nil,
          :unsupported_delivery
        )
      end
    end

    defp sign_options(opts),
      do:
        Keyword.take(opts, [:signing_timeout, :clock]) ++
          [body: Keyword.get(opts, :request_body, :as_is)]

    @doc false
    def sign_attempt(request) do
      state = request.private.request_seal
      attempt = state.attempt + 1

      result =
        Signing.protect(:req, :sign, attempt, fn ->
          Signing.ensure(
            List.last(request.request_steps) == {:request_seal_sign, &sign_attempt/1},
            :not_final_step
          )

          Signing.ensure(ordered_verify?(request), :unsupported_delivery)
          delivery!(request, state.options)
          request = retain_function(request, Keyword.get(state.options, :request_body, :as_is))
          delivery!(request, state.options)

          state = %{
            state
            | into: if(request.into == (&buffer_chunk/2), do: state.into, else: request.into)
          }

          request = remove_appended(request, state.appended)
          finch = build(request)
          origin = {Atom.to_string(finch.scheme), String.downcase(finch.host), finch.port}

          request =
            if state.origin != nil and state.origin != origin do
              allowed =
                case Keyword.get(state.options, :redirect, :same_origin) do
                  :same_origin -> false
                  {:allow, origins} -> origin in Enum.map(origins, &origin!/1)
                end

              Signing.ensure(allowed, :cross_origin_redirect)

              headers =
                ["authorization", "cookie", "proxy-authorization"] ++
                  credential_headers!(Keyword.get(state.options, :credential_headers, []))

              Enum.reduce(headers, request, &Req.Request.delete_header(&2, &1))
            else
              request
            end

          finch = %{finch | headers: Req.Fields.get_list(request.headers)}

          {finch, message} =
            RequestSeal.Finch.prepare(finch, Keyword.get(state.options, :request_body, :as_is))

          signed =
            Signing.sign(
              message,
              state.options[:sign],
              state.options[:signer],
              sign_options(state.options)
            )

          appended =
            Enum.drop(signed.fields, length(message.fields))
            |> Enum.map(&{String.downcase(&1.name), &1.value})

          headers = Req.Fields.new(Enum.map(signed.fields, &{&1.name, &1.value}))

          state = %{
            state
            | attempt: attempt,
              origin: state.origin || origin,
              sent: signed,
              appended: appended,
              chunks: [],
              bytes: 0,
              digest: nil,
              delivery_error: nil
          }

          request = %{
            request
            | headers: headers,
              body: finch.body,
              private: Map.put(request.private, :request_seal, state)
          }

          request = buffer_delivery(request)
          {:ok, request}
        end)

      case result do
        {:ok, request} -> request
        {:error, error} -> Req.Request.halt(request, error)
      end
    end

    defp ordered_verify?(request) do
      step = {:request_seal_verify, &verify_response/1}

      if request.private.request_seal.options[:verify] == :none do
        index =
          Enum.find_index(request.response_steps, fn {name, _} -> name == :decompress_body end)

        is_integer(index) and index > 0 and Enum.at(request.response_steps, index - 1) == step
      else
        List.first(request.response_steps) == step
      end
    end

    defp safe_response_prelude?(request) do
      # During attachment there is no verification step yet. Once attached,
      # no response hook may move ahead of verification.
      not Enum.any?(request.response_steps, fn {name, _} -> name == :request_seal_verify end) or
        ordered_verify?(request)
    end

    defp build(request) do
      body =
        case request.body do
          nil -> nil
          b when is_binary(b) or is_list(b) -> b
          b when is_function(b, 1) -> Signing.fail(:body_unavailable)
          enumerable -> {:stream, enumerable}
        end

      Finch.build(request.method, request.url, Req.Fields.get_list(request.headers), body)
    rescue
      _ -> Signing.fail(:invalid_request)
    end

    defp retain_function(%{body: fun} = request, {:retain, max}) when is_function(fun, 1) do
      retain_function(request, fun, max, [], 0)
    end

    defp retain_function(request, _), do: request

    defp retain_function(request, fun, max, chunks, bytes) do
      case fun.(request) do
        {:data, chunk, %Req.Request{} = request} ->
          bytes = bytes + IO.iodata_length(chunk)
          Signing.ensure(bytes <= max, :limit)
          retain_function(request, fun, max, [chunk | chunks], bytes)

        {:done, %Req.Request{} = request} ->
          %{request | body: chunks |> Enum.reverse() |> IO.iodata_to_binary()}

        {:halt, %Req.Request{}} ->
          Signing.fail(:body_unavailable)

        _ ->
          Signing.fail(:invalid_request)
      end
    end

    defp remove_appended(request, appended) do
      Enum.reduce(appended, request, fn {name, value}, r ->
        values = Req.Request.get_header(r, name)
        # Remove exactly one matching occurrence, preserving caller occurrences.
        values = List.delete(values, value)

        if values == [],
          do: Req.Request.delete_header(r, name),
          else: %{r | headers: Map.put(r.headers, name, values)}
      end)
    end

    defp buffer_delivery(%{private: %{request_seal: %{options: opts}}} = r) do
      if opts[:verify] == :none do
        r
      else
        content = opts[:verify].policy.content

        digest =
          if is_map(content) and r.private.request_seal.into != nil do
            {:ok, d} =
              Digest.init(content.kind, content.algorithms,
                max_bytes: opts[:verify].max_stream_bytes
              )

            d
          end

        r = put_in(r.private.request_seal.digest, digest)
        %{r | into: &buffer_chunk/2}
      end
    end

    defp buffer_chunk({:data, chunk}, {request, response}) do
      state = request.private.request_seal

      result =
        Signing.protect(:req, :verify, state.attempt, fn ->
          bytes = state.bytes + byte_size(chunk)
          Signing.ensure(bytes <= state.options[:verify].max_stream_bytes, :limit)

          digest =
            if state.digest do
              case Digest.update(state.digest, chunk) do
                {:ok, value} -> value
                _ -> Signing.fail(:limit)
              end
            end

          {:ok, %{state | bytes: bytes, chunks: [chunk | state.chunks], digest: digest}}
        end)

      case result do
        {:ok, state} ->
          {:cont,
           {%{request | private: Map.put(request.private, :request_seal, state)}, response}}

        {:error, error} ->
          state = %{state | chunks: [], digest: nil, delivery_error: error}

          {:halt,
           {%{request | private: Map.put(request.private, :request_seal, state)}, response}}
      end
    end

    @doc false
    def verify_response({request, response}) do
      state = request.private.request_seal

      cond do
        state.delivery_error != nil ->
          Req.Request.halt(request, state.delivery_error)

        state.options[:verify] == :none or
            Map.get(response.private, :request_seal_verified, false) ->
          {request, response}

        true ->
          result =
            Signing.protect(:req, :verify, state.attempt, fn ->
              chunks = Enum.reverse(state.chunks)
              body = IO.iodata_to_binary(chunks)

              finch = %Finch.Response{
                status: response.status,
                headers: Req.Fields.get_list(response.headers),
                trailers: Req.Fields.get_list(response.trailers),
                body: body
              }

              disposition = if state.digest, do: :consumed, else: :retained
              message = RequestSeal.Finch.response_value(finch, state.sent, disposition)
              opts = [label: state.options[:verify].label]
              opts = if state.digest, do: opts ++ [digest_state: state.digest], else: opts

              {:ok, verified} =
                RequestSeal.Finch.verify_value(message, state.options[:verify].policy, opts)

              response = %{
                response
                | body: body,
                  private:
                    Map.merge(response.private, %{
                      request_seal: verified,
                      request_seal_verified: true
                    })
              }

              {request, response} = deliver(request, response, chunks)
              request = %{request | into: state.into}
              request = put_in(request.private.request_seal.chunks, [])
              request = put_in(request.private.request_seal.digest, nil)
              {:ok, {request, response}}
            end)

          case result do
            {:ok, pair} -> pair
            {:error, error} -> Req.Request.halt(request, error)
          end
      end
    end

    defp deliver(%{private: %{request_seal: %{into: nil}}} = r, s, _), do: {r, s}

    defp deliver(%{private: %{request_seal: %{into: fun}}} = r, s, chunks)
         when is_function(fun, 2) do
      Enum.reduce_while(chunks, {r, %{s | body: ""}}, fn chunk, pair ->
        case fun.({:data, chunk}, pair) do
          {:cont, pair} -> {:cont, pair}
          {:halt, pair} -> {:halt, pair}
        end
      end)
    end

    defp deliver(%{private: %{request_seal: %{into: collectable}}} = r, s, chunks) do
      {acc, collector} = Collectable.into(collectable)

      try do
        acc = Enum.reduce(chunks, acc, &collector.(&2, {:cont, &1}))
        {r, %{s | body: collector.(acc, :done)}}
      catch
        kind, reason ->
          collector.(acc, :halt)
          :erlang.raise(kind, reason, __STACKTRACE__)
      end
    end
  end
end
