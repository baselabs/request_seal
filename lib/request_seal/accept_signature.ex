defmodule RequestSeal.AcceptSignature do
  @moduledoc """
  RFC 9421 Section 5 signature requests and nonce challenges.

  A requester serializes ordered requests with `serialize/1` into an
  `Accept-Signature` field. The other party parses them with `parse/2` for its
  own message kind and signs them with `fulfill/5`, whose chooser and signer
  own key selection and custody. Created/expires requests are bare true;
  nonce, keyid, tag, and alg are strings. Algorithms are exact HTTP registry
  tokens, never JWS selections. Unknown parameters reject. Components include
  their exact parameters; request targets cannot cover `@status` or related
  requests. Response targets require `req` for request-derived components.

  Passing requests as `accept_signature:` to `RequestSeal.verify_quorum/3`
  requires each exact label in the verified, selector-eligible pool after key-unit
  filtering, with the same covered component identity set and every requested
  parameter. The label need not be assigned to a counted slot; it appears in
  `qualifying` and `signatures` only when assigned. Extra metadata and separate
  signatures are allowed.
  A challenge match is established; replay storage and authorization are not.
  Limits: 16 requests, 65,536 wire bytes, and the signature-base component bounds.
  """
  alias RequestSeal.{Crypto, Error, Message, Policy, Quorum, SignatureFields}
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.StructuredFields.Value
  @parameters ~w(keyid alg created expires nonce tag)
  @request_derived ~w(@method @target-uri @authority @scheme @request-target @path @query @query-param)
  @type request :: %{
          label: binary(),
          components: Value.t(),
          parameters: %{optional(binary()) => true | binary()}
        }

  @doc """
  Parse ordered signature requests for an explicit target message kind.

  ## Parameters

    * `wire` - one `Accept-Signature` field value, or a list of at most 1,024
      ordered field occurrences (joined with `", "`). At most 65,536 bytes in
      total, at most 16 dictionary members.
    * `opts` - exactly `[target: :request]` or `[target: :response]`: the kind
      of message that will carry the requested signatures.

  ## Returns

    * `{:ok, [request]}` - `t:request/0` maps in wire order, each with
      `:label`, `:components` (a metadata-free Structured Fields Inner List),
      and `:parameters` (a map of `"created"`/`"expires"` to `true` and
      `"nonce"`, `"keyid"`, `"tag"`, `"alg"` to strings). An empty field
      value or list returns `{:ok, []}`.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return:
      `:invalid_options` and `:limit` (layer `:input`); `:duplicate_label` and
      `:duplicate_parameter` (layer `:fields`); `:invalid_accept_signature`
      and `:inapplicable_component` (layer `:negotiation`).
      Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {:ok, [request]} =
      ...>   RequestSeal.AcceptSignature.parse(
      ...>     ~s[reply=("@method" "@path" "content-digest");created;nonce="chat-7f3a";keyid="relay"],
      ...>     target: :request
      ...>   )
      iex> {request.label, request.parameters}
      {"reply", %{"created" => true, "keyid" => "relay", "nonce" => "chat-7f3a"}}
      iex> {:error, error} = RequestSeal.AcceptSignature.parse(~s[reply=("@status")], target: :request)
      iex> {error.reason, error.layer}
      {:inapplicable_component, :negotiation}
      iex> {:error, error} = RequestSeal.AcceptSignature.parse(~s[reply=("@method");alg="RS256"], target: :request)
      iex> error.reason
      :invalid_accept_signature
  """
  @spec parse(binary() | [binary()], keyword()) :: {:ok, [request()]} | {:error, Error.t()}
  def parse(wire, opts) do
    protect(fn ->
      ensure(
        match?([target: kind] when kind in [:request, :response], opts),
        :invalid_options,
        :input
      )

      fields = if is_binary(wire), do: [wire], else: wire

      ensure(
        Quorum.bounded_list?(fields, 0, 1024) and Enum.all?(fields, &is_binary/1),
        :invalid_accept_signature
      )

      size = Enum.reduce(fields, 0, &(byte_size(&1) + &2 + 2)) - if(fields == [], do: 0, else: 2)
      ensure(size <= 65_536, :limit, :input)

      parsed =
        case SF.parse_unique(Enum.join(fields, ", "), SignatureFields.schema(:dictionary),
               max_members: 16
             ) do
          {:ok, parsed} -> parsed
          {:error, %{reason: :duplicate_key}} -> fail(:duplicate_label, :fields)
          {:error, %{reason: :duplicate_parameter}} -> fail(:duplicate_parameter, :fields)
          {:error, %{reason: :limit}} -> fail(:limit, :input)
          _ -> fail(:invalid_accept_signature)
        end

      requests =
        Enum.map(parsed.value, fn {label, input} ->
          ensure(input.type == :inner_list, :invalid_accept_signature)

          %{
            label: label,
            components: %{input | parameters: []},
            parameters: SignatureFields.parameters(input)
          }
        end)

      validate!(requests, opts[:target])
      {:ok, requests}
    end)
  end

  @doc """
  Serialize ordered requests with deterministic signature metadata ordering.

  Requests keep their order; parameters are written in the order keyid, alg,
  created, expires, nonce, tag. No target applicability check is made.

  ## Parameters

    * `requests` - list of at most 16 `t:request/0` maps with unique labels,
      shaped as `parse/2` returns them.

  ## Returns

    * `{:ok, binary}` - the `Accept-Signature` field value.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return:
      `:invalid_accept_signature` (layer `:negotiation`), `:duplicate_label`
      (layer `:fields`), `:limit` (layer `:input`).
      Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {:ok, requests} =
      ...>   RequestSeal.AcceptSignature.parse(
      ...>     ~s[reply=("@method" "@path");nonce="chat-7f3a";created;keyid="relay"],
      ...>     target: :request
      ...>   )
      iex> RequestSeal.AcceptSignature.serialize(requests)
      {:ok, ~s[reply=("@method" "@path");keyid="relay";created;nonce="chat-7f3a"]}
      iex> {:error, error} = RequestSeal.AcceptSignature.serialize(requests ++ requests)
      iex> {error.reason, error.layer}
      {:duplicate_label, :fields}
  """
  @spec serialize([request()]) :: {:ok, binary()} | {:error, Error.t()}
  def serialize(requests) do
    protect(fn ->
      validate!(requests, nil)

      values =
        Enum.map(requests, fn r ->
          {r.label, %{r.components | parameters: parameter_values(r.parameters)}}
        end)

      case SF.serialize(
             %Value{type: :dictionary, value: values},
             SignatureFields.schema(:dictionary),
             max_members: 16
           ) do
        {:ok, bytes} -> {:ok, bytes}
        {:error, %{reason: :limit}} -> fail(:limit, :input)
        _ -> fail(:invalid_accept_signature)
      end
    end)
  end

  @doc """
  Fulfill requests in order through caller-owned key selection and signing.

  For each request the chooser returns the algorithm and times to use.
  A requested `alg` must equal the chosen algorithm; keyid, nonce, tag, and
  alg are copied verbatim. Requested `created` and `expires` take the
  chooser's values, which must then be integers; times that were not
  requested are not written. Signatures are appended in request order through
  the explicit form of `RequestSeal.sign/4`. Any failure returns an error and
  no partially signed message.

  ## Parameters

    * `message` - the valid `RequestSeal.Message` to sign; its kind is the
      target every request must apply to.
    * `requests` - list of at most 16 `t:request/0` maps with unique labels.
    * `chooser` - arity-one function receiving each request and returning
      `{:ok, %{algorithm: algorithm, created: integer_or_nil, expires: integer_or_nil}}`
      (an HTTP registry algorithm; times from -999,999,999,999,999 through
      999,999,999,999,999) or `:error`.
    * `signer` - arity-two function `(algorithm, base)` returning
      `{:ok, signature_bytes}` or `{:error, term}`.
    * `opts` - `[]` or `[field_schemas: schemas]`, passed to `RequestSeal.sign/4`.

  ## Returns

    * `{:ok, %RequestSeal.Message{}}` - the message with one `Signature-Input`
      and one `Signature` occurrence appended per request.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return:
      `:invalid_options` and `:invalid_message` (layer `:input`);
      `:duplicate_label` (layer `:fields`); `:invalid_accept_signature`,
      `:inapplicable_component`, and `:negotiation_unfulfillable` (layer
      `:negotiation`; unavailable component, incompatible chooser,
      unfulfillable parameter, callback fault, or signing failure). When an
      underlying signing step fails, its bounded reason appears in the error's
      `detail`. Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, message} =
      ...>   RequestSeal.Message.request("POST", "https://chat.example/rooms/7/messages", [], "hello")
      iex> {:ok, requests} =
      ...>   RequestSeal.AcceptSignature.parse(~s[reply=("@method" "@path");created;nonce="chat-7f3a"], target: :request)
      iex> chooser = fn _request -> {:ok, %{algorithm: "ed25519", created: 1_700_000_000, expires: nil}} end
      iex> signer = fn "ed25519", base -> RequestSeal.Custody.sign(handle, base) end
      iex> {:ok, signed} = RequestSeal.AcceptSignature.fulfill(message, requests, chooser, signer, [])
      iex> signed.fields |> hd() |> Map.fetch!(:value)
      ~s[reply=("@method" "@path");created=1700000000;nonce="chat-7f3a"]
      iex> {:error, error} = RequestSeal.AcceptSignature.fulfill(message, requests, fn _ -> :error end, signer, [])
      iex> {error.reason, error.layer}
      {:negotiation_unfulfillable, :negotiation}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec fulfill(
          Message.t(),
          [request()],
          (request() -> {:ok, map()} | :error),
          Policy.signer(),
          keyword()
        ) :: {:ok, Message.t()} | {:error, Error.t()}
  def fulfill(message, requests, chooser, signer, opts) do
    protect(fn ->
      ensure(
        Quorum.bounded_list?(opts, 0, 1) and Keyword.keyword?(opts) and
          Enum.all?(Keyword.keys(opts), &(&1 == :field_schemas)) and
          Policy.schemas?(Keyword.get(opts, :field_schemas, %{})) and is_function(chooser, 1) and
          is_function(signer, 2),
        :invalid_options,
        :input
      )

      ensure(Message.validate(message) == :ok, :invalid_message, :input)
      validate!(requests, message.kind)

      output =
        Enum.reduce(requests, message, fn request, current ->
          choice = callback(fn -> chooser.(request) end)
          ensure(choice?(choice), :negotiation_unfulfillable)
          {:ok, choice} = choice

          ensure(
            not Map.has_key?(request.parameters, "alg") or
              request.parameters["alg"] == choice.algorithm,
            :negotiation_unfulfillable
          )

          params =
            Enum.reduce(request.parameters, %{}, fn
              {name, true}, acc when name in ["created", "expires"] ->
                value = if name == "created", do: choice.created, else: choice.expires
                ensure(is_integer(value), :negotiation_unfulfillable)
                Map.put(acc, name, value)

              {name, value}, acc ->
                Map.put(acc, name, value)
            end)

          input = %{request.components | parameters: parameter_values(params)}

          case RequestSeal.sign(
                 current,
                 %{label: request.label, signature_input: input, algorithm: choice.algorithm},
                 signer,
                 opts
               ) do
            {:ok, signed} ->
              signed

            # The bounded signing reason rides along in detail; the public
            # reason stays :negotiation_unfulfillable.
            {:error, %RequestSeal.Error{reason: signing_reason}} ->
              fail(:negotiation_unfulfillable, :negotiation, signing_reason)

            _ ->
              fail(:negotiation_unfulfillable)
          end
        end)

      {:ok, output}
    end)
  end

  @doc false
  def validate_requests(requests, target),
    do:
      protect(fn ->
        validate!(requests, target)
        :ok
      end)

  defp validate!(requests, target) do
    ensure(Quorum.bounded_list?(requests, 0, 16), :invalid_accept_signature)

    Enum.each(requests, fn request ->
      ensure(request?(request), :invalid_accept_signature)
      ensure(target == nil or applicable?(request.components, target), :inapplicable_component)
    end)

    ensure(
      length(Enum.uniq_by(requests, & &1.label)) == length(requests),
      :duplicate_label,
      :fields
    )
  end

  defp request?(%{label: label, components: components, parameters: params} = r)
       when map_size(r) == 3 do
    SignatureFields.label?(label) and match?(%Value{type: :inner_list}, components) and
      is_map(params) and map_size(params) <= 6 and
      match?({:ok, _}, SignatureFields.inner(components)) and components.parameters == [] and
      Enum.all?(params, fn
        {name, true} when name in ["created", "expires"] -> true
        {"alg", value} -> value in Crypto.algorithms()
        {name, value} when name in ["nonce", "keyid", "tag"] -> string?(value)
        _ -> false
      end)
  end

  defp request?(_), do: false

  defp string?(value) do
    is_binary(value) and
      match?(
        {:ok, _},
        SF.serialize(%Value{type: :item, value: {:string, value}}, SignatureFields.schema(:item))
      )
  end

  defp applicable?(components, target) do
    Enum.all?(components.value, fn %Value{value: {:string, name}, parameters: params} ->
      req = List.keymember?(params, "req", 0)

      case target do
        :request -> name != "@status" and not req
        :response -> (name != "@status" or not req) and (name not in @request_derived or req)
      end
    end)
  end

  defp parameter_values(params) do
    for name <- @parameters, Map.has_key?(params, name) do
      value = params[name]

      type =
        cond do
          value == true -> :boolean
          is_integer(value) -> :integer
          true -> :string
        end

      {name, {type, value}}
    end
  end

  defp choice?({:ok, %{algorithm: alg, created: created, expires: expires} = choice}) do
    map_size(choice) == 3 and alg in Crypto.algorithms() and time?(created) and time?(expires)
  end

  defp choice?(_), do: false
  defp time?(nil), do: true
  defp time?(t), do: is_integer(t) and t in -999_999_999_999_999..999_999_999_999_999

  defp callback(fun) do
    fun.()
  rescue
    _ -> fail(:negotiation_unfulfillable)
  catch
    _, _ -> fail(:negotiation_unfulfillable)
  end

  defp ensure(value, reason, layer \\ :negotiation)
  defp ensure(true, _, _), do: :ok
  defp ensure(_, reason, layer), do: fail(reason, layer)

  @spec fail(term()) :: no_return()
  @spec fail(term(), atom()) :: no_return()
  @spec fail(term(), atom(), atom() | nil) :: no_return()
  defp fail(reason, layer \\ :negotiation, detail \\ nil),
    do: throw({:negotiation_error, Error.new(reason, layer, detail)})

  defp protect(fun) do
    fun.()
  catch
    {:negotiation_error, error} -> {:error, error}
  end
end
