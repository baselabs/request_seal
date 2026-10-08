defmodule RequestSeal.AcceptSignature do
  @moduledoc """
  RFC 9421 Section 5 signature requests and nonce challenges.

  `parse/2` accepts one field value or ordered field occurrences, with explicit
  `target: :request | :response`. It returns ordered requests, each a map with
  `:label`, `:components` (a metadata-free Structured Fields Inner List), and
  `:parameters` (a map). Created/expires requests must be bare true; nonce,
  keyid, tag, and alg must be strings. Algorithms are exact HTTP registry tokens,
  never JWS selections. Unknown parameters reject. Components include their
  exact parameters; request targets cannot cover @status or related requests.
  Response targets require `req` for request-derived components.

  `serialize/1` writes a deterministic dictionary. `fulfill/5` validates the
  target and asks an arity-one chooser for `{:ok, %{algorithm: algorithm,
  created: integer_or_nil, expires: integer_or_nil}}` or `:error`. Requested alg
  must agree; keyid, nonce, and tag are copied verbatim. Requested times come
  from the chooser. Signatures are appended in request order via
  `RequestSeal.sign/4` and its caller signer; options are its `:field_schemas`.
  The chooser and signer own custody. Unavailable components or choices reject
  with `:negotiation_unfulfillable`, without a partial message.

  Passing requests as `accept_signature:` to `RequestSeal.verify_quorum/3`
  requires each exact label to qualify, the same covered identity set, and every
  requested parameter. Extra metadata and separate signatures are allowed.
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

  @doc "Parse ordered signature requests for an explicit target message kind."
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

  @doc "Serialize ordered requests with deterministic signature metadata ordering."
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

  @doc "Fulfill requests in order through caller-owned key selection and signing."
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
            {:ok, signed} -> signed
            _ -> fail(:negotiation_unfulfillable)
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

  defp fail(reason, layer \\ :negotiation),
    do: throw({:negotiation_error, Error.new(reason, layer)})

  defp protect(fun) do
    fun.()
  catch
    {:negotiation_error, error} -> {:error, error}
  end
end
