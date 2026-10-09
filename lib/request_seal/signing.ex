defmodule RequestSeal.Signing do
  @moduledoc false
  alias RequestSeal.{Body, Custody, Digest, KeyHandle, Policy, SignatureBase, SignatureFields}
  alias RequestSeal.Adapter.Error

  @type spec :: RequestSeal.signing_spec() | full_spec()
  @type full_spec :: %{
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

  def protect(adapter, stage, attempt, fun) do
    fun.()
  rescue
    _ -> {:error, Error.new(fault(stage), adapter, stage, attempt)}
  catch
    {:adapter, reason, source} -> {:error, Error.new(reason, adapter, stage, attempt, source)}
    _, _ -> {:error, Error.new(fault(stage), adapter, stage, attempt)}
  end

  defp fault(:capture), do: :invalid_request
  defp fault(:attach), do: :invalid_options
  defp fault(:sign), do: :signing_failed
  defp fault(:verify), do: :response_rejected
  def ensure(true, _), do: :ok
  def ensure(_, reason), do: fail(reason)
  def fail(reason, source \\ nil), do: throw({:adapter, reason, source})

  def options(opts, allowed) do
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_options)
    keys = Keyword.keys(opts)

    ensure(
      length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in allowed)),
      :invalid_options
    )

    opts
  end

  def spec!(s, opts \\ []) do
    options(opts, [:related])
    related = Keyword.get(opts, :related, false)
    ensure(is_boolean(related), :invalid_options)

    ensure(
      is_map(s) and
        Enum.sort(Map.keys(s)) ==
          Enum.sort([:label, :components, :algorithm, :parameters, :digest, :field_schemas]),
      :invalid_options
    )

    ensure(
      SignatureFields.label?(s.label) and SignatureFields.algorithm?(s.algorithm) and
        is_binary(s.components) and Policy.schemas?(s.field_schemas),
      :invalid_options
    )

    p = s.parameters

    ensure(
      is_map(p) and
        Enum.sort(Map.keys(p)) == Enum.sort([:created, :expires_in, :nonce, :alg, :keyid, :tag]),
      :invalid_options
    )

    ensure(
      is_boolean(p.created) and is_boolean(p.alg) and p.nonce in [nil, :random] and
        (p.expires_in == nil or
           (is_integer(p.expires_in) and p.expires_in in 1..999_999_999_999_999)) and
        (p.expires_in == nil or p.created) and string?(p.keyid) and string?(p.tag) and
        (not is_tuple(s.algorithm) or not p.alg),
      :invalid_options
    )

    ensure(
      s.digest == nil or
        s.digest in [["sha-256"], ["sha-512"], ["sha-256", "sha-512"], ["sha-512", "sha-256"]],
      :invalid_options
    )

    input =
      case SignatureFields.inner(s.components) do
        {:ok, value} -> value
        {:error, %{reason: :limit}} -> fail(:limit)
        _ -> fail(:invalid_options)
      end

    ensure(input.parameters == [], :invalid_options)

    ensure(
      Enum.all?(input.value, fn item ->
        item.value != {:string, "host"} and
          not Enum.any?(item.parameters, fn {name, _} ->
            name == "tr" or (name == "req" and not related)
          end)
      end),
      :unsupported_component
    )

    input
  end

  defp string?(nil), do: true
  defp string?(s), do: is_binary(s) and byte_size(s) <= 1024

  def sign_options!(opts) do
    options(opts, [:signing_timeout, :clock, :body, :nonce])
    timeout = Keyword.get(opts, :signing_timeout, 5_000)
    ensure(is_integer(timeout) and timeout in 1..300_000, :invalid_options)

    ensure(
      is_function(Keyword.get(opts, :clock, fn -> System.system_time(:second) end), 0),
      :invalid_options
    )

    if Keyword.has_key?(opts, :nonce) do
      nonce = Keyword.get(opts, :nonce)
      ensure(is_binary(nonce) and byte_size(nonce) == 32, :invalid_options)
    end

    body_option!(Keyword.get(opts, :body, :as_is))
    timeout
  end

  def body_option!(:as_is), do: :ok
  def body_option!({:retain, n}) when is_integer(n) and n >= 0, do: :ok
  def body_option!(_), do: fail(:invalid_options)

  def body(nil, _), do: {nil, retained("")}
  def body({:stream, _enumerable} = stream, :as_is), do: {stream, %Body{state: :unavailable}}

  def body({:stream, enumerable}, {:retain, max}) do
    ensure(not is_function(enumerable), :body_unavailable)

    {chunks, _} =
      Enum.reduce(enumerable, {[], 0}, fn chunk, {chunks, size} ->
        total = size + IO.iodata_length(chunk)
        ensure(total <= max, :limit)
        {[chunk | chunks], total}
      end)

    bytes = chunks |> Enum.reverse() |> IO.iodata_to_binary()
    {bytes, retained(bytes)}
  end

  def body(data, option) when is_binary(data) or is_list(data) do
    size = IO.iodata_length(data)

    max =
      case option do
        :as_is -> 16_777_216
        {:retain, n} -> n
      end

    ensure(size <= max, :limit)
    bytes = IO.iodata_to_binary(data)
    {bytes, retained(bytes)}
  end

  def body(_, _), do: fail(:invalid_request)
  def retained(bytes), do: %Body{state: :retained, bytes: bytes, max_bytes: byte_size(bytes)}

  def body_required?(input, s),
    do:
      s.digest != nil or
        Enum.any?(
          input.value,
          &(not related?(&1) and
              &1.value in [
                {:string, "content-digest"},
                {:string, "repr-digest"},
                {:string, "content-length"}
              ])
        )

  def covered?(input, name),
    do: Enum.any?(input.value, &(&1.value == {:string, name} and not related?(&1)))

  defp related?(component), do: List.keymember?(component.parameters, "req", 0)

  # Core errors stay bounded; adapters keep their existing stage/attempt envelope.
  def core_sign(message, spec, signer, opts) do
    options(opts, [:clock, :signing_timeout, :nonce])

    spec = normalize_spec!(spec)

    case RequestSeal.Message.validate(message) do
      :ok -> {:ok, sign(message, spec, signer, opts, related: message.kind == :response)}
      _ -> {:error, RequestSeal.Error.new(:invalid_message, :input)}
    end
  rescue
    _ -> {:error, RequestSeal.Error.new(:invalid_options, :input)}
  catch
    {:adapter, _, %RequestSeal.Error{} = source} ->
      {:error, source}

    {:adapter, :signing_failed, _} ->
      {:error, RequestSeal.Error.new(:signer_failed, :crypto)}

    {:adapter, :body_unavailable, _} ->
      {:error, RequestSeal.Error.new(:body_unavailable, :content)}

    {:adapter, :digest_conflict, _} ->
      {:error, RequestSeal.Error.new(:digest_mismatch, :content)}

    {:adapter, :limit, _} ->
      {:error, RequestSeal.Error.new(:limit, :input)}

    {:adapter, reason, _}
    when reason in [:invalid_options, :unsupported_component, :invalid_request] ->
      {:error, RequestSeal.Error.new(reason, :input)}
  end

  def normalize_spec!(spec) do
    # Preserve the complete adapter contract, including explicitly absent expiry.
    case spec do
      %{parameters: parameters, digest: _, field_schemas: _} when is_map(parameters) ->
        if Enum.all?(
             [:created, :expires_in, :nonce, :alg, :keyid, :tag],
             &Map.has_key?(parameters, &1)
           ),
           do: spec,
           else: core_spec!(spec)

      _ ->
        core_spec!(spec)
    end
  end

  defp core_spec!(spec) do
    ensure(is_map(spec), :invalid_options)
    base_keys = [:label, :algorithm, :components, :digest, :field_schemas]
    parameter_keys = [:created, :expires_in, :nonce, :alg, :keyid, :tag]
    nested? = Map.has_key?(spec, :parameters)
    allowed = base_keys ++ if(nested?, do: [:parameters], else: parameter_keys)
    ensure(Enum.all?(Map.keys(spec), &(&1 in allowed)), :invalid_options)

    ensure(
      Enum.all?([:label, :algorithm, :components], &Map.has_key?(spec, &1)),
      :invalid_options
    )

    params = if nested?, do: spec.parameters, else: Map.take(spec, parameter_keys)

    ensure(
      is_map(params) and Enum.all?(Map.keys(params), &(&1 in parameter_keys)),
      :invalid_options
    )

    ensure(
      is_integer(params[:expires_in]) and params[:expires_in] in 1..999_999_999_999_999,
      :invalid_options
    )

    params =
      Map.merge(
        %{created: true, nonce: :random, alg: not is_tuple(spec.algorithm), keyid: nil, tag: nil},
        params
      )

    spec
    |> Map.take(base_keys)
    |> Map.put_new(:digest, nil)
    |> Map.put_new(:field_schemas, %{})
    |> Map.put(:parameters, params)
  end

  def sign(message, spec, signer, opts, mode \\ []) do
    spec = normalize_spec!(spec)
    input = spec!(spec, mode)
    timeout = sign_options!(opts)
    ensure(is_function(signer, 2) or match?(%KeyHandle{}, signer), :invalid_options)

    if match?(%KeyHandle{}, signer),
      do: ensure(signer.algorithm == spec.algorithm, :invalid_options)

    ensure(not body_required?(input, spec) or message.body.state == :retained, :body_unavailable)
    message = digest(message, spec.digest)
    message = content_length(message, input)
    input = %{input | parameters: parameters(spec, opts)}

    base =
      case SignatureBase.build(message, input, field_schemas: spec.field_schemas) do
        {:ok, bytes} -> bytes
        {:error, %{reason: :limit}} -> fail(:limit)
        _ -> fail(:unsupported_component)
      end

    signature =
      case invoke(signer, spec.algorithm, base, timeout) do
        {:ok, bytes} when is_binary(bytes) -> bytes
        {:error, %Custody.Error{} = source} -> fail(:signing_failed, source)
        _ -> fail(:signing_failed)
      end

    case RequestSeal.sign(
           message,
           %{label: spec.label, signature_input: input, algorithm: spec.algorithm},
           fn _, ^base -> {:ok, signature} end,
           field_schemas: spec.field_schemas
         ) do
      {:ok, signed} -> signed
      {:error, source} -> fail(:signing_failed, source)
    end
  end

  defp invoke(%KeyHandle{} = handle, _, base, timeout),
    do: Custody.sign(handle, base, timeout: timeout)

  defmodule FunctionCustodian do
    @moduledoc false
    @behaviour RequestSeal.Custody
    @impl true
    def sign(ref, algorithm, base, _context), do: ref.().(algorithm, base)
    @impl true
    def public_key(_), do: {:error, :unsupported_operation}
    @impl true
    def identity(_), do: {:error, :unsupported_operation}
  end

  defp invoke(signer, alg, base, timeout) do
    handle = %KeyHandle{
      custodian: FunctionCustodian,
      algorithm: alg,
      capabilities: [:sign],
      ref: fn -> signer end
    }

    Custody.sign(handle, base, timeout: timeout)
  end

  defp parameters(spec, opts) do
    p = spec.parameters

    now =
      if p.created,
        do: clock!(Keyword.get(opts, :clock, fn -> System.system_time(:second) end)),
        else: nil

    ensure(
      (not p.created and now == nil) or
        (is_integer(now) and now in 0..999_999_999_999_999),
      :invalid_options
    )

    expires = if p.expires_in, do: now + p.expires_in, else: nil

    ensure(
      expires == nil or expires in 0..999_999_999_999_999,
      :invalid_options
    )

    [
      {"created", integer(now)},
      {"expires", integer(expires)},
      {"nonce",
       if(p.nonce,
         do:
           {:string,
            Base.url_encode64(
              Keyword.get_lazy(opts, :nonce, fn -> :crypto.strong_rand_bytes(32) end),
              padding: false
            )},
         else: nil
       )},
      {"alg", if(p.alg, do: {:string, spec.algorithm}, else: nil)},
      {"keyid", string(p.keyid)},
      {"tag", string(p.tag)}
    ]
    |> Enum.reject(&(elem(&1, 1) == nil))
  end

  defp clock!(clock) do
    clock.()
  rescue
    _ -> fail(:invalid_options)
  catch
    _, _ -> fail(:invalid_options)
  end

  defp integer(nil), do: nil
  defp integer(i), do: {:integer, i}
  defp string(nil), do: nil
  defp string(s), do: {:string, s}

  defp digest(m, nil), do: m

  defp digest(m, algorithms) do
    values = for f <- m.fields, String.downcase(f.name) == "content-digest", do: f.value

    if values == [] do
      case Digest.compute(m.body, algorithms) do
        {:ok, value} ->
          {:ok, wire} = Digest.serialize(value)
          %{m | fields: m.fields ++ [field("content-digest", wire)]}

        {:error, %{reason: :limit}} ->
          fail(:limit)

        _ ->
          fail(:body_unavailable)
      end
    else
      case Digest.check(m, :content) do
        {:ok, facts} ->
          ensure(Enum.sort(facts.checked) == Enum.sort(algorithms), :digest_conflict)
          m

        {:error, %{reason: :limit}} ->
          fail(:limit)

        _ ->
          fail(:digest_conflict)
      end
    end
  end

  defp content_length(m, input) do
    if covered?(input, "content-length") do
      value = Integer.to_string(byte_size(m.body.bytes))
      values = for f <- m.fields, String.downcase(f.name) == "content-length", do: f.value
      ensure(values == [] or values == [value], :invalid_request)
      if values == [], do: %{m | fields: m.fields ++ [field("content-length", value)]}, else: m
    else
      m
    end
  end

  def field(name, value),
    do: %RequestSeal.FieldOccurrence{name: name, value: value, section: :headers}
end
