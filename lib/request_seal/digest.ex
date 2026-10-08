defmodule RequestSeal.Digest do
  @moduledoc """
  [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) content/representation digests and preference fields, using OTP hashes.

  `compute/3` hashes a retained `RequestSeal.Body` without re-encoding its bytes.
  Algorithms are an explicit nonempty, unique list drawn from `"sha-256"` and
  `"sha-512"`. Its result is a Structured Fields dictionary, serialized with
  `serialize/1`. `init/3`, `update/2`, and `finish/1` support caller-fed binary
  chunks without retaining content, reading handles, or starting processes.
  `:max_bytes` defaults to 16,777,216 and may be lowered to any nonnegative integer.
  Retained-body `compute/3` and `check/3` cannot raise this 16 MiB hard limit,
  bounding work on already retained content. Only caller-fed streams may explicitly
  opt in to a higher `:max_bytes` through `init/3`: incremental hash state uses
  constant memory and retains no chunks. The caller owns that larger work budget.
  A chunk exceeding the remaining limit rejects before hashing it. State is
  caller-owned and immutable; use each returned state and finish only at EOF.
  Finishing does not prove transport completion; the caller supplies that boundary.

  Hash HTTP content after transfer framing removal but before content decoding.
  Gzip bytes remain gzip bytes. A range's content is only the transmitted range;
  a HEAD response's content is empty. Representation hashing always uses the
  complete selected representation, including content encoding (Sections 2–3).
  The caller selects that representation using HTTP method, status, metadata,
  and resource semantics; this library never reconstructs it from partial content.

  `check/3` takes a validated Message and `:content` or `:representation`.
  Content uses the Message's retained body. Representation requires the option
  `:representation`, a retained Body containing the entire selected representation,
  even when it equals content. No unavailable body substitutes for empty bytes.
  `:section` selects `:headers` (default) or `:trailers`; sections never merge.
  `:max_bytes` sets the computation bound. Unknown or duplicate options reject.
  `check_stream/3` checks caller-fed state against the field selected by its kind;
  its only option is `:section`. A trailer must be observed before checking it.

  Every supported checksum present must match. Before dictionary deduplication,
  checks reject a supported algorithm appearing more than once across the combined
  occurrences in the selected section with `:conflicting_digest`, even if its
  checksum values agree. Unknown and deprecated algorithms
  are parsed but never computed; success reports only their count. They cannot
  establish a match alone. A stream must have computed every supported algorithm
  in the field. A successful map contains `:kind`, `:bytes`, `:checked` (supported
  algorithm names), and `:unsupported` (count); it proves checksum agreement only,
  with no signature coverage, authentication, identity, or authorization claim.
  Legacy Digest fields never substitute for these fields.

  `parse/1` and `serialize/1` use the RFC 8941 dictionary/byte-sequence schema
  mandated by RFC 9530; known checksum lengths are checked. `parse_preferences/1`,
  `serialize_preferences/1`, and `preferences/3` use integer weights in 0..10.
  Preferences are hints, with 0 meaning unacceptable (Section 4); this module
  selects no algorithm from them. Parameters and duplicate keys follow Structured
  Fields rules (last value, first position), except supported checksum algorithms
  in `check/3` and `check_stream/3`, which reject any repeat with `:conflicting_digest`.
  Inspection hides hash contexts.
  """
  alias RequestSeal.{Body, Message, StructuredFields}
  alias RequestSeal.StructuredFields.{Schema, Value}
  alias RequestSeal.Digest.Error

  @derive {Inspect, only: [:kind, :bytes, :max_bytes]}
  defstruct [:kind, :hashes, bytes: 0, max_bytes: 16_777_216]

  @type t :: %__MODULE__{
          kind: :content | :representation,
          hashes: [{binary(), reference()}],
          bytes: non_neg_integer(),
          max_bytes: non_neg_integer()
        }
  @type failure :: {:error, Error.t() | StructuredFields.Error.t()}
  @algorithms %{"sha-256" => {:sha256, 32}, "sha-512" => {:sha512, 64}}
  @ceiling 16_777_216

  @doc """
  Initialize incremental hashes for an explicit semantic kind and algorithms.

  `:max_bytes` may exceed 16 MiB to explicitly opt in to a larger streaming work budget.
  """
  @spec init(:content | :representation, [binary()], keyword()) :: {:ok, t()} | failure()
  def init(kind, algorithms, opts \\ []) do
    protect(fn ->
      ensure(kind in [:content, :representation], :invalid_kind)
      options(opts, [:max_bytes])
      max = maximum(opts)
      ensure(valid_algorithms?(algorithms), :unsupported_algorithm)

      hashes =
        Enum.map(algorithms, fn name -> {name, :crypto.hash_init(elem(@algorithms[name], 0))} end)

      {:ok, %__MODULE__{kind: kind, hashes: hashes, max_bytes: max}}
    end)
  end

  @doc "Hash one binary content chunk, rejecting overflow before cryptographic work."
  @spec update(t(), binary()) :: {:ok, t()} | failure()
  def update(state, chunk) do
    protect(fn ->
      valid_state(state)
      ensure(is_binary(chunk), :invalid_chunk)
      total = state.bytes + byte_size(chunk)
      ensure(total <= state.max_bytes, :limit)

      hashes =
        Enum.map(state.hashes, fn {name, context} ->
          {name, :crypto.hash_update(context, chunk)}
        end)

      {:ok, %{state | hashes: hashes, bytes: total}}
    end)
  end

  @doc "Finalize checksums as an ordered Structured Fields dictionary at caller EOF."
  @spec finish(t()) :: {:ok, Value.t()} | failure()
  def finish(state) do
    protect(fn ->
      valid_state(state)

      members =
        Enum.map(state.hashes, fn {name, context} ->
          digest = :crypto.hash_final(context)
          ensure(byte_size(digest) == elem(@algorithms[name], 1), :invalid_state)
          {name, %Value{type: :item, value: {:bytes, digest}}}
        end)

      {:ok, %Value{type: :dictionary, value: members}}
    end)
  end

  @doc "Compute SHA-256/SHA-512 checksums from retained exact body bytes."
  @spec compute(Body.t(), [binary()], keyword()) :: {:ok, Value.t()} | failure()
  def compute(body, algorithms, opts \\ []) do
    protect(fn ->
      bytes = retained(body)
      options(opts, [:max_bytes])
      retained_maximum(opts)

      with {:ok, state} <- init(:content, algorithms, opts),
           {:ok, state} <- update(state, bytes),
           do: finish(state)
    end)
  end

  @doc "Parse an RFC 9530 integrity dictionary; parameters retain RFC semantics."
  @spec parse(binary()) :: {:ok, Value.t()} | failure()
  def parse(wire), do: validate_parsed(StructuredFields.parse(wire, schema(:bytes)), :bytes)

  @doc "Serialize a digest dictionary with known algorithm checksum-size validation."
  @spec serialize(Value.t()) :: {:ok, binary()} | failure()
  def serialize(value), do: serialize_value(value, :bytes)

  @doc "Parse an RFC 9530 preference dictionary with integer weights in 0..10."
  @spec parse_preferences(binary()) :: {:ok, Value.t()} | failure()
  def parse_preferences(wire),
    do: validate_parsed(StructuredFields.parse(wire, schema(:integer)), :integer)

  @doc "Serialize an RFC 9530 preference dictionary with weight validation."
  @spec serialize_preferences(Value.t()) :: {:ok, binary()} | failure()
  def serialize_preferences(value), do: serialize_value(value, :integer)

  @doc "Read an explicit Want-Content-Digest or Want-Repr-Digest field/section."
  @spec preferences(Message.t(), binary(), :headers | :trailers) :: {:ok, Value.t()} | failure()
  def preferences(message, name, section \\ :headers) do
    protect(fn ->
      ensure(section in [:headers, :trailers], :invalid_options)

      ensure(
        RequestSeal.Message.Validation.token?(name, 256) and
          String.downcase(name) in ["want-content-digest", "want-repr-digest"],
        :invalid_field
      )

      validate_parsed(
        StructuredFields.parse_field(message, name, schema(:integer), section),
        :integer
      )
    end)
  end

  @doc "Recompute the selected field from retained content or explicit representation."
  @spec check(Message.t(), :content | :representation, keyword()) :: {:ok, map()} | failure()
  def check(message, kind, opts \\ []) do
    protect(fn ->
      ensure(Message.validate(message) == :ok, :invalid_message)
      ensure(kind in [:content, :representation], :invalid_kind)
      options(opts, [:section, :max_bytes, :representation])
      section = section(opts)
      retained_maximum(opts)

      ensure(
        kind == :representation or not Keyword.has_key?(opts, :representation),
        :invalid_options
      )

      body = if kind == :content, do: message.body, else: representation(opts)
      bytes = retained(body)

      with {:ok, expected} <- field(message, kind, section),
           names = supported(expected),
           {:ok, state} <- init(kind, names, Keyword.take(opts, [:max_bytes])),
           {:ok, state} <- update(state, bytes),
           do: compare(state, expected)
    end)
  end

  @doc "Check hashes accumulated through caller EOF against a Message digest field."
  @spec check_stream(t(), Message.t(), keyword()) :: {:ok, map()} | failure()
  def check_stream(state, message, opts \\ []) do
    protect(fn ->
      valid_state(state)
      options(opts, [:section])

      with {:ok, expected} <- field(message, state.kind, section(opts)),
           do: compare(state, expected)
    end)
  end

  defp compare(state, expected) do
    names = supported(expected)
    ensure(names != [], :unsupported_algorithm)

    with {:ok, actual} <- finish(state) do
      computed = Map.new(actual.value)

      Enum.each(expected.value, fn {name, item} ->
        if Map.has_key?(@algorithms, name) do
          ensure(Map.has_key?(computed, name), :uncomputed_algorithm)
          {:bytes, bytes} = computed[name].value
          {:bytes, expected_bytes} = item.value
          ensure(:crypto.hash_equals(bytes, expected_bytes), :mismatch)
        end
      end)

      {:ok,
       %{
         kind: state.kind,
         bytes: state.bytes,
         checked: names,
         unsupported: length(expected.value) - length(names)
       }}
    end
  end

  defp field(message, kind, section) do
    name = if kind == :content, do: "Content-Digest", else: "Repr-Digest"

    case StructuredFields.parse_field(
           message,
           name,
           schema(:bytes),
           section,
           unique_keys: Map.keys(@algorithms)
         ) do
      {:error, %StructuredFields.Error{reason: :duplicate_key}} ->
        {:error, %Error{reason: :conflicting_digest}}

      result ->
        validate_parsed(result, :bytes)
    end
  end

  defp supported(value),
    do: for({name, _} <- value.value, Map.has_key?(@algorithms, name), do: name)

  defp schema(type) do
    %Schema{
      revision: :rfc8941,
      type: :dictionary,
      item_types: [type],
      parameter_types: Schema.types(:rfc8941)
    }
  end

  defp validate_parsed({:ok, value}, type) do
    protect(fn ->
      Enum.each(value.value, fn {name, item} ->
        case {type, item.value} do
          {:integer, {:integer, weight}} ->
            ensure(weight in 0..10, :invalid_preference)

          {:bytes, {:bytes, bytes}} ->
            case @algorithms[name] do
              nil -> :ok
              {_, size} -> ensure(byte_size(bytes) == size, :invalid_digest_length)
            end
        end
      end)

      {:ok, value}
    end)
  end

  defp validate_parsed(error, _), do: error

  defp serialize_value(value, type) do
    with {:ok, wire} <- StructuredFields.serialize(value, schema(type)),
         {:ok, _} <- validate_parsed({:ok, value}, type),
         do: {:ok, wire}
  end

  defp representation(opts) do
    ensure(Keyword.has_key?(opts, :representation), :representation_required)
    Keyword.fetch!(opts, :representation)
  end

  defp retained(body) do
    ensure(Body.validate(body) == :ok, :invalid_body)
    ensure(body.state == :retained, :body_unavailable)
    body.bytes
  end

  defp options(opts, allowed) do
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_options)
    keys = Keyword.keys(opts)

    ensure(
      length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in allowed)),
      :invalid_options
    )
  end

  defp maximum(opts) do
    max = Keyword.get(opts, :max_bytes, @ceiling)
    ensure(is_integer(max) and max >= 0, :invalid_options)
    max
  end

  defp retained_maximum(opts) do
    max = maximum(opts)
    ensure(max <= @ceiling, :invalid_options)
    max
  end

  defp section(opts) do
    section = Keyword.get(opts, :section, :headers)
    ensure(section in [:headers, :trailers], :invalid_options)
    section
  end

  defp valid_algorithms?([name]), do: Map.has_key?(@algorithms, name)

  defp valid_algorithms?([a, b]),
    do: a != b and Map.has_key?(@algorithms, a) and Map.has_key?(@algorithms, b)

  defp valid_algorithms?(_), do: false

  defp valid_state(state) do
    ensure(state_valid?(state), :invalid_state)
  end

  defp state_valid?(%__MODULE__{} = state) do
    Enum.sort(Map.keys(state)) == Enum.sort(Map.keys(%__MODULE__{})) and
      state.kind in [:content, :representation] and is_integer(state.max_bytes) and
      state.max_bytes >= 0 and is_integer(state.bytes) and state.bytes >= 0 and
      state.bytes <= state.max_bytes and valid_hashes?(state.hashes)
  end

  defp state_valid?(_), do: false

  defp valid_hashes?(hashes) when is_list(hashes) and length(hashes) in 1..2 do
    Enum.all?(hashes, fn
      {name, context} -> Map.has_key?(@algorithms, name) and is_reference(context)
      _ -> false
    end) and valid_algorithms?(Enum.map(hashes, &elem(&1, 0)))
  end

  defp valid_hashes?(_), do: false

  defp ensure(true, _), do: :ok
  defp ensure(_, reason), do: throw({:digest, reason})

  defp protect(fun) do
    fun.()
  rescue
    _error in [ArgumentError, ErlangError] ->
      {:error, %Error{reason: :invalid_state}}
  catch
    {:digest, reason} -> {:error, %Error{reason: reason}}
  end
end
