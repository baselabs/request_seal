defmodule RequestSeal.Digest do
  @moduledoc """
  [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) content/representation digests and preference fields, using OTP hashes.

  `compute/3` hashes a retained `RequestSeal.Body` without re-encoding its bytes.
  `init/3`, `update/2`, and `finish/1` support caller-fed binary chunks without
  retaining content, reading handles, or starting processes. Results are
  Structured Fields dictionaries, serialized with `serialize/1`. `check/3` and
  `check_stream/3` compare computed checksums with a Message's Content-Digest or
  Repr-Digest field.

  Retained content is bounded at 16,777,216 bytes (16 MiB): `compute/3` and
  `check/3` cannot raise that hard limit, bounding work on already retained
  content. Only caller-fed streams may explicitly opt in to a higher `:max_bytes`
  through `init/3`: incremental hash state uses constant memory and retains no
  chunks. The caller owns that larger work budget. State is caller-owned and
  immutable; use each returned state and finish only at EOF. Finishing does not
  prove transport completion; the caller supplies that boundary.

  Hash HTTP content after transfer framing removal but before content decoding.
  Gzip bytes remain gzip bytes. A range's content is only the transmitted range;
  a HEAD response's content is empty. Representation hashing always uses the
  complete selected representation, including content encoding (Sections 2–3).
  The caller selects that representation using HTTP method, status, metadata,
  and resource semantics; this library never reconstructs it from partial content.
  No unavailable body substitutes for empty bytes.

  Every supported checksum present must match. Before dictionary deduplication,
  checks reject a supported algorithm appearing more than once across the combined
  occurrences in the selected section with `:conflicting_digest`, even if its
  checksum values agree. Unknown and deprecated algorithms
  are parsed but never computed; success reports only their count. They cannot
  establish a match alone. A stream must have computed every supported algorithm
  in the field. A successful check proves checksum agreement only,
  with no signature coverage, authentication, identity, or authorization claim.
  Legacy Digest fields never substitute for these fields.

  `parse/1` and `serialize/1` use the RFC 8941 dictionary/byte-sequence schema
  mandated by RFC 9530; known checksum lengths are checked. Preferences are
  hints, with 0 meaning unacceptable (Section 4); this module selects no
  algorithm from them. Parameters and duplicate keys follow Structured
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

  Feed chunks with `update/2`, then call `finish/1` or `check_stream/3` at the
  caller's EOF.

  ## Parameters

    * `kind` - `:content` or `:representation`; selects the field `check_stream/3`
      compares against (Content-Digest or Repr-Digest).
    * `algorithms` - a nonempty list of unique names drawn from `"sha-256"` and
      `"sha-512"`; the result keeps this order.

  ## Options

    * `:max_bytes` - nonnegative integer bounding the total bytes accepted by
      `update/2`; default 16,777,216. It may exceed 16 MiB to explicitly opt in to
      a larger streaming work budget.

  ## Returns

    * `{:ok, %RequestSeal.Digest{}}` - immutable hash state with `bytes: 0`.
    * `{:error, %RequestSeal.Digest.Error{}}` - reasons this function can return:
      `:invalid_kind`, `:invalid_options` (not a keyword list, unknown or
      duplicate keys, or a negative or non-integer `:max_bytes`), and
      `:unsupported_algorithm`. Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> {:ok, state} = RequestSeal.Digest.init(:content, ["sha-256", "sha-512"], max_bytes: 1024)
      iex> {state.kind, state.bytes, state.max_bytes}
      {:content, 0, 1024}
      iex> RequestSeal.Digest.init(:content, ["md5"])
      {:error, %RequestSeal.Digest.Error{reason: :unsupported_algorithm}}
      iex> RequestSeal.Digest.init(:content, ["sha-256", "sha-256"])
      {:error, %RequestSeal.Digest.Error{reason: :unsupported_algorithm}}
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

  @doc """
  Hash one binary content chunk, rejecting overflow before cryptographic work.

  A chunk that would take the total past the state's `:max_bytes` rejects before
  it is hashed. The input state is not changed; continue with the returned state.

  ## Parameters

    * `state` - a `RequestSeal.Digest` state from `init/3` or a previous `update/2`.
    * `chunk` - a binary; an empty binary is allowed.

  ## Returns

    * `{:ok, %RequestSeal.Digest{}}` - the new state with `:bytes` increased.
    * `{:error, %RequestSeal.Digest.Error{}}` - reasons this function can return:
      `:invalid_state`, `:invalid_chunk`, and `:limit`.
      Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> {:ok, state} = RequestSeal.Digest.init(:content, ["sha-256"], max_bytes: 12)
      iex> {:ok, state} = RequestSeal.Digest.update(state, "cpu=0.42;")
      iex> state.bytes
      9
      iex> RequestSeal.Digest.update(state, "mem=0.91;")
      {:error, %RequestSeal.Digest.Error{reason: :limit}}
      iex> RequestSeal.Digest.update(state, [?a])
      {:error, %RequestSeal.Digest.Error{reason: :invalid_chunk}}
  """
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

  @doc """
  Finalize checksums as an ordered Structured Fields dictionary at caller EOF.

  Finishing does not prove transport completion. The state stays usable; finishing
  it again returns the same checksums.

  ## Parameters

    * `state` - a `RequestSeal.Digest` state.

  ## Returns

    * `{:ok, %RequestSeal.StructuredFields.Value{type: :dictionary}}` - one
      `{name, item}` member per algorithm in `init/3` order; each item value is
      `{:bytes, checksum}`.
    * `{:error, %RequestSeal.Digest.Error{reason: :invalid_state}}` - the only
      reason. Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> {:ok, state} = RequestSeal.Digest.init(:content, ["sha-256"])
      iex> {:ok, state} = RequestSeal.Digest.update(state, ~s({"hello": ))
      iex> {:ok, state} = RequestSeal.Digest.update(state, ~s("world"}))
      iex> {:ok, dictionary} = RequestSeal.Digest.finish(state)
      iex> RequestSeal.Digest.serialize(dictionary)
      {:ok, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}
      iex> RequestSeal.Digest.finish(%{state | bytes: -1})
      {:error, %RequestSeal.Digest.Error{reason: :invalid_state}}
  """
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

  @doc """
  Compute SHA-256/SHA-512 checksums from retained exact body bytes.

  ## Parameters

    * `body` - a valid `RequestSeal.Body` in the `:retained` state. Its bytes are
      hashed as they are, without re-encoding.
    * `algorithms` - a nonempty list of unique names drawn from `"sha-256"` and
      `"sha-512"`; the result keeps this order.

  ## Options

    * `:max_bytes` - integer in 0..16,777,216 bounding the hashed bytes; default
      16,777,216. A larger value rejects; use `init/3` for a larger streaming budget.

  ## Returns

    * `{:ok, %RequestSeal.StructuredFields.Value{type: :dictionary}}` - as in `finish/1`.
    * `{:error, %RequestSeal.Digest.Error{}}` - reasons this function can return:
      `:invalid_body`, `:body_unavailable` (streaming, unavailable, or consumed),
      `:invalid_options`, `:unsupported_algorithm`, and `:limit`.
      Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ~s({"hello": "world"})})
      iex> {:ok, dictionary} = RequestSeal.Digest.compute(body, ["sha-256"])
      iex> RequestSeal.Digest.serialize(dictionary)
      {:ok, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}
      iex> RequestSeal.Digest.compute(body, ["sha-256"], max_bytes: 16_777_217)
      {:error, %RequestSeal.Digest.Error{reason: :invalid_options}}
      iex> {:ok, unavailable} = RequestSeal.Body.new(%{state: :unavailable})
      iex> RequestSeal.Digest.compute(unavailable, ["sha-256"])
      {:error, %RequestSeal.Digest.Error{reason: :body_unavailable}}
  """
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

  @doc """
  Parse an RFC 9530 integrity dictionary; parameters retain RFC semantics.

  Every member must be a byte sequence. Known algorithms (`"sha-256"`, 32 bytes;
  `"sha-512"`, 64 bytes) have their checksum length checked; other algorithm
  names are kept unchecked. Duplicate keys follow the Structured Fields
  last-value, first-position rule.

  ## Parameters

    * `wire` - the field value bytes (at most 65,536).

  ## Returns

    * `{:ok, %RequestSeal.StructuredFields.Value{type: :dictionary}}`.
    * `{:error, %RequestSeal.StructuredFields.Error{}}` - `:syntax`, `:limit`,
      `:revision_type`, or `:schema_type`. Meanings: `RequestSeal.StructuredFields.Error`.
    * `{:error, %RequestSeal.Digest.Error{reason: :invalid_digest_length}}`.
      Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> {:ok, dictionary} = RequestSeal.Digest.parse("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, md5=:AAAA:")
      iex> Enum.map(dictionary.value, fn {name, _item} -> name end)
      ["sha-256", "md5"]
      iex> RequestSeal.Digest.parse("sha-256=:AAAA:")
      {:error, %RequestSeal.Digest.Error{reason: :invalid_digest_length}}
      iex> RequestSeal.Digest.parse("sha-256=42")
      {:error, %RequestSeal.StructuredFields.Error{reason: :schema_type}}
  """
  @spec parse(binary()) :: {:ok, Value.t()} | failure()
  def parse(wire), do: validate_parsed(StructuredFields.parse(wire, schema(:bytes)), :bytes)

  @doc """
  Serialize a digest dictionary with known algorithm checksum-size validation.

  ## Parameters

    * `value` - a `RequestSeal.StructuredFields.Value` dictionary whose members are
      `{:bytes, checksum}` items, such as the result of `compute/3` or `finish/1`.

  ## Returns

    * `{:ok, wire}` - canonical field value bytes; `""` for an empty dictionary
      (omit the field).
    * `{:error, %RequestSeal.StructuredFields.Error{}}` - `:invalid_value`,
      `:schema_type`, `:revision_type`, or `:limit`.
      Meanings: `RequestSeal.StructuredFields.Error`.
    * `{:error, %RequestSeal.Digest.Error{reason: :invalid_digest_length}}`.
      Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> alias RequestSeal.StructuredFields.Value
      iex> checksum = :crypto.hash(:sha256, "invoice 2041")
      iex> RequestSeal.Digest.serialize(%Value{type: :dictionary, value: [{"sha-256", %Value{type: :item, value: {:bytes, checksum}}}]})
      {:ok, "sha-256=:" <> Base.encode64(checksum) <> ":"}
      iex> RequestSeal.Digest.serialize(%Value{type: :dictionary, value: [{"sha-512", %Value{type: :item, value: {:bytes, checksum}}}]})
      {:error, %RequestSeal.Digest.Error{reason: :invalid_digest_length}}
  """
  @spec serialize(Value.t()) :: {:ok, binary()} | failure()
  def serialize(value), do: serialize_value(value, :bytes)

  @doc """
  Parse an RFC 9530 preference dictionary with integer weights in 0..10.

  Weights are hints; 0 means unacceptable. Algorithm names are not restricted.

  ## Parameters

    * `wire` - the Want-Content-Digest or Want-Repr-Digest field value bytes
      (at most 65,536).

  ## Returns

    * `{:ok, %RequestSeal.StructuredFields.Value{type: :dictionary}}` - members
      carry `{:integer, weight}` items.
    * `{:error, %RequestSeal.StructuredFields.Error{}}` - `:syntax`, `:limit`,
      `:revision_type`, or `:schema_type`. Meanings: `RequestSeal.StructuredFields.Error`.
    * `{:error, %RequestSeal.Digest.Error{reason: :invalid_preference}}` - a
      weight outside 0..10. Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> {:ok, preferences} = RequestSeal.Digest.parse_preferences("sha-512=3, sha-256=10, md5=0")
      iex> Enum.map(preferences.value, fn {name, item} -> {name, item.value} end)
      [{"sha-512", {:integer, 3}}, {"sha-256", {:integer, 10}}, {"md5", {:integer, 0}}]
      iex> RequestSeal.Digest.parse_preferences("sha-256=11")
      {:error, %RequestSeal.Digest.Error{reason: :invalid_preference}}
  """
  @spec parse_preferences(binary()) :: {:ok, Value.t()} | failure()
  def parse_preferences(wire),
    do: validate_parsed(StructuredFields.parse(wire, schema(:integer)), :integer)

  @doc """
  Serialize an RFC 9530 preference dictionary with weight validation.

  ## Parameters

    * `value` - a `RequestSeal.StructuredFields.Value` dictionary whose members are
      `{:integer, weight}` items with weights in 0..10.

  ## Returns

    * `{:ok, wire}` - canonical field value bytes; `""` for an empty dictionary
      (omit the field).
    * `{:error, %RequestSeal.StructuredFields.Error{}}` - `:invalid_value`,
      `:schema_type`, `:revision_type`, or `:limit`.
      Meanings: `RequestSeal.StructuredFields.Error`.
    * `{:error, %RequestSeal.Digest.Error{reason: :invalid_preference}}`.
      Meanings: `RequestSeal.Digest.Error`.

  ## Examples

      iex> alias RequestSeal.StructuredFields.Value
      iex> weight = fn n -> %Value{type: :item, value: {:integer, n}} end
      iex> RequestSeal.Digest.serialize_preferences(%Value{type: :dictionary, value: [{"sha-256", weight.(10)}, {"sha-512", weight.(1)}]})
      {:ok, "sha-256=10, sha-512=1"}
      iex> RequestSeal.Digest.serialize_preferences(%Value{type: :dictionary, value: [{"sha-256", weight.(-1)}]})
      {:error, %RequestSeal.Digest.Error{reason: :invalid_preference}}
  """
  @spec serialize_preferences(Value.t()) :: {:ok, binary()} | failure()
  def serialize_preferences(value), do: serialize_value(value, :integer)

  @doc """
  Read an explicit Want-Content-Digest or Want-Repr-Digest field/section.

  Matching occurrences in the selected section are combined in order, as in
  `RequestSeal.StructuredFields.parse_field/5`, then parsed as in
  `parse_preferences/1`.

  ## Parameters

    * `message` - a valid `RequestSeal.Message`.
    * `name` - `"Want-Content-Digest"` or `"Want-Repr-Digest"`, any case.
    * `section` - `:headers` (default) or `:trailers`.

  ## Returns

    * `{:ok, %RequestSeal.StructuredFields.Value{type: :dictionary}}`.
    * `{:error, %RequestSeal.Digest.Error{}}` - `:invalid_options` (another
      section), `:invalid_field` (another field name), or `:invalid_preference`.
      Meanings: `RequestSeal.Digest.Error`.
    * `{:error, %RequestSeal.StructuredFields.Error{}}` - `:invalid_message`,
      `:unavailable_section`, `:missing_field`, `:limit`, `:syntax`,
      `:revision_type`, or `:schema_type`.
      Meanings: `RequestSeal.StructuredFields.Error`.

  ## Examples

      iex> {:ok, request} = RequestSeal.Message.request("GET", "https://builds.example/artifacts/118", [{"Want-Content-Digest", "sha-512=3, sha-256=10"}], nil)
      iex> {:ok, preferences} = RequestSeal.Digest.preferences(request, "want-content-digest")
      iex> Enum.map(preferences.value, fn {name, item} -> {name, item.value} end)
      [{"sha-512", {:integer, 3}}, {"sha-256", {:integer, 10}}]
      iex> RequestSeal.Digest.preferences(request, "Want-Repr-Digest")
      {:error, %RequestSeal.StructuredFields.Error{reason: :missing_field}}
      iex> RequestSeal.Digest.preferences(request, "Accept")
      {:error, %RequestSeal.Digest.Error{reason: :invalid_field}}
  """
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

  @doc """
  Recompute the selected field from retained content or explicit representation.

  `:content` checks Content-Digest against the Message's retained body.
  `:representation` checks Repr-Digest against the `:representation` option, a
  retained Body containing the entire selected representation, even when it
  equals content. Only supported algorithms in the field are computed.

  ## Parameters

    * `message` - a valid `RequestSeal.Message`.
    * `kind` - `:content` or `:representation`.

  ## Options

  Unknown or duplicate options reject.

    * `:section` - `:headers` (default) or `:trailers`; sections never merge. A
      trailer must be observed (a list) before checking it.
    * `:max_bytes` - integer in 0..16,777,216 bounding the hashed bytes; default
      16,777,216.
    * `:representation` - a retained `RequestSeal.Body`; required for
      `:representation` and rejected for `:content`.

  ## Returns

    * `{:ok, %{kind: kind, bytes: count, checked: names, unsupported: count}}` -
      every supported checksum matched. `:checked` lists the supported algorithm
      names in field order; `:unsupported` counts other algorithm names.
    * `{:error, %RequestSeal.Digest.Error{}}` - reasons this function can return:
      `:invalid_message`, `:invalid_kind`, `:invalid_options`,
      `:representation_required`, `:invalid_body`, `:body_unavailable`,
      `:conflicting_digest`, `:invalid_digest_length`, `:unsupported_algorithm`
      (no supported algorithm in the field), `:limit`, and `:mismatch`.
      Meanings: `RequestSeal.Digest.Error`.
    * `{:error, %RequestSeal.StructuredFields.Error{}}` - `:unavailable_section`,
      `:missing_field`, `:limit`, `:syntax`, `:revision_type`, or `:schema_type`.
      Meanings: `RequestSeal.StructuredFields.Error`.

  ## Examples

      iex> {:ok, request} = RequestSeal.Message.request("POST", "https://docs.example/notes", [], ~s({"hello": "world"}), digest: ["sha-256"])
      iex> RequestSeal.Digest.check(request, :content)
      {:ok, %{kind: :content, bytes: 18, checked: ["sha-256"], unsupported: 0}}
      iex> RequestSeal.Digest.check(%{request | body: %{request.body | bytes: ~s({"hello": "World"})}}, :content)
      {:error, %RequestSeal.Digest.Error{reason: :mismatch}}
      iex> RequestSeal.Digest.check(request, :representation)
      {:error, %RequestSeal.Digest.Error{reason: :representation_required}}

  A representation check reads Repr-Digest and the explicit representation body:

      iex> {:ok, representation} = RequestSeal.Body.new(%{state: :retained, bytes: ~s({"hello": "world"})})
      iex> {:ok, response} = RequestSeal.Message.response(200, [{"Repr-Digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}], nil)
      iex> RequestSeal.Digest.check(response, :representation, representation: representation)
      {:ok, %{kind: :representation, bytes: 18, checked: ["sha-256"], unsupported: 0}}
  """
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

  @doc """
  Check hashes accumulated through caller EOF against a Message digest field.

  The state's kind selects Content-Digest (`:content`) or Repr-Digest
  (`:representation`). The state must have computed every supported algorithm in
  the field; extra computed algorithms are ignored. The Message body is not read.

  ## Parameters

    * `state` - a `RequestSeal.Digest` state fed through the caller's EOF.
    * `message` - a valid `RequestSeal.Message`.

  ## Options

    * `:section` - `:headers` (default) or `:trailers`; the only option. A trailer
      must be observed (a list) before checking it.

  ## Returns

    * `{:ok, %{kind: kind, bytes: count, checked: names, unsupported: count}}` - as in `check/3`.
    * `{:error, %RequestSeal.Digest.Error{}}` - reasons this function can return:
      `:invalid_state`, `:invalid_options`, `:conflicting_digest`,
      `:invalid_digest_length`, `:unsupported_algorithm`, `:uncomputed_algorithm`,
      and `:mismatch`. Meanings: `RequestSeal.Digest.Error`.
    * `{:error, %RequestSeal.StructuredFields.Error{}}` - `:invalid_message`,
      `:unavailable_section`, `:missing_field`, `:limit`, `:syntax`,
      `:revision_type`, or `:schema_type`.
      Meanings: `RequestSeal.StructuredFields.Error`.

  ## Examples

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :streaming, source: make_ref()})
      iex> {:ok, transport} = RequestSeal.TransportFacts.new(%{})
      iex> {:ok, field} = RequestSeal.FieldOccurrence.new(%{name: "Content-Digest", value: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", section: :headers})
      iex> {:ok, response} = RequestSeal.Message.new(%{kind: :response, status: 200, fields: [field], trailers: :pending, body: body, transport: transport})
      iex> {:ok, state} = RequestSeal.Digest.init(:content, ["sha-256"])
      iex> {:ok, state} = RequestSeal.Digest.update(state, ~s({"hello": "world"}))
      iex> RequestSeal.Digest.check_stream(state, response)
      {:ok, %{kind: :content, bytes: 18, checked: ["sha-256"], unsupported: 0}}
      iex> RequestSeal.Digest.check_stream(state, response, section: :trailers)
      {:error, %RequestSeal.StructuredFields.Error{reason: :unavailable_section}}
      iex> {:ok, other} = RequestSeal.Digest.init(:content, ["sha-512"])
      iex> RequestSeal.Digest.check_stream(other, response)
      {:error, %RequestSeal.Digest.Error{reason: :uncomputed_algorithm}}
  """
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
