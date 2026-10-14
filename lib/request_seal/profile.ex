defmodule RequestSeal.Profile do
  @moduledoc """
  Shared HTTP signature pipeline for profiles owned by extension packages.

  This extension surface is unstable; pin RequestSeal exactly.

  An extension selects its source-specific rules, then uses `dictionaries/2` to
  parse paired signature fields, `preflight/4` to check coverage and freshness
  before discovery, and `verify_label/6` to verify its selected dictionary
  member under an explicit `RequestSeal.Policy`. The input and signature values
  come from the same label returned by `dictionaries/2`.

  Profile maps contain at most eight atom keys and require
  `name: {package, kind}`, where both values are atoms and `package` is not
  `:request_seal`, `:"request-seal"`, `:rfc9421`, `:web_bot_auth`, or `:"web-bot-auth"`. Use a compile-time constant
  in the extension module, never a name derived from wire input. Bare atom names, including the core-owned names
  `:rfc9421` and `:web_bot_auth`, reject as `:invalid_profile` at the `:input` layer.
  Other values must be atoms, integers from -999,999,999,999,999 through
  999,999,999,999,999, or binaries of at most 256 bytes.

  This pipeline enforces the supplied generic policy, not an extension's
  source-specific predicates. Extensions own those checks and any trusted
  principal attribution. A profile stamp is not proof of profile enforcement;
  consumers must allowlist trusted profiles and their verification code.
  Replay commitments receive the selected profile in authenticated facts;
  commitments must bind `facts.profile` to separate profile security scopes.
  `RequestSeal.Ash.scope/2` accepts only its core profile allowlist.
  """
  alias RequestSeal.{Authentication, Error, Message, Policy, SignatureFields, Verification}
  alias RequestSeal.StructuredFields.Value

  @type stamp :: %{
          required(:name) => {atom(), atom()},
          optional(atom()) => atom() | integer() | binary()
        }

  @doc """
  Check the semantic rules for one parsed RFC 9421 Signature-Input Inner List.

  Accepts a `RequestSeal.StructuredFields.Value` with `type: :inner_list`,
  ordered component items, and signature parameters. It delegates to the shared
  signature-field validator: at most 256 components, unique component identities,
  recognized derived components or lowercase field names, permitted component
  parameters, and integer `created`/`expires` or string `nonce`/`alg`/`keyid`/`tag`.
  Unknown signature parameters remain permitted under RFC 9421 Section 2.3.
  An empty component list is permitted; profiles select required coverage.

  Parse or validate the Structured Fields representation first under an RFC 8941
  schema. This predicate checks signature semantics, not the complete Structured
  Fields grammar, parameter uniqueness, freshness, key trust, or cryptography.
  It does not parse wire binaries.

  ## Parameters

    * `input` - any term; only a parsed `RequestSeal.StructuredFields.Value`
      Inner List can pass.

  ## Returns

    * `true` - the Inner List satisfies the rules above.
    * `false` - otherwise, including binaries, non-inner lists, and malformed
      structures that cannot be inspected. This function never raises.

  ## Examples

      iex> alias RequestSeal.StructuredFields.{Schema, Value}
      iex> {:ok, schema} = Schema.new(%{revision: :rfc8941, type: :list, item_types: [:string], inner_lists: true})
      iex> {:ok, %Value{value: [input]}} = RequestSeal.StructuredFields.parse(~s[("@method" "@path");created=1618884473], schema)
      iex> RequestSeal.Profile.valid_signature_input?(input)
      true
      iex> RequestSeal.Profile.valid_signature_input?(~s[("@method")])
      false
  """
  @spec valid_signature_input?(term()) :: boolean()
  def valid_signature_input?(input) do
    SignatureFields.valid_inner?(input)
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  @doc """
  Parse paired signature dictionaries in encounter order under a member limit.

  Parses `Signature-Input` and `Signature` header fields with the same rules as
  `RequestSeal.verify/3` and checks that their labels pair exactly. It
  validates the message and `max` first but not the selected Inner List; pass
  the returned values to `preflight/4` and `verify_label/6`.

  ## Parameters

    * `message` - a `RequestSeal.Message`.
    * `max` - dictionary encounter ceiling for each field, normally the
      policy's `:max_signatures` (1 to 64).

  ## Returns

    * `{:ok, {entries, signatures}}` - `entries` is a list of
      `{label, input}` Signature-Input members in encounter order; `signatures`
      maps each label to its `Signature` byte-sequence value.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return:
      `:missing_signature_input`, `:missing_signature`,
      `:invalid_signature_input`, `:invalid_signature_field`,
      `:duplicate_label`, `:duplicate_parameter`, `:label_mismatch` (layer
      `:fields`); `:limit` (layer `:input`); `:invalid_policy` (layer
      `:input`) for an unexpected fault; `:invalid_options` (layer `:input`)
      when `max` is not an integer from 1 to 64; `:invalid_message` (layer
      `:input`) when `message` is not a valid `RequestSeal.Message`. Both are
      checked before parsing. Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, message} = RequestSeal.Message.request("GET", "https://crawl.example.org/sitemap.xml", [], nil)
      iex> spec = %{label: "crawl", algorithm: "ed25519", components: ~s[("@method" "@authority" "@path")], expires_in: 60, keyid: "crawler-key", tag: "example-crawl"}
      iex> {:ok, signed} = RequestSeal.sign(message, spec, handle, clock: fn -> 1_700_000_000 end)
      iex> {:ok, {[{"crawl", input}], signatures}} = RequestSeal.Profile.dictionaries(signed, 16)
      iex> {RequestSeal.Profile.valid_signature_input?(input), Map.keys(signatures)}
      {true, ["crawl"]}
      iex> {:error, error} = RequestSeal.Profile.dictionaries(message, 16)
      iex> {error.reason, error.layer}
      {:missing_signature_input, :fields}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec dictionaries(Message.t(), pos_integer()) ::
          {:ok, {[{binary(), Value.t()}], %{binary() => Value.t()}}} | {:error, Error.t()}
  def dictionaries(message, max) do
    protect(fn ->
      cond do
        not (is_integer(max) and max in 1..64) -> error(:invalid_options, :input)
        Message.validate(message) != :ok -> error(:invalid_message, :input)
        true -> Authentication.dictionaries(message, max)
      end
    end)
  end

  @doc """
  Check required coverage and freshness before resolving a selected key.

  Lets an extension reject a selected signature before key discovery. It
  applies the same coverage and freshness rules as `RequestSeal.verify/3`
  and reads the freshness clock once. `verify_label/6` repeats these checks
  under a validated policy.

  ## Parameters

    * `input` - the selected Signature-Input Inner List from `dictionaries/2`.
    * `components` - serialized Inner List of required component identifiers,
      as in `RequestSeal.Policy`.
    * `extra` - `:allow` or `:reject` (exact coverage), as the policy's
      `:extra_components`.
    * `freshness_policy` - `:not_evaluated` or a freshness map with `:clock`,
      `:max_age`, `:skew`, and `:require_expires`, as in `RequestSeal.Policy`.
      It is validated like `RequestSeal.Policy.new/1`'s freshness.

  ## Returns

    * `{:ok, :not_evaluated}` - when freshness is not evaluated.
    * `{:ok, facts}` - freshness facts `%{now: _, created: _, expires: _, max_age: _, skew: _}`.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return:
      `:missing_required_component`, `:unexpected_component` (layer
      `:policy`); `:invalid_clock`, `:missing_created`, `:missing_expires`,
      `:created_in_future`, `:expired`, `:too_old` (layer `:freshness`);
      `:invalid_signature_input` (layer `:fields`) or `:limit` (layer
      `:input`) for unparsable `components`; `:invalid_policy` (layer
      `:input`) when `extra` is not `:allow` or `:reject`, when the freshness
      policy is invalid (for example a negative `skew`), or for a malformed
      argument that faults.
      Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, message} = RequestSeal.Message.request("GET", "https://crawl.example.org/sitemap.xml", [], nil)
      iex> spec = %{label: "crawl", algorithm: "ed25519", components: ~s[("@method" "@authority" "@path")], expires_in: 60, keyid: "crawler-key", tag: "example-crawl"}
      iex> {:ok, signed} = RequestSeal.sign(message, spec, handle, clock: fn -> 1_700_000_000 end)
      iex> {:ok, {[{"crawl", input}], _signatures}} = RequestSeal.Profile.dictionaries(signed, 16)
      iex> freshness = %{clock: fn -> 1_700_000_030 end, max_age: 300, skew: 0, require_expires: true}
      iex> {:ok, facts} = RequestSeal.Profile.preflight(input, ~s[("@method" "@authority" "@path")], :reject, freshness)
      iex> {facts.created, facts.expires}
      {1_700_000_000, 1_700_000_060}
      iex> {:error, error} = RequestSeal.Profile.preflight(input, ~s[("@method" "@path")], :reject, :not_evaluated)
      iex> {error.reason, error.layer}
      {:unexpected_component, :policy}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec preflight(Value.t(), binary(), :allow | :reject, :not_evaluated | map()) ::
          {:ok, :not_evaluated | map()} | {:error, Error.t()}
  def preflight(input, components, extra, freshness_policy) do
    protect(fn ->
      if extra in [:allow, :reject] and Policy.freshness_valid?(freshness_policy),
        do: Authentication.preflight(input, components, extra, freshness_policy),
        else: error(:invalid_policy, :input)
    end)
  end

  @doc """
  Verify a selected member under an explicit policy and package-namespaced profile.

  Runs the generic verification pipeline of `RequestSeal.verify/3` on one
  label, stamping `profile` into the result and into replay commitment facts.
  Verification re-parses the message under the policy's `max_signatures` and
  checks that both supplied values equal that label's entries before
  resolving a key.

  `verify_label/6` does not accept `:representation` or `:digest_state` options.
  Content checks can use retained message body bytes only; representation
  policies and stream digest states require generic `RequestSeal.verify/3`
  with its validated options.

  ## Parameters

    * `message` - a `RequestSeal.Message`.
    * `policy` - a valid `RequestSeal.Policy`.
    * `label` - the selected signature label.
    * `input` - the label's Signature-Input value from `dictionaries/2`.
    * `signature` - the label's Signature value from `dictionaries/2`
      (a byte sequence of 1 to 1,024 bytes).
    * `profile` - a `t:stamp/0` with a package-namespaced `name`, as
      described in the module documentation.

  ## Returns

    * `{:ok, %RequestSeal.Verification{}}` - with `profile` set to the stamp,
      `principal: :unattributed`, and `authorization: :not_evaluated`.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return:
      `:invalid_profile`, `:invalid_policy`, `:invalid_options` (invalid
      label), `:invalid_message`, `:limit` (layer `:input`);
      `:invalid_signature_field`, `:unknown_label`, `:invalid_signature_input`,
      and the dictionary reasons of `dictionaries/2` (layer `:fields`); and
      every `:policy`, `:freshness`, `:key`, `:crypto`, `:content`, and
      `:replay` reason of `RequestSeal.verify/3`. An unexpected fault returns
      `:invalid_policy`. Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, message} = RequestSeal.Message.request("GET", "https://crawl.example.org/sitemap.xml", [], nil)
      iex> spec = %{label: "crawl", algorithm: "ed25519", components: ~s[("@method" "@authority" "@path")], expires_in: 60, keyid: "crawler-key", tag: "example-crawl"}
      iex> {:ok, signed} = RequestSeal.sign(message, spec, handle, clock: fn -> 1_700_000_000 end)
      iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
      iex> {:ok, policy} =
      ...>   RequestSeal.Policy.new(%{
      ...>     algorithms: ["ed25519"],
      ...>     components: ~s[("@method" "@authority" "@path")],
      ...>     key_resolver: fn %{keyid: "crawler-key"} -> {:ok, %{algorithm: "ed25519", key: key}} end,
      ...>     freshness: %{clock: fn -> 1_700_000_030 end, max_age: 300, skew: 0, require_expires: true},
      ...>     content: :not_required,
      ...>     replay: :not_required
      ...>   })
      iex> {:ok, {[{"crawl", input}], signatures}} = RequestSeal.Profile.dictionaries(signed, policy.max_signatures)
      iex> stamp = %{name: {:example_crawl, :sitemap_fetch}, revision: 1}
      iex> {:ok, verification} = RequestSeal.Profile.verify_label(signed, policy, "crawl", input, signatures["crawl"], stamp)
      iex> {verification.profile, verification.principal}
      {%{name: {:example_crawl, :sitemap_fetch}, revision: 1}, :unattributed}
      iex> {:error, error} = RequestSeal.Profile.verify_label(signed, policy, "crawl", input, signatures["crawl"], %{name: :rfc9421})
      iex> {error.reason, error.layer}
      {:invalid_profile, :input}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec verify_label(Message.t(), Policy.t(), binary(), Value.t(), Value.t(), stamp()) ::
          {:ok, Verification.t()} | {:error, Error.t()}
  def verify_label(message, policy, label, input, signature, profile) do
    protect(fn ->
      cond do
        not profile?(profile) ->
          error(:invalid_profile, :input)

        not Policy.valid?(policy) ->
          error(:invalid_policy, :input)

        not SignatureFields.label?(label) ->
          error(:invalid_options, :input)

        Message.validate(message) != :ok ->
          error(:invalid_message, :input)

        not signature?(signature) ->
          error(:invalid_signature_field, :fields)

        true ->
          with {:ok, {entries, signatures}} <-
                 Authentication.dictionaries(message, policy.max_signatures),
               {:ok, input} <- selected_member(entries, signatures, label, input, signature) do
            {result, _cache} =
              Authentication.verify_label(
                message,
                policy,
                label,
                input,
                signature,
                %{profile: profile},
                %{}
              )

            case result do
              {:ok, verification, _identity} -> {:ok, verification}
              error -> error
            end
          end
      end
    end)
  end

  defp profile?(%{name: {package, kind}} = profile),
    do:
      not is_struct(profile) and is_atom(package) and is_atom(kind) and
        package not in [:request_seal, :"request-seal", :rfc9421, :web_bot_auth, :"web-bot-auth"] and
        map_size(profile) <= 8 and
        Enum.all?(profile, fn
          {:name, _} -> true
          {key, value} -> is_atom(key) and profile_value?(value)
        end)

  defp profile?(_), do: false

  defp profile_value?(value),
    do:
      is_atom(value) or (is_integer(value) and abs(value) <= 999_999_999_999_999) or
        (is_binary(value) and byte_size(value) <= 256)

  defp selected_member(entries, signatures, label, input, signature) do
    inputs = Map.new(entries)

    cond do
      not Map.has_key?(inputs, label) -> error(:unknown_label, :fields)
      input != inputs[label] -> error(:invalid_signature_input, :fields)
      signature != signatures[label] -> error(:invalid_signature_field, :fields)
      true -> selected_input(input)
    end
  end

  defp selected_input(%Value{} = input) do
    case SignatureFields.inner(input) do
      {:ok, input} -> {:ok, input}
      _ -> error(:invalid_signature_input, :fields)
    end
  end

  defp selected_input(_), do: error(:invalid_signature_input, :fields)

  defp signature?(%Value{type: :item, value: {:bytes, bytes}}),
    do: is_binary(bytes) and byte_size(bytes) in 1..1024

  defp signature?(_), do: false

  defp error(reason, layer), do: {:error, Error.new(reason, layer)}

  defp protect(fun) do
    fun.()
  rescue
    _ -> error(:invalid_policy, :input)
  catch
    _, _ -> error(:invalid_policy, :input)
  end
end
