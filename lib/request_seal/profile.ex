defmodule RequestSeal.Profile do
  @moduledoc """
  Shared HTTP signature pipeline for profiles owned by extension packages.

  This extension surface is unstable; pin RequestSeal exactly.

  An extension selects its source-specific rules, then uses `dictionaries/2` to
  parse paired signature fields, `preflight/4` to check coverage and freshness
  before discovery, and `verify_label/6` to verify its selected dictionary
  member under an explicit `RequestSeal.Policy`. The input and signature values
  come from the same label returned by `dictionaries/2`. Verification re-parses
  the message under the policy's `max_signatures` and checks that both supplied
  values equal that label's entries before resolving a key.

  `verify_label/6` does not accept `:representation` or `:digest_state` options.
  Content checks can use retained message body bytes only; representation
  policies and stream digest states require generic `RequestSeal.verify/3`
  with its validated options.

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
  It does not parse wire binaries. Non-inner lists and malformed structures that
  cannot be inspected return false.

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

  @doc "Parse paired signature dictionaries in encounter order under a member limit."
  @spec dictionaries(Message.t(), pos_integer()) ::
          {:ok, {[{binary(), Value.t()}], %{binary() => Value.t()}}} | {:error, Error.t()}
  def dictionaries(message, max) do
    protect(fn -> Authentication.dictionaries(message, max) end)
  end

  @doc "Check required coverage and freshness before resolving a selected key."
  @spec preflight(Value.t(), binary(), :allow | :reject, :not_evaluated | map()) ::
          {:ok, :not_evaluated | map()} | {:error, Error.t()}
  def preflight(input, components, extra, freshness_policy) do
    protect(fn -> Authentication.preflight(input, components, extra, freshness_policy) end)
  end

  @doc "Verify a selected member under an explicit policy and package-namespaced profile."
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
