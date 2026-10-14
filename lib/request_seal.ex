defmodule RequestSeal do
  @moduledoc """
  HTTP message signatures under explicit caller policy and custody.

  `verify/3` selects exactly one explicitly labeled RFC 9421 signature. It
  returns `RequestSeal.Verification` only after every required policy layer
  passes, or a bounded `RequestSeal.Error`. Construct a `RequestSeal.Policy`
  with six explicit choices; no implicit label, algorithm, profile or trust
  association is selected. Success always reports principal `:unattributed`,
  replay `:not_required` or a `RequestSeal.Replay.Receipt`, and authorization
  `:not_evaluated`. Required replay invokes the caller commitment only after
  validation, then makes one atomic claim through the caller-owned store.
  Composite verification uses `verify_quorum/3` with explicit `RequestSeal.Quorum`.

  `RequestSeal.Custody` supplies algorithm-bound `RequestSeal.KeyHandle` capabilities,
  local OTP private-key import, symmetric-secret verification, and an optional
  non-exporting OpenSSH agent signer. Its monitored workers enforce deadlines and
  caller cancellation; public-key resolution and internal key equivalence exclude
  private material. Custody verification establishes mathematical validity only.

  `sign/4` appends one signature, either from a caller-built Signature-Input
  (`t:signature_spec/0`) or from a `t:signing_spec/0` that generates metadata.
  The spec form is the shared Req/Finch signing path; `Message.request/5` and
  `Message.response/4` build lossless messages from ordered headers and exact
  retained bytes. Signing establishes local construction only.

  Callback exceptions, exits, throws and malformed results reject without
  retaining their text. `RequestSeal.Error` documents every reason and layer;
  all errors are nonretryable, with random correlation tokens. No identity,
  authorization, implicit network fetch or mandatory process is supplied. Explicit
  discovery is available through `RequestSeal.Discovery`. Optional local ETS
  and Postgrex replay adapters start only through explicit caller operations.
  Exact bytes come from `RequestSeal.Message` and `RequestSeal.SignatureBase`.

  See the public architecture, threat model, and technical decisions in the generated guides.
  """
  alias RequestSeal.{Authentication, Error, Message, Policy, Verification}

  @type signature_spec :: %{
          label: binary(),
          signature_input: binary() | RequestSeal.StructuredFields.Value.t(),
          algorithm: RequestSeal.Crypto.algorithm()
        }
  @type signing_spec ::
          %{
            required(:label) => binary(),
            required(:components) => binary(),
            required(:algorithm) => RequestSeal.Crypto.algorithm(),
            required(:expires_in) => pos_integer(),
            optional(:created) => boolean(),
            optional(:nonce) => :random | nil,
            optional(:alg) => boolean(),
            optional(:keyid) => binary() | nil,
            optional(:tag) => binary() | nil,
            optional(:digest) => [binary()] | nil,
            optional(:field_schemas) => map()
          }
          | parameterized_signing_spec()

  @type parameterized_signing_spec :: %{
          required(:label) => binary(),
          required(:components) => binary(),
          required(:algorithm) => RequestSeal.Crypto.algorithm(),
          required(:parameters) => %{
            required(:expires_in) => pos_integer() | nil,
            optional(:created) => boolean(),
            optional(:nonce) => :random | nil,
            optional(:alg) => boolean(),
            optional(:keyid) => binary() | nil,
            optional(:tag) => binary() | nil
          },
          optional(:digest) => [binary()] | nil,
          optional(:field_schemas) => map()
        }

  @doc """
  Verify one explicitly labeled signature under a fully explicit generic policy.

  The message must carry `Signature-Input` and `Signature` fields whose labels
  pair exactly; only the member named by `:label` is verified. Checks run in
  this order. Before the key resolver: options, policy and message validation,
  both signature dictionaries and label pairing, the selected label's
  component and metadata validation, the 1,024-byte nonce bound, required
  coverage, freshness, then the sender `alg` allowlist check when `alg` is
  present. After the resolver: sender `alg` must equal the authoritative
  algorithm (JWS requires `alg` to be absent), that algorithm must be in the
  policy allowlist, then the signature base is built, the cryptography
  verified, the content digest checked, and required replay commitment and
  storage performed.

  Dictionaries are RFC 8941: Signature-Input members must be string Inner
  Lists; Signature members are byte sequences of at most 1,024 bytes.
  Encounters are bounded by policy `:max_signatures` before duplicate-label
  rejection. Repeated parameter names on either dictionary reject with
  `:duplicate_parameter`; other Signature member parameters are ignored per
  Structured Fields. Duplicate labels reject with `:duplicate_label`, including
  across field occurrences. Every Signature label must have a matching
  Signature-Input label, and every Signature-Input label a matching Signature.

  The key resolver result may carry an optional `:identity`. Here it is only
  checked (a public key's derived identity must agree with it, otherwise
  `:key_resolver_failed`); it affects counting only in `verify_quorum/3`.

  ## Parameters

    * `message` - a `RequestSeal.Message`; it is validated before parsing.
    * `policy` - a `RequestSeal.Policy` from `RequestSeal.Policy.new/1`.
      Directly built structs are revalidated and reject with `:invalid_policy`.
    * `opts` - keyword list of the options below. Unknown and duplicate
      options reject with `:invalid_options`.

  ## Options

    * `:label` - required. The case-sensitive Structured Fields dictionary key
      to verify: 1 to 256 bytes, a lowercase letter or `*` followed by
      lowercase letters, digits, `_`, `-`, `.` or `*`.
    * `:representation` - optional validated `RequestSeal.Body`, accepted only
      when the policy requires a representation digest. No content body
      substitutes for it.
    * `:digest_state` - optional caller-fed `RequestSeal.Digest` state whose
      kind matches the policy's required digest kind. The caller establishes
      end of stream; the library never reads a stream handle. Mutually
      exclusive with `:representation`.

  `:profile` and `:principal` options reject with `:invalid_profile`.
  Named-profile packages use `RequestSeal.Profile` and enforce their own
  source-specific rules; caller options cannot stamp generic verification.

  ## Returns

    * `{:ok, %RequestSeal.Verification{}}` - with `profile: %{name: :rfc9421}`,
      `principal: :unattributed`, `authorization: :not_evaluated`, and `replay`
      either `:not_required` or a `RequestSeal.Replay.Receipt`.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return, by layer:
      * `:input` - `:invalid_options`, `:invalid_profile`, `:invalid_policy`,
        `:invalid_message`, `:limit`.
      * `:fields` - `:missing_signature_input`, `:missing_signature`,
        `:invalid_signature_input`, `:invalid_signature_field`,
        `:duplicate_label`, `:duplicate_parameter`, `:label_mismatch`,
        `:unknown_label`.
      * `:policy` - `:missing_required_component`, `:unexpected_component`,
        `:algorithm_not_permitted`, `:algorithm_mismatch`.
      * `:freshness` - `:invalid_clock`, `:missing_created`, `:missing_expires`,
        `:created_in_future`, `:expired`, `:too_old`.
      * `:key` - `:unknown_key`, `:key_resolver_failed`.
      * `:crypto` - `:signature_base_failed` (`detail` is the signature-base
        reason), `:invalid_signature`, `:verifier_failed`.
      * `:content` - `:digest_not_covered`, `:digest_unsupported`,
        `:digest_mismatch`, `:body_unavailable`.
      * `:replay` - `:missing_replay_identifier`, `:retention_exceeded`,
        `:commitment_failed`, `:replayed`, `:store_unavailable`,
        `:store_timeout`, `:store_failed`.

      Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, key} = RequestSeal.PublicKey.import({:ed25519, public}, :raw)
      iex> clock = fn -> 1_700_000_000 end
      iex> {:ok, message} =
      ...>   RequestSeal.Message.request("PUT", "https://docs.example.com/documents/42", [], "draft")
      iex> spec = %{
      ...>   label: "sig",
      ...>   algorithm: "ed25519",
      ...>   components: ~s[("@method" "@authority" "@path")],
      ...>   expires_in: 60,
      ...>   keyid: "docs-key"
      ...> }
      iex> {:ok, signed} = RequestSeal.sign(message, spec, handle, clock: clock)
      iex> {:ok, policy} =
      ...>   RequestSeal.Policy.new(%{
      ...>     algorithms: ["ed25519"],
      ...>     components: ~s[("@method" "@authority" "@path")],
      ...>     key_resolver: fn
      ...>       %{keyid: "docs-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
      ...>       _ -> :error
      ...>     end,
      ...>     freshness: %{clock: clock, max_age: 300, skew: 5, require_expires: true},
      ...>     content: :not_required,
      ...>     replay: :not_required
      ...>   })
      iex> {:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
      iex> {verification.signature.keyid, verification.principal, verification.authorization}
      {"docs-key", :unattributed, :not_evaluated}
      iex> {:error, error} = RequestSeal.verify(%{signed | method: "DELETE"}, policy, label: "sig")
      iex> {error.reason, error.layer}
      {:invalid_signature, :crypto}
      iex> {:error, error} = RequestSeal.verify(signed, policy, label: "other")
      iex> {error.reason, error.layer}
      {:unknown_label, :fields}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec verify(Message.t(), Policy.t(), keyword()) ::
          {:ok, Verification.t()} | {:error, Error.t()}
  def verify(message, policy, opts), do: Authentication.verify(message, policy, opts)

  @doc """
  Verify a composite set of signatures against explicit signer slots.

  Each signature label is verified independently against the policy of every
  slot whose `:label` and `:tag` selectors match it; coverage never pools. The
  verified candidates are then assigned to slots and counted by the quorum's
  unit. Assignment, identity classes, bindings, negotiation, and the search
  budget are specified in `RequestSeal.Quorum`. A label that fails every
  eligible slot is recorded in `nonqualifying`; it rejects the call only under
  `invalid: :reject`.

  ## Parameters

    * `message` - a `RequestSeal.Message`; it is validated before parsing.
    * `quorum` - a `RequestSeal.Quorum` from `RequestSeal.Quorum.new/1`.
      Directly built structs are revalidated and reject with `:invalid_quorum`.
    * `opts` - keyword list with at most the option below. `[]` is valid.

  ## Options

    * `:accept_signature` - list of signature requests from
      `RequestSeal.AcceptSignature.parse/2`, at most 16, each applicable to the
      message kind. Every request must be met by a verified, selector-eligible
      label after key-unit filtering, with the same covered component identity
      set and every requested parameter. Default `[]` (no negotiation).

  ## Returns

    * `{:ok, %RequestSeal.Quorum.Verification{}}` - the assigned slots, unit
      count, per-label results and nonqualifying facts.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return, by layer:
      * `:input` - `:invalid_options`, `:invalid_quorum`, `:invalid_policy`
        (a slot policy requires replay; see `RequestSeal.Quorum`),
        `:invalid_message`, `:limit` (dictionary bounds or an exhausted
        assignment search).
      * `:fields` - `:missing_signature_input`, `:missing_signature`,
        `:invalid_signature_input`, `:invalid_signature_field`,
        `:duplicate_label`, `:duplicate_parameter`, `:label_mismatch`.
      * `:negotiation` - `:invalid_accept_signature`, `:inapplicable_component`,
        `:negotiation_unfulfilled`.
      * `:quorum` - `:unexpected_signature`, `:nonqualifying_signature`
        (`detail` is the label's last failure reason), `:ambiguous_key_identity`,
        `:quorum_not_met`, `:binding_unsatisfied`.

      Failures of individual labels against individual slots are not returned
      directly; they appear in `nonqualifying`. Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {public_a, seed_a} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {public_b, seed_b} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle_a} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed_a})
      iex> {:ok, handle_b} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed_b})
      iex> {:ok, key_a} = RequestSeal.PublicKey.import({:ed25519, public_a}, :raw)
      iex> {:ok, key_b} = RequestSeal.PublicKey.import({:ed25519, public_b}, :raw)
      iex> keys = %{"builder" => key_a, "reviewer" => key_b}
      iex> clock = fn -> 1_700_000_000 end
      iex> {:ok, message} =
      ...>   RequestSeal.Message.request("POST", "https://builds.example/releases", [], "artifact")
      iex> spec = fn label, keyid ->
      ...>   %{
      ...>     label: label,
      ...>     algorithm: "ed25519",
      ...>     components: ~s[("@method" "@path")],
      ...>     expires_in: 60,
      ...>     keyid: keyid
      ...>   }
      ...> end
      iex> {:ok, once} = RequestSeal.sign(message, spec.("build", "builder"), handle_a, clock: clock)
      iex> {:ok, twice} = RequestSeal.sign(once, spec.("review", "reviewer"), handle_b, clock: clock)
      iex> {:ok, policy} =
      ...>   RequestSeal.Policy.new(%{
      ...>     algorithms: ["ed25519"],
      ...>     components: ~s[("@method" "@path")],
      ...>     key_resolver: fn %{keyid: keyid} ->
      ...>       if key = keys[keyid], do: {:ok, %{algorithm: "ed25519", key: key}}, else: :error
      ...>     end,
      ...>     freshness: %{clock: clock, max_age: 300, skew: 0, require_expires: true},
      ...>     content: :not_required,
      ...>     replay: :not_required
      ...>   })
      iex> {:ok, quorum} =
      ...>   RequestSeal.Quorum.new(%{
      ...>     mode: {:threshold, 2},
      ...>     unit: :key,
      ...>     slots: [
      ...>       %{id: :build, policy: policy, required: true, label: "build"},
      ...>       %{id: :review, policy: policy, required: false, label: "review"}
      ...>     ],
      ...>     unexpected: :reject,
      ...>     invalid: :reject
      ...>   })
      iex> {:ok, result} = RequestSeal.verify_quorum(twice, quorum, [])
      iex> {result.satisfied, result.count, result.authorization}
      {[:build, :review], 2, :not_evaluated}
      iex> {:error, error} = RequestSeal.verify_quorum(once, quorum, [])
      iex> {error.reason, error.layer}
      {:quorum_not_met, :quorum}
      iex> RequestSeal.Custody.Local.release(handle_a)
      :ok
      iex> RequestSeal.Custody.Local.release(handle_b)
      :ok
  """
  @spec verify_quorum(Message.t(), RequestSeal.Quorum.t(), keyword()) ::
          {:ok, RequestSeal.Quorum.Verification.t()} | {:error, Error.t()}
  def verify_quorum(message, quorum, opts),
    do: RequestSeal.Quorum.Evaluation.verify(message, quorum, opts)

  @doc """
  Append one signature through caller-owned custody or an arity-two signer.

  `spec` selects one of two forms. A map containing `:components` is a
  `t:signing_spec/0`: metadata is generated from a clock, `Content-Digest` can
  be computed or checked, and both signer kinds run through custody's
  monitored deadline and cancellation workers. Any other map is the explicit
  `t:signature_spec/0`: a caller-built Signature-Input is signed as given and
  no metadata is generated. Both forms append a `Signature-Input` and a
  `Signature` header occurrence with caller provenance, then revalidate the
  message and both dictionaries. No framework is required; Req and Finch
  accept the same spec defaults through this shared signing construction.

  The message's existing signature dictionaries are parsed with a
  16-encounter ceiling; with 16 labels present, signing rejects with `:limit`.
  An existing label rejects with `:label_in_use`. Signatures must be nonempty
  and at most 1,024 bytes.

  ## Parameters

    * `message` - a valid `RequestSeal.Message`.
    * `spec` - a `t:signing_spec/0` or `t:signature_spec/0`, described below.
    * `signer` - a `RequestSeal.KeyHandle` whose algorithm equals the spec's
      `:algorithm`, or an arity-two function `(algorithm, base)` returning
      `{:ok, signature_bytes}` or `{:error, term}`.
    * `opts` - keyword list; the permitted options depend on the form. Unknown
      and duplicate options reject with `:invalid_options`.

  ### Signing spec

  A `t:signing_spec/0` requires `:label`, `:algorithm`, serialized
  `:components` (an Inner List without list parameters), and `:expires_in` (a
  positive integer of seconds, at most 999,999,999,999,999). Defaults are
  `created: true`, `nonce: :random`, `alg: true` (false for JWS algorithm
  tuples), `keyid: nil`, `tag: nil`, `digest: nil`, and `field_schemas: %{}`.
  The parameter keys may also be nested under `:parameters`. A complete spec
  (all six parameter keys under `:parameters`, plus `:digest` and
  `:field_schemas`) also accepts `expires_in: nil`; a non-nil `expires_in`
  requires `created: true`.

  Parameter order is created, expires, nonce, alg, keyid, tag. JWS requires
  `alg: false`. `keyid` and `tag` are printable ASCII of at most 1,024 bytes.
  Caller clocks range from 0 through 253,402,300,799 Unix seconds; wire
  `created` and `expires` retain the Structured Fields integer range.
  `digest` is nil or a unique list of `"sha-256"` and `"sha-512"`. An absent
  `Content-Digest` is computed from the retained body and appended; an existing
  one is checked against the retained bytes and must carry exactly the
  requested algorithms. A covered `content-length` is supplied from the
  retained bytes when absent and must equal it when present. A digest request
  or a covered `content-digest`, `repr-digest`, or `content-length` requires a
  retained body. `host` and trailer (`tr`) components reject; related-request
  (`req`) components need a response.

  ### Explicit signature spec

  A `t:signature_spec/0` has exactly `:label`, `:signature_input` (a
  serialized Inner List or `RequestSeal.StructuredFields.Value`), and
  `:algorithm`. An HTTP `alg` parameter must equal `:algorithm`; JWS selection
  requires no `alg` parameter. A function signer runs synchronously in the
  caller.

  ## Options

  Signing spec:

    * `:clock` - arity-zero function returning integer Unix seconds, read only
      when `created` is true. Default: system time in seconds.
    * `:signing_timeout` - 1 to 300,000 ms for either signer kind. Default 5,000.
    * `:nonce` - 32 bytes of caller-owned entropy, encoded as unpadded
      Base64url when nonce is selected. Without it the nonce uses the CSPRNG.
      Supply fresh entropy on every attempt.

  Explicit signature spec:

    * `:field_schemas` - lowercase field names to `RequestSeal.StructuredFields.Schema`
      values, with the same rules as `RequestSeal.Policy`. Default `%{}`.
    * `:signing_timeout` - 1 to 300,000 ms, applied to a `RequestSeal.KeyHandle`.
      A valid timeout does not wrap or interrupt a function signer. Default 5,000.

  ## Returns

    * `{:ok, %RequestSeal.Message{}}` - the message with the two signature
      header occurrences appended.
    * `{:error, %RequestSeal.Error{}}` - reasons this function can return, by layer:
      * `:input` - `:invalid_options`, `:invalid_message`, `:limit`. Signing
        spec only: `:unsupported_component` (a `host`, trailer, or unavailable
        component), `:invalid_request` (covered `Content-Length` conflicts with
        the retained bytes); a KeyHandle algorithm mismatch is
        `:invalid_options`. Explicit spec only: `:algorithm_mismatch`, and
        `:signer_algorithm_mismatch` for a KeyHandle algorithm mismatch,
        before custody is invoked, with message
        `"signer algorithm does not match signature specification"`.
      * `:fields` - `:label_in_use`, `:label_mismatch`, `:duplicate_label`,
        `:duplicate_parameter`, `:invalid_signature_input`,
        `:invalid_signature_field`.
      * `:content` (signing spec only) - `:body_unavailable`, `:digest_mismatch`.
      * `:crypto` - `:signing_failed` for a failing KeyHandle, with a bounded
        `RequestSeal.Custody.Error` `source`; `:signer_failed` for a failing
        function signer (fault, error, malformed result, empty or oversized
        signature). Explicit spec only: `:signature_base_failed` (`detail` is
        the signature-base reason).

      Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
      iex> spec = %{label: "sig", algorithm: "ed25519", components: ~s[("@method" "@authority" "@path")], parameters: %{created: true, expires_in: 60, nonce: :random, alg: true, keyid: "example-key", tag: nil}, digest: nil, field_schemas: %{}}
      iex> {:ok, signed} = RequestSeal.sign(message, spec, handle)
      iex> Enum.map(signed.fields, & &1.name)
      ["Signature-Input", "Signature"]
      iex> {:error, error} = RequestSeal.sign(signed, spec, handle)
      iex> {error.reason, error.layer}
      {:label_in_use, :fields}
      iex> explicit = %{label: "order", signature_input: ~s[("@method");created=1700000000], algorithm: "hmac-sha256"}
      iex> {:error, error} = RequestSeal.sign(message, explicit, handle)
      iex> {error.reason, error.message}
      {:signer_algorithm_mismatch, "signer algorithm does not match signature specification"}
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec sign(Message.t(), signature_spec(), Policy.signer(), keyword()) ::
          {:ok, Message.t()} | {:error, Error.t()}
  @spec sign(Message.t(), signature_spec(), RequestSeal.KeyHandle.t(), keyword()) ::
          {:ok, Message.t()} | {:error, Error.t()}
  @spec sign(Message.t(), signing_spec(), Policy.signer(), keyword()) ::
          {:ok, Message.t()} | {:error, Error.t()}
  @spec sign(Message.t(), signing_spec(), RequestSeal.KeyHandle.t(), keyword()) ::
          {:ok, Message.t()} | {:error, Error.t()}
  def sign(message, spec, signer, opts \\ [])

  def sign(message, %{components: _} = spec, signer, opts),
    do: RequestSeal.Signing.core_sign(message, spec, signer, opts)

  def sign(message, spec, signer, opts),
    do: Authentication.sign(message, spec, signer, opts)
end
