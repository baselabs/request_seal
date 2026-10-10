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

  `RequestSeal.Custody` supplies algorithm-bound `RequestSeal.KeyHandle` capabilities,
  local OTP private-key import, symmetric-secret verification, and an optional
  non-exporting OpenSSH agent signer. Its monitored workers enforce deadlines and
  caller cancellation; public-key resolution and internal key equivalence exclude
  private material. Custody verification establishes mathematical validity only.


  Verification options (unknown and duplicate options reject):

  `:profile` and `:principal` options return `:invalid_profile` at the `:input`
  layer. Named-profile packages use `RequestSeal.Profile` and enforce their own
  source-specific rules; caller options cannot stamp generic verification.

  * `:label` — required case-sensitive Structured Fields dictionary key.
  * `:representation` — optional validated `RequestSeal.Body`, for a required
    representation digest only. No content body substitutes for it.
  * `:digest_state` — optional caller-fed `RequestSeal.Digest` state, matching
    the policy's required kind. Caller establishes EOF; the library never reads
    a stream handle. Mutually exclusive with `:representation`.

  Before the key resolver: options, policy and message validation, both signature
  dictionaries and label pairing, selected label and component/metadata validation,
  the 1,024-byte nonce bound, exact coverage, freshness, then the sender `alg`
  allowlist check when present.
  After the resolver: cross-check sender `alg` against the authoritative algorithm
  (JWS requires absent `alg`), check that algorithm against the policy allowlist,
  build the signature base, verify cryptography, check the content digest, then
  perform required replay commitment and storage.
  Dictionaries are RFC 8941: Signature-Input
  members must be string Inner Lists; Signature members byte sequences at most
  1,024 bytes. Encounters are bounded by policy `:max_signatures` before
  duplicate-label rejection. Repeated parameter names on either dictionary reject
  with `:duplicate_parameter`; other Signature member parameters are ignored
  per Structured Fields;
  duplicate labels reject with `:duplicate_label`, including across field occurrences.
  Composite verification uses `verify_quorum/3` with explicit `RequestSeal.Quorum`.
  Every Signature label must have a matching Signature-Input label.

  The explicit-input form of `sign/4` takes a map with exactly `:label`, `:signature_input` (serialized Inner
  List or `RequestSeal.StructuredFields.Value`), and `:algorithm`, plus an
  `RequestSeal.KeyHandle` or arity-two caller signer `(algorithm, base)` returning
  `{:ok, signature_bytes}` or `{:error, term}`. It appends two caller-provenance header occurrences and
  validates the resulting Message and dictionaries. Existing labels reject.
  Options are `:field_schemas`, default `%{}`, with the same schema rules as Policy,
  and `:signing_timeout` (1–300,000 ms, default 5,000) for custody handles.
  Sign dictionaries have a 16-encounter ceiling and signatures must
  be nonempty and at most 1,024 bytes. HTTP alg must equal the explicit algorithm;
  JWS selection requires no HTTP alg. Signing establishes local construction.

  `sign/4` also accepts `t:signing_spec/0` to generate metadata from `:clock`,
  compute/check content digests, and use bounded custody signing. This is the
  shared Req/Finch signing path; `Message.request/5` and `Message.response/4`
  build lossless messages from ordered headers and exact retained bytes.

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
  Verify one explicit label under a fully explicit generic policy.

  An optional `:identity` member in the resolver result is accepted and used only by quorum verification.
  """
  @spec verify(Message.t(), Policy.t(), keyword()) ::
          {:ok, Verification.t()} | {:error, Error.t()}
  def verify(message, policy, opts), do: Authentication.verify(message, policy, opts)

  @doc """
  Verify explicit signer slots, counting units, bindings, and negotiated requests.

  Each assigned slot, signature label, and merged identity class is unique.
  Every mode fills all required slots; bound slots must be filled and meet their
  nested (both inner dictionary members) or equal, non-nil parameter binding.
  Every assigned signature meets its own complete slot policy; coverage never pools.
  Assignment maximizes counting units, then filled slots, using canonical slot
  and candidate order (challenge labels first), while result lists retain the
  configured slot order. Optional additions preserve a feasible quorum except
  when new evidence bridges identity classes: one label observed under multiple
  identities merges those classes, including the shared unknown pool. A label
  with any known observation survives key-unit filtering; unknown-only labels
  cannot count in a key quorum.

  Bindings inspect alternative verified candidates. Negotiation reads the
  verified, selector-eligible pool after key-unit filtering, so a valid challenge
  can fulfill negotiation without being counted. It appears in `qualifying` and
  `signatures` only when assigned; tampered challenges fail.

  At most 64 × 16 label-slot verifications run. Unbound key, principal, and
  shared-principal role units use polynomial matching; other assignments use
  exact search bounded at 131,072 nodes. Exhaustion returns best-so-far only when
  the mode, required slots, and bindings hold, otherwise `:limit`, layer `:input`.
  Trusted signers populating selector-free bound slots can reach this budget.
  See `RequestSeal.Quorum` for the complete policy contract.
  """
  @spec verify_quorum(Message.t(), RequestSeal.Quorum.t(), keyword()) ::
          {:ok, RequestSeal.Quorum.Verification.t()} | {:error, Error.t()}
  def verify_quorum(message, quorum, opts),
    do: RequestSeal.Quorum.Evaluation.verify(message, quorum, opts)

  @doc """
  Append one signature through caller-owned custody or an arity-two signer.

  A `t:signing_spec/0` requires `:label`, `:algorithm`, serialized `:components`,
  and `:expires_in` (a positive integer of seconds). Defaults are `created: true`,
  `nonce: :random`, `alg: true` (false for JWS algorithm tuples), `keyid: nil`,
  `tag: nil`, `digest: nil`, and `field_schemas: %{}`. Caller clocks range from 0 through 253,402,300,799 Unix seconds. Wire
  `created` and `expires` retain the Structured Fields integer range.
  Req and Finch accept the same defaults through shared signing construction.
  Complete full specs (all parameter keys, digest, and field_schemas) also support
  expires_in nil. The short form requires a positive integer.
  Parameter order is created, expires, nonce, alg, keyid, tag. JWS requires alg false.
  Digest is nil or a unique SHA-256/SHA-512 list. Existing digests are checked
  against retained bytes; covered Content-Length is supplied from those bytes.
  Host and trailer components reject; related-request components need a response.

  Spec options are `:clock` (arity zero, default system seconds),
  `:signing_timeout` (1–300,000 ms, default 5,000), and `:nonce` (optional
  caller-owned 32-byte entropy, encoded as unpadded Base64url when nonce is
  selected). Without that option nonce uses the CSPRNG. Supply fresh entropy on
  every attempt. Spec signers accept a KeyHandle or function; both run through
  custody's monitored deadline/cancellation workers. No framework is required.

  The original three-key specification (`:label`, `:signature_input`,
  `:algorithm`) accepts an algorithm-matching KeyHandle with `:signing_timeout`
  (1–300,000 ms, default 5,000), or the existing synchronous function signer.
  `:field_schemas` defaults to `%{}`. A valid timeout does not wrap or interrupt
  the synchronous function. A handle algorithm mismatch returns
  `:signer_algorithm_mismatch` at `:input`, with message
  `"signer algorithm does not match signature specification"`. Custody failures
  return `:signing_failed` at `:crypto` with a bounded `RequestSeal.Custody.Error` source.
  It never generates metadata. Both forms append ordered signature
  headers and return bounded `RequestSeal.Error` on rejection.

      iex> {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
      iex> {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
      iex> spec = %{label: "sig", algorithm: "ed25519", components: ~s[("@method" "@authority" "@path")], parameters: %{created: true, expires_in: 60, nonce: :random, alg: true, keyid: "example-key", tag: nil}, digest: nil, field_schemas: %{}}
      iex> {:ok, signed} = RequestSeal.sign(message, spec, handle)
      iex> Enum.map(signed.fields, & &1.name)
      ["Signature-Input", "Signature"]
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
