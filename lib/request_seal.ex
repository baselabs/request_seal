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

  `sign/4` takes a map with exactly `:label`, `:signature_input` (serialized Inner
  List or `RequestSeal.StructuredFields.Value`), and `:algorithm`, plus an
  arity-two caller signer `(algorithm, base)` returning `{:ok, signature_bytes}`
  or `{:error, term}`. It appends two caller-provenance header occurrences and
  validates the resulting Message and dictionaries. Existing labels reject.
  Its only option is `:field_schemas`, default `%{}`, with the same schema rules
  as Policy. Sign dictionaries have a 16-encounter ceiling and signatures must
  be nonempty and at most 1,024 bytes. HTTP alg must equal the explicit algorithm;
  JWS selection requires no HTTP alg. Signing establishes local construction.

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

  @doc "Append a signature through caller-owned custody; no private key enters the API."
  @spec sign(Message.t(), map(), Policy.signer(), keyword()) ::
          {:ok, Message.t()} | {:error, Error.t()}
  def sign(message, spec, signer, opts \\ []),
    do: Authentication.sign(message, spec, signer, opts)
end
