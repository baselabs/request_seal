defmodule RequestSeal.Verification do
  @moduledoc """
  Complete facts for one explicitly selected HTTP signature profile.

  Constructed by the generic, core named-profile, and extension profile pipelines
  after their required policy layers succeed. Generic `profile` is
  `%{name: :rfc9421}`; Web Bot Auth uses `%{name: :web_bot_auth, revision: revision}`
  with the exact draft revision. Extension profiles use a package-namespaced
  `{package, kind}` name through `RequestSeal.Profile`. Profile and principal
  stamps are descriptive only. Consumers must allowlist trusted profiles,
  principal kinds, and the code that verifies their source-specific rules;
  an unknown principal kind must never be treated as attributed.

  `signature` records the authoritative resolver algorithm, canonical ordered
  covered identifier strings (including parameters), decoded signature parameter
  map, optional keyid and `crypto: :valid`. It does not retain signature bytes,
  base bytes or keys.

  `content` is `:not_required` or the `RequestSeal.Digest.check/3` result
  (`kind`, `checked`, `bytes`, `unsupported`). `freshness` is `:not_evaluated` or
  a map of `now`, `created`, `expires`, `max_age`, and `skew`. `replay` is
  `:not_required` or a `RequestSeal.Replay.Receipt` after one atomic claim.
  The receipt contains only adapter module and exclusive retention end. Generic `principal` is
  `:unattributed`: generic validity, including HMAC shared-secret possession,
  establishes no trusted identity. Profile implementations own any trusted
  principal attribution and source provenance. Web Bot Auth returns an agent
  principal (`kind: :agent`) with trusted source provenance, or a key principal
  (`kind: :key`) for an explicitly held key.
  `authorization` is always `:not_evaluated`.

  Web Bot Auth supplies an agent association from a trusted source or a held-key thumbprint.
  Default inspection exposes only label, profile, replay, and
  authorization. Explicit access to `signature.parameters` or `signature.keyid`
  can expose sender-supplied sensitive metadata; do not log those maps.
  """
  @derive {Inspect, only: [:label, :profile, :replay, :authorization]}
  defstruct [
    :label,
    :profile,
    :signature,
    :content,
    :freshness,
    replay: :not_required,
    principal: :unattributed,
    authorization: :not_evaluated
  ]

  @type t :: %__MODULE__{
          label: binary(),
          profile: %{required(:name) => atom() | {atom(), atom()}, optional(atom()) => term()},
          signature: map(),
          content: :not_required | map(),
          freshness: :not_evaluated | map(),
          replay: :not_required | RequestSeal.Replay.Receipt.t(),
          principal:
            :unattributed
            | %{required(:kind) => atom() | {atom(), atom()}, optional(atom()) => term()},
          authorization: :not_evaluated
        }
end
