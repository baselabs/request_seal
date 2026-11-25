# 0034 — Parse canonical signature bases

Status: Accepted.

## Context

Inspecting a signed base requires its exact bytes and the order of its covered components.

## Decision

The parser checks the canonical signature parameter list and matches each line to its
ordered identifier. It accepts precisely the same byte alphabet as the builder.
Rebuilding the parsed result must reproduce the supplied bytes.

## Reasons

Byte equality detects normalization. Using the signature-input validator keeps
recorded identifiers within the same grammar as live verification.

## Consequences

Inspection alone establishes neither message provenance nor signature validity.
The ordered derivation is also available through `SignatureBase.components/3`.
See [RFC 9421 Sections 2.1 and 2.5](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5).

Parse at most 256 component lines and stop on the first excess delimiter.
Apply the verifier's component syntax and nonce bound. Derived component values
must have the form HTTP message validation and derivation would produce.
Checking message context, field schemas, and derived value equality requires
the original message.
Building a base or inspecting derived components rejects a nonce over 1,024
bytes with `:limit`. Low-level signing reports `:signature_base_failed` with
detail `:limit` before asking custody to sign.

Byte-wrapped fields contain a comma-space-delimited sequence of canonical
Base64 items. Validate each item's decoded field bytes and re-encode it
before accepting the retained base.

Ordinary fields use trimmed occurrences separated by a comma and one space.
A final empty occurrence preserves that separator. Structured fields and
dictionary member selections must round-trip through the canonical
Structured Fields serializer. Component names and modifiers use the same
registration rules for construction and validation.
