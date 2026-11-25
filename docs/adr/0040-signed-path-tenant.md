# 0040 — Bind tenant context to the signed path

Status: Accepted.

## Context

[RFC 9421 Section 2.2.6](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.6)
covers the case-sensitive path bytes. Router parameters alone do not establish
that a tenant selector was covered by the verified signature.

## Decision

After Plug verification, require unparameterized `@path`. Check that the
captured path and Plug's segment split agree. Decode segments once under
[RFC 3986 Section 2.4](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.4)
and refuse empty segments, dot segments, delimiters, and residual escapes.
The caller's template nominates one capture as the tenant. Reject competing
headers, query parameters and fetched body fields. Compare the selected tenant
with the mapping supplied by the caller's trusted principal binding.

Pass the resulting tenant to the existing Ash scope construction. The resource's
multitenancy strategy and policies decide which data operations may proceed.

## Alternatives

Reading merged parameters would allow query or body fields to compete with the
path. A tenant selected solely by the principal could silently override a
different authenticated path.

## Consequences

Apply the plug after Verify and any relevant body parsers. The binding is
specific to one connection and fails closed when repeated or deverified.
