# 0030 — Proposed: Capture request bodies through a bounded call that never sends

## Context

Content-Digest verification and signature bases need the exact request body. Plug reads a
body once from the socket, so the bytes have to be captured before any parser consumes
them. `RequestSeal.Plug.Capture` captures and, on rejection, sends a response and halts.
Applications that map errors to their own responses, run inside another framework's
pipeline, or verify after other plugs need a capture that decides nothing about the
response.

## Decision

1. `RequestSeal.Capture.capture/2` returns `{:ok, conn}` or `{:error, reason, conn}`. It
   never sends a response and never halts.
2. The body is captured once and not decoded. Repeated reads share one total byte budget
   and one read deadline.
3. Retained bytes never exceed the limit. Over-read is at most one HTTP/1 read chunk or
   one HTTP/2 DATA frame. A chunk boundary alone proves neither oversize nor
   incompleteness.
4. An oversized or incomplete HTTP/2 stream is cancelled, not drained.
5. Later readers use the captured replay, never the socket.
6. Status mapping belongs to the application. `RequestSeal.Plug.Capture` keeps its sending
   behaviour.

## Consequences

The function is new and additive. It needs protocol tests for HTTP/1 and HTTP/2 under the
real adapters, including cancellation. The contract has not had an independent design
review; this record stays Proposed until it does and the function lands.
