# 02 — Extract TelemetrySink Module & Non-Blocking Logging

**What to build:**
A standalone `TelemetrySink` module that encapsulates request/response logging, sensitive credential sanitization (redacting access tokens, client secrets, API keys), token usage extraction, and non-blocking Cloudflare D1 batch inserts. Replaces manual sanitization calls in Worker fetch handlers and Durable Object methods with a clean `.recordEvent()` interface.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] Create `TelemetrySink` module exposing `.recordEvent(event)` and `.flush()`
- [ ] Implement inline sanitization for authorization headers, API keys, and OAuth client secrets
- [ ] Implement FIFO in-memory buffering with threshold-based auto-flushing (e.g. 50 items or 30-second interval)
- [ ] Implement non-blocking Cloudflare D1 batch insert execution using background contexts
- [ ] Add unit tests verifying credential redaction and token extraction logic
