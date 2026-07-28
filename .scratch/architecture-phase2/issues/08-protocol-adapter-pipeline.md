# 08 — Wire ProtocolAdapter Deeply into KeyRotator.fetch Pipeline

**What to build:**
Refactor `KeyRotator.fetch()` in `src/rotator.ts` to delegate request translation, model mapping, and response stream formatting uniformly through `ProtocolAdapter`. Eliminates residual inline protocol branching (`if (mode === 'openai') ...`) in `KeyRotator.fetch()`, turning `KeyRotator` into a 100% protocol-agnostic orchestrator.

**Blocked by:** Ticket 06, Ticket 07

**Status:** ready-for-agent

- [ ] Refactor `KeyRotator.fetch()` to use `getProtocolAdapter(mode).translateRequest()` for inbound payloads
- [ ] Pipeline upstream fetch execution directly through `adapter.translateResponse()`
- [ ] Remove inline protocol branching and manual stream wrapper logic from `KeyRotator.fetch()`
- [ ] Verify full test suite and end-to-end proxy behavior across OpenAI, Claude, Gemini, and Antigravity protocols
