# 05 — Refactor KeyRotator Orchestrator & End-to-End Integration

**What to build:**
Refactor the `KeyRotator` Durable Object class to delegate protocol translation, prompt optimization, key state rotation, and telemetry logging to `ProtocolAdapter`, `ContextOptimizer`, `KeyPool`, and `TelemetrySink`. Removes over 1,500 lines of monolithic code from `KeyRotator`, turning it into a lean state orchestrator verified by end-to-end proxy integration tests.

**Blocked by:** 
- 01 — Extract ContextOptimizer Module & Unit Tests
- 02 — Extract TelemetrySink Module & Non-Blocking Logging
- 03 — Extract KeyPool Module & Atomic Rotation State
- 04 — Extract ProtocolAdapter Seam & Implement Translators

**Status:** ready-for-agent

- [ ] Update `KeyRotator` to use `ProtocolAdapter` for request translation and response streaming
- [ ] Wire `ContextOptimizer` into request pipeline prior to upstream fetch
- [ ] Integrate `KeyPool` for key acquisition, atomic rotation, and 429 retries
- [ ] Replace inline logging calls with `TelemetrySink.recordEvent()`
- [ ] Delete legacy inline protocol branching, regex functions, and key state maps from `KeyRotator`
- [ ] Run full test suite and verify proxy functionality across OpenAI, Claude, Gemini, and Antigravity protocols
