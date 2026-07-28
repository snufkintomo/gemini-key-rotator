# 03 — Extract KeyPool Module & Atomic Rotation State

**What to build:**
A deep `KeyPool` module that encapsulates multi-type key management (Standard API keys, Google OAuth PKCE tokens, Antigravity keys) and rate-limit backoff timers. It handles atomic index rotation directly in Durable Object storage and automatically manages Google OAuth PKCE token refreshes, hiding key health state and rotation mechanics from callers.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] Create `KeyPool` module handling key selection across standard Gemini, OAuth, and Antigravity pools
- [ ] Bind atomic index storage directly to Durable Object `state.storage` (`getStandardIndex`, `getOAuthIndex`, `getAntigravityIndex`)
- [ ] Implement unified 429 rate-limit backoff state machine (8s -> 20s -> 60s)
- [ ] Implement Google OAuth PKCE token auto-refresh lifecycle
- [ ] Add unit tests for rotation order, rate-limit backoffs, and failover selection
