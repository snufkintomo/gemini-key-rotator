# 01 — Extract ContextOptimizer Module & Unit Tests

**What to build:**
A self-contained `ContextOptimizer` module that consolidates all prompt context processing (git diff folding, ANSI code stripping, tool-call dependency pruning, and token estimation) behind a single `optimizePayload()` interface. This allows prompt optimization logic to be executed and tested in pure JavaScript without requiring Cloudflare Worker or Durable Object runtime mocks.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] Create `ContextOptimizer` module unifying git diff folding, ANSI stripping, tool call dependency pruning, and token calculation
- [ ] Ensure tool call dependency pruning preserves tool response associations across 3-pass analysis
- [ ] Provide comprehensive table-driven unit tests covering edge cases in git diff compression and regex parsing
- [ ] Export clean `optimizePayload()` interface ready for consumption by proxy pipeline
