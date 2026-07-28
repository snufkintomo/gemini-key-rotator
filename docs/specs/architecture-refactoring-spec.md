# Architectural Refactoring & Module Deepening Specification

## Problem Statement

The `gemini-key-rotator` codebase currently suffers from architectural friction due to shallow modules and a monolithic Durable Object (`KeyRotator`). Protocol translation (OpenAI, Claude, Antigravity, Gemini), context optimization (git diff compression, ANSI stripping, tool-call dependency pruning), credential health/rotation tracking, and telemetry/sanitization are mixed together inside a 2,900-line Durable Object file and scattered across multiple utility files. 

This lack of locality and module depth makes it difficult to add new LLM protocols, maintain rate-limiting/rotation rules, test prompt optimization rules in isolation, and navigate or extend the codebase safely.

## Solution

Deepen the architecture by extracting four well-encapsulated, high-leverage modules behind clear seams:

1. **`ProtocolAdapter` Seam**: Unifies all incoming request normalization, model mapping, and response/streaming formatting for OpenAI, Claude, Gemini, and Antigravity protocols.
2. **`ContextOptimizer` Module**: Consolidates git diff folding, ANSI code stripping, tool-call dependency pruning, and token estimation behind a single `optimizePayload` interface.
3. **`KeyPool` Module**: Encapsulates multi-type key storage (Standard API keys, Google OAuth PKCE tokens, Antigravity keys), atomic index management in Durable Object storage, and unified backoff timers.
4. **`TelemetrySink` Module**: Consolidates credential sanitization, token usage extraction, FIFO in-memory buffering, and non-blocking Cloudflare D1 batch flushes.

This refactoring strips protocol parsing and utility management out of `KeyRotator`, turning it into a pure, protocol-agnostic state orchestrator.

## User Stories

1. As an API client sending OpenAI-formatted chat completions, I want my request translated seamlessly to Gemini upstream and streaming responses returned in valid SSE format, so that my existing OpenAI-compatible tools work without modification.
2. As an API client sending Claude-formatted messages with thinking blocks and system prompts, I want my request mapped accurately to Gemini, so that advanced Claude feature sets function correctly through the proxy.
3. As a developer using Git and terminal tooling through the proxy, I want large git diffs folded and ANSI escape sequences stripped automatically from prompt context, so that token usage and cost are minimized without losing critical context.
4. As an API client making tool/function call requests, I want expired or orphan tool calls and responses pruned intelligently, so that the context window remains clean and coherent.
5. As an administrator managing multiple key pools (Standard Gemini keys, Google OAuth tokens, Antigravity credentials), I want rate limits (429s) and backoff cooldowns tracked automatically per key and pool type, so that traffic automatically fails over to healthy keys without service interruption.
6. As a system operator, I want atomic key rotation maintained across concurrent requests for the same token, so that key usage is distributed evenly and concurrency limits are respected.
7. As a security auditor, I want all sensitive credentials (access tokens, client secrets, API keys) sanitized automatically from logs before persistence, so that sensitive data is never stored in plain text.
8. As a developer writing tests for a new LLM protocol adapter, I want to test request/response translation in isolation without instantiating Cloudflare Worker or Durable Object runtime mocks, so that test suites run fast and reliably.
9. As a developer modifying prompt optimization rules, I want to run table-driven tests against `ContextOptimizer` directly, so that edge cases in git diff compression or regex parsing can be verified independently.
10. As a developer adding a new authentication provider or key pool type, I want to implement the `KeyPool` interface without modifying the core request dispatch pipeline in `KeyRotator`, so that extending auth mechanisms is low-risk.
11. As a system maintainer, I want log flushing to Cloudflare D1 performed asynchronously in batches without blocking active proxy response streams, so that proxy latency remains minimal.
12. As an administrator viewing the Admin Console, I want real-time in-memory usage statistics and key health summaries exposed through a clean interface, so that system status is immediately visible.

## Implementation Decisions

### 1. `ProtocolAdapter` Module
- **Seam**: A single unified `ProtocolAdapter` interface exposed to `KeyRotator`.
- **Implementations**: `OpenAIAdapter`, `ClaudeAdapter`, `GeminiAdapter`, `AntigravityAdapter`.
- **Streaming Pipeline**: `translateResponse` returns a zero-copy `TransformStream` for streaming responses, piping transformed chunks directly to the client response stream.
- **Model Mapping**: Protocol adapters normalize incoming model names (e.g. `gpt-4o` -> `gemini-flash-latest`, `claude-3-7-sonnet` -> `gemini-2.5-pro`) before forwarding payloads to `KeyRotator`.

### 2. `ContextOptimizer` Module
- **Seam**: `ContextOptimizer.optimize(contents, options)` returning optimized contents and estimated token counts.
- **Sub-components**: `GitDiffFolder`, `AnsiStripper`, `ToolCallPruner`, `TokenEstimator`.
- **Execution Model**: Asynchronous execution to support both fast-path local regex/AST transformations and optional fallback to remote token counting APIs.
- **Pruning Strategy**: Implements 3-pass dependency graph analysis to ensure tool responses are never detached from their corresponding tool call IDs.

### 3. `KeyPool` Module
- **Seam**: `KeyPool` managing key selection, health state, and atomic index storage.
- **Storage Binding**: Direct integration with Durable Object `state.storage` for atomic index updates (`getStandardIndex`, `getOAuthIndex`, `getAntigravityIndex`).
- **Unified Backoff**: Single backoff state machine managing 429 exponential backoffs (8s -> 20s -> 60s) across all key pools.
- **Token Lifecycles**: Encapsulates PKCE refresh token exchange for Google OAuth and header generation for Antigravity keys.

### 4. `TelemetrySink` Module
- **Seam**: `TelemetrySink.recordEvent(event)` and `flush()`.
- **Sanitization**: Automatic inline redaction of authorization headers, tokens, and secrets prior to buffering.
- **Buffering**: In-memory FIFO queue with threshold-based auto-flushing (e.g., 50 items or 30-second interval) writing to Cloudflare D1 via non-blocking background context (`waitUntil`).

### 5. `KeyRotator` Orchestrator Simplification
- `KeyRotator` becomes a protocol-agnostic orchestrator. Its responsibilities are strictly reduced to:
  1. Receiving incoming HTTP request.
  2. Invoking `ProtocolAdapter.translateRequest()`.
  3. Acquiring healthy key via `KeyPool.getNextKey()`.
  4. Optimizing context via `ContextOptimizer.optimize()`.
  5. Executing upstream HTTP fetch with failover retries on 429/5xx.
  6. Returning translated response via `ProtocolAdapter.translateResponse()`.
  7. Recording telemetry via `TelemetrySink.recordEvent()`.

## Testing Decisions

### Good Test Principles
- **Behavior-Driven**: Tests focus on external module behavior, contract compliance, and inputs/outputs rather than internal state variables or private helper methods.
- **No Heavy Mocks**: Deep modules enable unit tests to run with pure JS/TS objects, eliminating the need to mock complex Cloudflare Worker or Durable Object environments for logic tests.

### Module Seams Under Test
1. **`ProtocolAdapter` Seam**:
   - Tested by feeding raw request payloads (OpenAI JSON, Claude JSON, Antigravity request headers) and asserting normalized Gemini request payloads and stream chunks.
2. **`ContextOptimizer` Seam**:
   - Tested using table-driven test cases containing raw prompt payloads with git diffs, ANSI escape codes, and complex tool call chains, asserting exact output structures and token estimates.
3. **`KeyPool` Seam**:
   - Tested with simulated 429 errors and concurrency calls, asserting proper atomic index increments, backoff timer enforcement, and failover key selection.
4. **`TelemetrySink` Seam**:
   - Tested by recording telemetry events with dummy credentials, asserting that output logs are properly sanitized, token counts are extracted correctly, and batch payloads format as expected for D1 inserts.

### Prior Art
- Existing unit tests in the repository and standard Vitest Cloudflare Worker test patterns.

## Out of Scope

- Changes to the D1 database schema (`api_credentials`, `api_logs`).
- Changes to the Admin Console UI layout or frontend HTML templates.
- Changes to user authentication (`X-Access-Token` validation in `src/index.ts`).
- Upstream Google Gemini API endpoint changes or model behavior shifts.

## Further Notes

- The refactoring can be applied incrementally module by module (e.g., extracting `ContextOptimizer` first, followed by `ProtocolAdapter`, `KeyPool`, and `TelemetrySink`).
- All changes preserve 100% backwards compatibility with existing API clients and environment configurations.
