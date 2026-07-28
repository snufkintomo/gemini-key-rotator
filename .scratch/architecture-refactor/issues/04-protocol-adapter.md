# 04 — Extract ProtocolAdapter Seam & Implement Translators

**What to build:**
A unified `ProtocolAdapter` seam containing dedicated adapters for OpenAI (`OpenAIAdapter`), Claude (`ClaudeAdapter`), Gemini (`GeminiAdapter`), and Antigravity (`AntigravityAdapter`). Translates incoming request payloads into normalized Gemini format and transforms upstream response streams into protocol-specific formats using zero-copy `TransformStream` pipelines.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] Create `ProtocolAdapter` interface and factory for OpenAI, Claude, Gemini, and Antigravity protocols
- [ ] Implement request normalization and dynamic model name mapping (e.g. `gpt-4o` -> `gemini-flash-latest`, `claude-3-7-sonnet` -> `gemini-2.5-pro`)
- [ ] Implement response transformation and SSE streaming formatters using zero-copy `TransformStream`
- [ ] Add unit tests verifying request conversion, Claude thinking block mapping, and SSE stream chunk formatting
