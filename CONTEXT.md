# Domain Context & Architectural Glossary — gemini-key-rotator

This document defines the domain terms, deep module boundaries, and architectural vocabulary for `gemini-key-rotator`.

## Domain Concepts

- **KeyRotator**: The stateful Cloudflare Durable Object responsible for atomic key selection, failover retry loops, and request orchestration.
- **ProtocolAdapter**: A deep translation seam responsible for converting external API protocols (OpenAI, Claude, Antigravity) into native Gemini payloads, and streaming responses back into client-compatible formats.
- **ContextOptimizer**: A deep payload processing module that compresses prompt context (git diffs, ANSI escape codes, expired tool calls) and estimates token usage before sending requests upstream.
- **KeyPool**: A unified credential management module encapsulating standard API keys, Google OAuth tokens, and Antigravity tokens, tracking health state, backoff timers, and atomic rotation indices.
- **TelemetrySink**: A non-blocking telemetry and logging module that sanitizes sensitive credentials, aggregates in-memory usage metrics, and flushes log batches asynchronously to Cloudflare D1.

## Architectural Vocabulary (Codebase Design)

- **Module**: A unit of encapsulation with a well-defined interface and hidden implementation complexity.
- **Interface**: The minimum surface area exposed by a module to its callers.
- **Depth**: The ratio of internal work/complexity to interface complexity. A deep module provides high value behind a simple interface.
- **Seam**: A point of isolation where behavior can be swapped, mocked, or extended without altering callers.
- **Adapter**: A translation layer bridging two distinct interfaces or protocols.
- **Leverage**: The amount of functionality gained per line of interface code.
- **Locality**: Keeping related code and logic together so that changes do not require bouncing across multiple files.
