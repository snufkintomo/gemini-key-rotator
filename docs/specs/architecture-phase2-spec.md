# Phase 2 Architecture Refactoring & System Deepening Specification

## Problem Statement

While Phase 1 succeeded in creating core deep modules (`ContextOptimizer`, `TelemetrySink`, `KeyPool`, `ProtocolAdapter`), three key areas of architectural friction remain:

1. `src/index.ts` remains a 1,100+ line monolith mixing edge HTTP routing, AES-GCM session cookie verification, D1 CRUD database operations, and HTML asset serving for the Admin Console.
2. `KeyRotator.fetch()` in `src/rotator.ts` still contains residual protocol branching and manual payload handling for OpenAI, Claude, Antigravity, and Gemini CLI calls rather than delegating completely to `ProtocolAdapter`.
3. Google Cloud Code Companion API communications (endpoint fallback loops, project discovery, quota retrieval) are duplicated across `src/utils/oauth.ts` and `src/utils/antigravity.ts`.

This friction degrades edge router clarity, leaks database operations into request handlers, and fragments Google Companion API integrations across separate utilities.

## Solution

Complete the architecture deepening through three targeted refactorings:

1. **`AdminController` Seam**: Extract all Admin Console API endpoints (`/admin/stats`, `/admin/keys`, `/admin/logs`, `/admin/oauth`, `/admin/models`), session cookie decryption, and D1 queries into an `AdminController` module behind a clean `adminController.handleRequest(request, env)` interface.
2. **Full `ProtocolAdapter` Integration**: Refactor `KeyRotator.fetch()` to delegate 100% of request translation and response stream formatting to `ProtocolAdapter`, eliminating protocol branching in the Durable Object router.
3. **`CompanionClient` Module**: Consolidate Google Cloud Code Companion API operations, authorization header generation, project ID auto-discovery, and endpoint fallback loops into a deep `CompanionClient` module.

## User Stories

1. As a system administrator accessing the Admin Console, I want my session cookie authenticated securely using AES-GCM encryption, so that administrative endpoints are protected against unauthorized access.
2. As a system administrator managing credentials, I want API keys, Google OAuth tokens, and Antigravity keys saved and fetched through structured controller methods, so that database queries are isolated from the main edge router.
3. As a system administrator viewing proxy statistics, I want real-time model metrics and request history served via dedicated controller endpoints, so that UI rendering is fast and reliable.
4. As an API client sending requests using OpenAI, Claude, or Antigravity format, I want `KeyRotator` to handle my request identically through a single `ProtocolAdapter` seam, so that proxy execution is protocol-agnostic.
5. As a developer adding support for a new LLM provider or protocol, I want to implement the `ProtocolAdapter` interface without modifying `KeyRotator.fetch()`, so that expanding protocol support carries zero risk to existing rotation logic.
6. As a Google OAuth or Antigravity user, I want my project ID auto-discovered and cached during initialization, so that manual project configuration is unnecessary.
7. As a system operator, I want Google Cloud Code Companion API requests to automatically try primary and secondary fallback endpoints when encountering network glitches, so that transient endpoint failures do not impact availability.
8. As a developer writing tests for Admin Console endpoints, I want to invoke `AdminController.handleRequest()` with a mock Request and environment, so that admin features can be unit-tested without spawning full Cloudflare Worker runtimes.
9. As a developer maintaining Google Companion API code, I want endpoint fallback lists and header construction located in a single module, so that updating Google API protocols requires modifying only one file.
10. As an edge Worker developer, I want `src/index.ts` to focus solely on top-level HTTP request dispatching, so that the routing table is readable and easy to audit.

## Implementation Decisions

### 1. `AdminController` Module
- **Seam**: `AdminController.handleRequest(request: Request, env: Env): Promise<Response | null>`
- **Authentication**: Encapsulates session cookie validation and AES-GCM session key decryption.
- **Database Access**: Isolates all D1 database CRUD operations (`SELECT`, `INSERT`, `UPDATE` on `api_credentials` and `api_logs`).
- **Asset Serving**: Serves bundled Admin Console HTML assets and JSON API responses.

### 2. Full `ProtocolAdapter` Integration in `KeyRotator`
- **Orchestration**: `KeyRotator.fetch()` invokes `getProtocolAdapter(mode)` for all inbound requests.
- **Request Pipeline**: Incoming request -> `adapter.translateRequest()` -> `KeyPool.getNextKey()` -> `ContextOptimizer.optimizePayload()` -> Upstream Fetch -> `adapter.translateResponse()` -> `TelemetrySink.recordEvent()`.
- **Simplification**: Deletes protocol-specific `if/switch` blocks from `KeyRotator.fetch()`.

### 3. `CompanionClient` Module
- **Seam**: `CompanionClient` exposing `discoverProjectId(accessToken, email)` and `fetchAvailableModels(accessToken, projectId)`.
- **Fallback Loop**: Encapsulates fallback retries across primary and companion endpoints (`CLOUDCODE_ENDPOINTS`).
- **Header Generation**: Consolidates authentic Antigravity and Google Companion HTTP request headers.

## Testing Decisions

### Good Test Principles
- **Behavior-Driven**: Test external HTTP responses and state outcomes from `AdminController` and `CompanionClient` rather than internal helper states.
- **Pure JS Execution**: Test admin session validation, credential queries, and fallback loops using lightweight mock environments.

### Testing Seams
1. **`AdminController` Seam**:
   - Verified by sending synthetic Requests to `/admin/stats`, `/admin/keys`, and `/admin/oauth` with valid/invalid session cookies, asserting exact status codes and JSON structures.
2. **`CompanionClient` Seam**:
   - Verified by mocking fetch calls across primary and fallback endpoints, asserting that failover retries proceed correctly and project IDs are extracted cleanly.
3. **`KeyRotator` Protocol Pipeline Seam**:
   - Verified by passing OpenAI, Claude, and Gemini requests through `KeyRotator.fetch()` to assert that translation and key selection complete uniformly.

### Prior Art
- Unit test patterns in `src/utils/protocol-adapter.test.ts`, `src/utils/telemetry-sink.test.ts`, and `src/rotator.test.ts`.

## Out of Scope

- Changes to the D1 database table schemas (`api_credentials`, `api_logs`).
- Changes to the Admin Console frontend visual design or CSS styling.
- Upstream Google Gemini or Cloud Code API protocol changes.

## Further Notes

- These three refactorings complete the architecture deepening roadmap, turning `src/index.ts` and `src/rotator.ts` into thin, highly readable routers.
