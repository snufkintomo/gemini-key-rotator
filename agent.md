# Gemini Key Rotator - AI Agent Instructions

Welcome, AI Agent! This file contains the authoritative architecture, safety guidelines, development rules, and deployment instructions for the `gemini-key-rotator` project. You must read and strictly adhere to these guidelines during any development session.

---

## 🚨 CRITICAL DEVELOPMENT & DEPLOYMENT RULE (DO NOT VIOLATE)

### 1. Frontend Asset Bundling Constraint (CRITICAL)
*   **The Architecture**: The Admin Console HTML is served statically by `src/index.ts` by importing `src/admin.html` at compile-time. The `src/admin.html` file is a compiled, single-file bundle generated from the separate source files in the `frontend/` directory (`frontend/app.js`, `frontend/index.html`, and `frontend/styles.css`).
*   **The Issue**: If you modify any files inside the `frontend/` folder, you **MUST** compile them first before deploying. Running `npx wrangler deploy` directly after making frontend changes will upload the old, stale `src/admin.html`, causing your changes to be lost on the live site.
*   **The Rule**:
    *   **To compile**: Run `node scripts/build-admin.js` (or `npm run build-admin`).
    *   **To deploy**: Always run **`npm run deploy`** (which runs the build first, then deploys) instead of calling `wrangler deploy` directly.
    *   **NEVER** run a raw `npx wrangler deploy` after modifying files in the `frontend/` folder without bundling first!

---

## 🛠️ CORE ARCHITECTURAL CONSTRAINTS & PREFERENCES

### 2. OAuth Route Isolation & Gateway Bypass
*   All OAuth-mode requests (streaming and non-streaming) must bypass the Cloudflare AI Gateway completely and route directly to Google's endpoints (`cloudcode-pa.googleapis.com`).
*   Standard API Key requests go to AI Studio (`generativelanguage.googleapis.com`).
*   **DO NOT** automatically cross-route, failover, or fall back between Companion (OAuth) and standard API Key channels. Keep them strictly separate.

### 3. Zero Blocking Database Reads on Worker Hot Path
*   The main proxy Worker (`src/index.ts`) must remain completely stateless and ultra-low-latency.
*   **NO** blocking D1 database metadata reads on the request path. Configuration flags like `enable_logging` and `enable_pruning` are query-cached inside Durable Object memory (`this.cachedCredentials`).
*   Database-bound logging must be delegated asynchronously using `ctx.state.waitUntil` via `writeCombinedLog` to prevent adding write latency to response times.

### 4. Enterprise-Grade Logging Security & Sanitization
*   Any database-bound log must scrub credentials before write. Use `sanitizeHeadersAndUrl` in `src/utils/logger.ts` to automatically mask sensitive headers (`authorization`, `cookie`, `x-access-token`, `x-api-key`, `x-goog-api-key`, `x-rotator-token`) and URL query parameters (`key`, `api_key`, `token`, `access_token`) as `[REDACTED]`.

### 5. Progressive Streaming Failover Timeouts
*   Keep timeout limits responsive: **8 seconds for the first attempt (TTFT)** and **20 seconds for the second attempt**.
*   This ensures cumulative failovers stay strictly under the 30-second gateway limit used by standard client environments (VS Code, Vercel, browsers).

### 6. Diagnostics Model Compatibility
*   Always test OAuth keys using `gemini-3.1-flash-lite` for OAuth test-cases. Do not silent-map under-the-hood or use heavy preview models that might trigger `403 Insufficient Scopes` on personal consumer accounts.

---

## 🧪 TESTING & VERIFICATION FLOW

Before completing any task, you must:
1.  Verify the compilation succeeds: `npm run build-admin`
2.  Run the integration and optimization test suites: `npm run test` (Vitest)
3.  Ensure all tests are passing. Never push code with failing test suites.
