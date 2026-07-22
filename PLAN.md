# Antigravity Dedicated OAuth Module Implementation Plan

This document outlines a phased, strict **Test-Driven Development (TDD)** plan to integrate the **ANTIGRAVITY OAuth Module** into the `gemini-key-rotator` project.

## Core Architectural Guarantees & Principles

1. **Zero Impact on Gemini CLI**: The existing `gemini-cli` OAuth pipeline (`oauth_credentials`, `oauth_key_states`, `*-oauth` model requests, `/admin/oauth-keys`, etc.) remains **100% untouched and isolated**.
2. **100% Official Antigravity Upstream Protocol**:
   - **Client ID**: `1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com`
   - **Client Secret**: `GOCSPX-K5FWR486LdLJ1mLB8sXC4z6qDAf`
   - **Scopes**:
     - `https://www.googleapis.com/auth/cloud-platform`
     - `https://www.googleapis.com/auth/userinfo.email`
     - `https://www.googleapis.com/auth/userinfo.profile`
     - `https://www.googleapis.com/auth/cclog`
     - `https://www.googleapis.com/auth/experimentsandconfigs`
   - **Headers Sent Upstream**:
     - `User-Agent: antigravity/1.0.5 darwin/arm64`
     - `X-Goog-Api-Client: google-api-nodejs-client/9.15.1`
     - `Client-Metadata: {"ideType":"ANTIGRAVITY"}` (JSON string format)
3. **Database Column Separation**:
   - Dedicated `antigravity_credentials` (TEXT)
   - Dedicated `current_antigravity_index` (INTEGER)
   - Dedicated `antigravity_key_states` (TEXT JSON)
4. **Routing Suffix**:
   - Model requests ending with **`-agy`** (e.g. `gemini-2.5-pro-agy`, `gemini-3.1-pro-preview-agy`) trigger Antigravity OAuth routing.
5. **Admin Console Isolation**:
   - Separate **🚀 Antigravity Keys** tab in Admin Console UI.

---

## Phased Implementation Plan

### Phase 1: Database Migration & Schema Extensions
- **Goal**: Add dedicated Antigravity columns to `api_credentials` in D1 and update TypeScript definitions without affecting `gemini-cli` columns.
- **Steps**:
  - **Step 1.1**: Create `migrations/add_antigravity_columns.sql`.
  - **Step 1.2**: Update `src/types.d.ts` and `src/rotator.ts` type definitions to include `antigravity_credentials`, `current_antigravity_index`, and `antigravity_key_states`.
  - **Step 1.3**: Verify TypeScript compilation and existing tests pass.

### Phase 2: Antigravity Protocol & Header Module (`src/utils/antigravity.ts`)
- **Goal**: Build a dedicated module encapsulating official Antigravity OAuth credentials, headers, request parsing, and model suffix handling (`-agy`).
- **Steps**:
  - **Step 2.1 (Red)**: Create `src/utils/antigravity.test.ts` with unit tests for:
    - Header generation (`getAntigravityHeaders` matching official Antigravity 100%).
    - Credential parsing (`parseAntigravityCredentials`).
    - Model suffix handling (`-agy` stripping).
  - **Step 2.2 (Green)**: Implement `src/utils/antigravity.ts`.
  - **Step 2.3 (Refactor & Verify)**: Run Vitest, verify all unit tests pass, update `PROGRESS.md`.

### Phase 3: Durable Object Isolation & Rotation Pools (`src/rotator.ts` & `src/utils/oauth.ts`)
- **Goal**: Implement independent `antigravityOAuthKeys` rotation pool, independent DO memory caching, independent proactive 12h sync, and independent manual model force-sync handlers in `KeyRotator`.
- **Steps**:
  - **Step 3.1 (Red)**: Add tests in `src/rotator-optimizations.test.ts` / `src/integration.test.ts` for:
    - `-agy` model request routing to the Antigravity pool.
    - Verification that `-agy` requests DO NOT touch `oauth_credentials` / `current_oauth_index`.
    - Verification that Antigravity model sync updates `antigravity_key_states` in D1 without modifying `oauth_key_states`.
  - **Step 3.2 (Green)**: Update `src/rotator.ts` and `src/utils/oauth.ts`:
    - Load `antigravity_credentials` and `antigravity_key_states` separately during DO initialization / `getCachedCredentials`.
    - Route `-agy` model requests through `handleAntigravityCli` using the `antigravityOAuthPool`.
    - Implement `/admin/antigravity-key-models`, `/admin/antigravity-key-diagnose`, and `/admin/antigravity-reset-health`.
  - **Step 3.3 (Verify)**: Run Vitest, verify all tests pass, update `PROGRESS.md`.

### Phase 4: OAuth Exchange Endpoint & Authorize Flow (`src/index.ts`)
- **Goal**: Implement `/api/antigravity/oauth-exchange` and `/api/antigravity/oauth-auth-url` endpoints using Antigravity Client ID, Secret, and Scopes.
- **Steps**:
  - **Step 4.1 (Red)**: Add integration tests in `src/integration.test.ts` for Antigravity OAuth URL generation and token exchange endpoint.
  - **Step 4.2 (Green)**: Implement endpoints in `src/index.ts`.
  - **Step 4.3 (Verify)**: Run Vitest, ensure no regressions on `gemini-cli` `/api/oauth-exchange`, update `PROGRESS.md`.

### Phase 5: Admin Console Dedicated Antigravity Tab UI/UX (`frontend/` & `src/admin.html`)
- **Goal**: Add a dedicated **🚀 Antigravity Keys** tab in the UI, separate from **🔑 OAuth Keys**, allowing users to log in, view keys, run diagnostics, query models, and delete/reset Antigravity credentials.
- **Steps**:
  - **Step 5.1**: Add Antigravity UI HTML layout in `frontend/index.html`.
  - **Step 5.2**: Add Antigravity UI event handlers and rendering logic in `frontend/app.js`.
  - **Step 5.3**: Run `node scripts/build-admin.js` to compile `src/admin.html`.
  - **Step 5.4 (Verify)**: Run test suite to ensure admin panel endpoints and static HTML serving work cleanly. Update `PROGRESS.md`.

### Phase 6: Final Review, Verification & Deployment
- **Goal**: Run the full test suite, apply D1 database migration to remote D1, review `PLAN.md` against implementation for complete accuracy, and execute `npm run deploy`.
- **Steps**:
  - **Step 6.1**: Run `npx vitest run` (100% pass).
  - **Step 6.2**: Execute remote D1 migration (`npx wrangler d1 execute gemini-key-rotator --remote --file=migrations/add_antigravity_columns.sql`).
  - **Step 6.3**: Re-examine `PLAN.md` to confirm zero omissions or errors.
  - **Step 6.4**: Deploy worker via `npm run deploy`.
  - **Step 6.5**: Update `PROGRESS.md` with final deployment status.
