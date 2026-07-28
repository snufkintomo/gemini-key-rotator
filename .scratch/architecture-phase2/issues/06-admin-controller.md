# 06 — Extract AdminController Module & Admin API Unit Tests

**What to build:**
A self-contained `AdminController` module that encapsulates all Admin Console HTTP endpoints (`/admin/stats`, `/admin/keys`, `/admin/logs`, `/admin/oauth`, `/admin/models`), session cookie decryption, and D1 database CRUD operations. Reduces `src/index.ts` from 1,100+ lines to ~200 lines of clean Worker fetch routing.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] Create `AdminController` module exposing `handleRequest(request, env)`
- [ ] Move AES-GCM session cookie verification and session state handling into `AdminController`
- [ ] Move D1 queries for credentials and logs into `AdminController`
- [ ] Update `src/index.ts` to delegate `/admin/*` requests directly to `AdminController`
- [ ] Add unit tests verifying admin authentication, credential endpoints, and log queries
