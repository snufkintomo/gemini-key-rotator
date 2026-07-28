# 07 — Extract CompanionClient Module & CloudCode Fallback Tests

**What to build:**
A dedicated `CompanionClient` module that consolidates Google Cloud Code Companion API communications, authorization header construction, project ID auto-discovery (`discoverProjectId`), and multi-endpoint fallback loops (`fetchWithEndpointFallback`). Eliminates duplicated CloudCode API calls between `oauth.ts` and `antigravity.ts`.

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] Create `CompanionClient` module encapsulating CloudCode endpoints and fallback loops
- [ ] Implement `discoverProjectId`, `fetchAvailableModels`, and `retrieveUserQuota` methods
- [ ] Unify Antigravity and OAuth Companion HTTP header generation
- [ ] Refactor `oauth.ts` and `antigravity.ts` to delegate Companion API calls to `CompanionClient`
- [ ] Add unit tests for endpoint fallbacks, header formatting, and project discovery
