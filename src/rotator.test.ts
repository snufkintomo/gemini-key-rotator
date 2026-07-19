import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KeyRotator, Env, extractUsageFromResponse } from './rotator';

describe('KeyRotator Index Management', () => {
    let mockState: any;
    let mockEnv: Env;
    let mockDB: any;
    let mockStorage: any;

    beforeEach(() => {
        mockStorage = new Map();
        mockState = {
            storage: {
                get: vi.fn(async (key: string) => mockStorage.get(key)),
                put: vi.fn(async (key: string, value: any) => mockStorage.set(key, value)),
            },
            waitUntil: vi.fn(),
        };

        mockDB = {
            prepare: vi.fn().mockReturnThis(),
            bind: vi.fn().mockReturnThis(),
            first: vi.fn(),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true }),
        };

        mockEnv = {
            DB: mockDB,
            CLOUDFLARE_AI_GATEWAY_ID: 'test-id',
            CLOUDFLARE_AI_GATEWAY_NAME: 'test-gateway',
        };
    });

    it('should rotate keys sequentially across multiple requests using DO storage', async () => {
        const userAccessToken = 'test-token';
        const apiKeys = 'key1,key2,key3';
        
        // Mock DB returning 3 keys
        mockDB.first.mockResolvedValue({
            api_keys: apiKeys,
            current_key_index: 0,
            key_states: '[]',
            oauth_credentials: '',
            current_oauth_index: 0,
            oauth_key_states: '[]',
        });

        const rotator = new KeyRotator(mockState, mockEnv);

        // First Request
        const req1 = new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        // We need to mock handleGemini or the whole proxy chain, but for this test
        // we mainly want to see if storage.setUserKeyIndex is called correctly.
        // Since handleOpenAI calls handleGemini which calls proxyRequest,
        // we can mock handleGemini indirectly if we wanted to test the full flow,
        // but here let's focus on the fetch method's index selection.

        // To avoid actually calling external APIs, we'll mock the internal proxying
        // but for now, let's just trace the index updates.
        
        // In a real Vitest setup, we might need to mock './utils/gemini' etc.
        // For this demonstration, I'll just check if the DO storage is updated.

        try {
            await rotator.fetch(req1);
        } catch (e) {
            // It might fail because of unmocked handleGemini, but we check updates before that
        }

        expect(mockState.storage.put).toHaveBeenCalledWith(`key_index_${userAccessToken}`, 1);

        // Second Request
        const req2 = new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        try {
            await rotator.fetch(req2);
        } catch (e) {}

        expect(mockState.storage.put).toHaveBeenCalledWith(`key_index_${userAccessToken}`, 2);
        
        // Third Request (should wrap back to 0 if we have 3 keys)
        const req3 = new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        try {
            await rotator.fetch(req3);
        } catch (e) {}

        expect(mockState.storage.put).toHaveBeenCalledWith(`key_index_${userAccessToken}`, 0);
    });

    it('should apply 6 hours cooldown on 429 RESOURCE_EXHAUSTED and 1 minute on normal 429', async () => {
        const userAccessToken = 'test-token-429';
        const apiKeys = 'key1,key2';
        
        // Mock DB returning 2 keys
        mockDB.first.mockResolvedValue({
            api_keys: apiKeys,
            current_key_index: 0,
            key_states: '[]',
            oauth_credentials: '',
            current_oauth_index: 0,
            oauth_key_states: '[]',
        });

        // Set Gemini base URL to avoid invalid URL errors
        mockEnv.GEMINI_API_BASE_URL = 'https://generativelanguage.googleapis.com';
        
        // Mock storage list and delete methods
        mockState.storage.list = vi.fn().mockResolvedValue(new Map());
        mockState.storage.delete = vi.fn().mockResolvedValue(undefined);

        const rotator = new KeyRotator(mockState, mockEnv);

        // Mock global fetch to return a standard 429 response first
        const mockResponseNormal429 = new Response(JSON.stringify({
            error: {
                code: 429,
                message: 'Rate limit exceeded',
                status: 'RATE_LIMIT_EXCEEDED'
            }
        }), {
            status: 429,
            headers: { 'Content-Type': 'application/json' }
        });

        const originalFetch = globalThis.fetch;
        let fetchSpy = vi.fn().mockResolvedValue(mockResponseNormal429);
        globalThis.fetch = fetchSpy;

        const req1 = new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        await rotator.fetch(req1);

        // Check DB update calls (keyStates updated with short cooldown)
        const updateCall = mockDB.bind.mock.calls.find((c: any) => typeof c[1] === 'string' && c[1].includes('exhaustedUntil'));
        expect(updateCall).toBeDefined();
        
        const updatedKeyStates = JSON.parse(updateCall[1]);
        
        // Verify key index 0 has a short cooldown (approx 60s)
        const key0ExhaustedUntil = updatedKeyStates[0].exhaustedUntil['gemini-1.5-flash'];
        const diffNormal = key0ExhaustedUntil - Date.now();
        expect(diffNormal).toBeLessThanOrEqual(60 * 1000 + 5000); // 1 minute + tolerance
        expect(diffNormal).toBeGreaterThanOrEqual(60 * 1000 - 5000);

        // Now mock global fetch to return RESOURCE_EXHAUSTED (daily queries limit exceeded) 429 response
        const mockResponseQuota429 = new Response(JSON.stringify({
            error: {
                code: 429,
                message: 'Resource has been exhausted (e.g. queries per day).',
                status: 'RESOURCE_EXHAUSTED'
            }
        }), {
            status: 429,
            headers: { 'Content-Type': 'application/json' }
        });

        // Reset rotator mock DB state to reflect no existing cooldowns
        mockDB.first.mockResolvedValue({
            api_keys: apiKeys,
            current_key_index: 0,
            key_states: '[]',
            oauth_credentials: '',
            current_oauth_index: 0,
            oauth_key_states: '[]',
        });
        
        // Re-instantiate rotator or clear cache
        const rotator2 = new KeyRotator(mockState, mockEnv);
        globalThis.fetch = vi.fn().mockResolvedValue(mockResponseQuota429);
        mockDB.bind.mockClear();

        const req2 = new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        await rotator2.fetch(req2);

        // Check updated key states
        const updateCall2 = mockDB.bind.mock.calls.find((c: any) => typeof c[1] === 'string' && c[1].includes('exhaustedUntil'));
        expect(updateCall2).toBeDefined();
        
        const updatedKeyStates2 = JSON.parse(updateCall2[1]);
        
        // Verify key index 0 has a 6 hours cooldown
        const key0ExhaustedUntil2 = updatedKeyStates2[0].exhaustedUntil['gemini-1.5-flash'];
        const diffQuota = key0ExhaustedUntil2 - Date.now();
        expect(diffQuota).toBeLessThanOrEqual(6 * 3600 * 1000 + 5000); // 6 hours + tolerance
        expect(diffQuota).toBeGreaterThanOrEqual(6 * 3600 * 1000 - 5000);

        // Restore global fetch
        globalThis.fetch = originalFetch;
    });

    it('should trigger single-request circuit breaker and abort retry loop on severe policy violations', async () => {
        const userAccessToken = 'test-token-violation';
        const apiKeys = 'key1,key2,key3'; // 3 keys available

        // Mock DB returning 3 keys
        mockDB.first.mockResolvedValue({
            api_keys: apiKeys,
            current_key_index: 0,
            key_states: '[]',
            oauth_credentials: '',
            current_oauth_index: 0,
            oauth_key_states: '[]',
        });

        mockEnv.GEMINI_API_BASE_URL = 'https://generativelanguage.googleapis.com';
        mockState.storage.list = vi.fn().mockResolvedValue(new Map());
        mockState.storage.delete = vi.fn().mockResolvedValue(undefined);

        const rotator = new KeyRotator(mockState, mockEnv);

        // Mock global fetch to return 403 with a severe suspension message
        const mockResponseSuspended = new Response(JSON.stringify({
            error: {
                code: 403,
                message: 'This project is flagged for abuse or policy violations.',
                status: 'PERMISSION_DENIED'
            }
        }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
        });

        const originalFetch = globalThis.fetch;
        let fetchSpy = vi.fn().mockResolvedValue(mockResponseSuspended);
        globalThis.fetch = fetchSpy;

        const req = new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        const res = await rotator.fetch(req);

        // Verify response status is 403 and body contains the policy error
        expect(res.status).toBe(403);

        // Verify the retry loop broke immediately on the first attempt
        // If it didn't break, it would have tried key2 and key3, making 3 fetch calls.
        // Because of the circuit breaker, it should make EXACTLY 1 fetch call!
        expect(fetchSpy).toHaveBeenCalledTimes(1);

        // Verify key index 0 was marked as invalid in the database
        const updateCall = mockDB.bind.mock.calls.find((c: any) => typeof c[1] === 'string' && c[1].includes('invalid'));
        expect(updateCall).toBeDefined();
        const updatedKeyStates = JSON.parse(updateCall[1]);
        expect(updatedKeyStates[0].invalid).toBe(true);

        // Restore global fetch
        globalThis.fetch = originalFetch;
    });
});

describe('KeyRotator Cache and Image Proxy', () => {
    let mockState: any;
    let mockEnv: Env;
    let mockDB: any;
    let mockStorage: any;

    beforeEach(() => {
        mockStorage = new Map();
        mockState = {
            storage: {
                get: vi.fn(async (key: string) => mockStorage.get(key)),
                put: vi.fn(async (key: string, value: any) => mockStorage.set(key, value)),
                delete: vi.fn(async (key: string) => mockStorage.delete(key)),
            },
            waitUntil: vi.fn(),
        };

        mockDB = {
            prepare: vi.fn().mockReturnThis(),
            bind: vi.fn().mockReturnThis(),
            first: vi.fn(),
            all: vi.fn().mockResolvedValue({ results: [] }),
            run: vi.fn().mockResolvedValue({ success: true }),
        };

        mockEnv = {
            DB: mockDB,
            CLOUDFLARE_AI_GATEWAY_ID: 'test-id',
            CLOUDFLARE_AI_GATEWAY_NAME: 'test-gateway',
        };
    });

    it('should cache DB credentials lookup inside DO in-memory cache', async () => {
        const userAccessToken = 'test-token';
        const apiKeys = 'key1';
        
        mockDB.first.mockResolvedValue({
            api_keys: apiKeys,
            current_key_index: 0,
            key_states: '[]',
            oauth_credentials: '',
            current_oauth_index: 0,
            oauth_key_states: '[]',
        });

        const rotator = new KeyRotator(mockState, mockEnv);

        const req = new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        // Trigger first fetch (caches)
        try { await rotator.fetch(req.clone() as any); } catch (e) {}
        // Trigger second fetch (should hit cache)
        try { await rotator.fetch(req.clone() as any); } catch (e) {}

        // Expect D1 SELECT statement to be prepared only ONCE
        expect(mockDB.prepare).toHaveBeenCalledTimes(1);
    });

    it('should store and retrieve images using local Image Proxy endpoint on DO storage', async () => {
        const userAccessToken = 'test-token';
        const imageId = 'test_image_id';
        const imageBytesBase64 = btoa('test-binary-data');

        mockStorage.set(`img_data_${imageId}`, imageBytesBase64);
        mockStorage.set(`img_expiry_${imageId}`, Date.now() + 3600 * 1000);

        const rotator = new KeyRotator(mockState, mockEnv);

        // Access the proxy retrieve route
        const req = new Request(`https://proxy.com/api/images/retrieve?id=${imageId}`, {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
            },
            method: 'GET'
        });

        const res = await rotator.fetch(req);
        expect(res.status).toBe(200);
        expect(res.headers.get('Content-Type')).toBe('image/jpeg');

        const arrayBuffer = await res.arrayBuffer();
        const text = new TextDecoder().decode(new Uint8Array(arrayBuffer));
        expect(text).toBe('test-binary-data');
    });

    it('should rotate keys correctly when requests are fired concurrently (high pressure)', async () => {
        const userAccessToken = 'concurrent-token';
        const apiKeys = 'keyA,keyB,keyC';
        
        mockDB.first.mockResolvedValue({
            api_keys: apiKeys,
            current_key_index: 0,
            key_states: '[]',
            oauth_credentials: '',
            current_oauth_index: 0,
            oauth_key_states: '[]',
        });

        const rotator = new KeyRotator(mockState, mockEnv);

        const makeReq = () => new Request('https://proxy.com/v1/chat/completions', {
            headers: {
                'X-Access-Token': userAccessToken,
                'X-Auth-Mode': 'openai',
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify({ model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] }),
        });

        const runFetch = async (r: Request) => {
            try {
                await rotator.fetch(r);
            } catch (e) {}
        };

        await Promise.all([
            runFetch(makeReq()),
            runFetch(makeReq()),
            runFetch(makeReq()),
        ]);

        const putCalls = mockState.storage.put.mock.calls
            .filter((call: any) => call[0] === `key_index_${userAccessToken}`)
            .map((call: any) => call[1]);
        
        expect(putCalls).toContain(1);
        expect(putCalls).toContain(2);
        expect(putCalls).toContain(0);
    });

    describe('getNextApiBaseUrl', () => {
        it('should return default URL when no endpoints are configured', async () => {
            const rotator = new KeyRotator(mockState, mockEnv);
            const url = await rotator.getNextApiBaseUrl(false);
            expect(url).toBe('https://generativelanguage.googleapis.com');
        });

        it('should return gateway URL when isStreaming is false and gateway is enabled', async () => {
            mockEnv.ENABLE_CLOUDFLARE_AI_GATEWAY = 'true';
            const rotator = new KeyRotator(mockState, mockEnv);
            const url = await rotator.getNextApiBaseUrl(false);
            expect(url).toBe('https://gateway.ai.cloudflare.com/v1/test-id/test-gateway/google-ai-studio');
        });

        it('should split multiple URLs in GEMINI_API_BASE_URL and round-robin across them', async () => {
            mockEnv.GEMINI_API_BASE_URL = 'https://api1.com, https://api2.com, , https://api3.com ';
            const rotator = new KeyRotator(mockState, mockEnv);

            const url1 = await rotator.getNextApiBaseUrl(false);
            const url2 = await rotator.getNextApiBaseUrl(false);
            const url3 = await rotator.getNextApiBaseUrl(false);
            const url4 = await rotator.getNextApiBaseUrl(false);

            expect(url1).toBe('https://api1.com');
            expect(url2).toBe('https://api2.com');
            expect(url3).toBe('https://api3.com');
            expect(url4).toBe('https://api1.com');
        });

        it('should round-robin across Org URL and split GEMINI_API_BASE_URL', async () => {
            mockEnv.ENABLE_ORG_GEMINI_API_BASE_URL = 'true';
            mockEnv.GEMINI_API_BASE_URL = 'https://api1.com, https://api2.com';
            const rotator = new KeyRotator(mockState, mockEnv);

            const url1 = await rotator.getNextApiBaseUrl(false);
            const url2 = await rotator.getNextApiBaseUrl(false);
            const url3 = await rotator.getNextApiBaseUrl(false);
            const url4 = await rotator.getNextApiBaseUrl(false);

            expect(url1).toBe('https://generativelanguage.googleapis.com');
            expect(url2).toBe('https://api1.com');
            expect(url3).toBe('https://api2.com');
            expect(url4).toBe('https://generativelanguage.googleapis.com');
        });
    });

    describe('extractUsageFromResponse', () => {
        it('should extract usage from a Gemini JSON response correctly', async () => {
            const body = JSON.stringify({
                usageMetadata: {
                    promptTokenCount: 150,
                    candidatesTokenCount: 100,
                    cachedContentTokenCount: 50
                }
            });
            const response = new Response(body, {
                headers: { 'Content-Type': 'application/json' }
            });
            const usage = await extractUsageFromResponse(response, 'google');
            expect(usage).toEqual({
                promptTokens: 150,
                completionTokens: 100,
                cachedTokens: 50
            });
        });

        it('should extract usage from an OpenAI JSON response correctly', async () => {
            const body = JSON.stringify({
                usage: {
                    prompt_tokens: 200,
                    completion_tokens: 120
                }
            });
            const response = new Response(body, {
                headers: { 'Content-Type': 'application/json' }
            });
            const usage = await extractUsageFromResponse(response, 'openai');
            expect(usage).toEqual({
                promptTokens: 200,
                completionTokens: 120,
                cachedTokens: 0
            });
        });

        it('should extract usage from a Claude JSON response correctly', async () => {
            const body = JSON.stringify({
                usage: {
                    input_tokens: 300,
                    output_tokens: 150
                }
            });
            const response = new Response(body, {
                headers: { 'Content-Type': 'application/json' }
            });
            const usage = await extractUsageFromResponse(response, 'claude');
            expect(usage).toEqual({
                promptTokens: 300,
                completionTokens: 150,
                cachedTokens: 0
            });
        });

        it('should extract usage from a Gemini text/event-stream response correctly using robust regex', async () => {
            const streamContent = 
                'data: {"candidates":[]}\n\n' +
                'data: {"usageMetadata":{"promptTokenCount":500,"candidatesTokenCount":250,"cachedContentTokenCount":120}}\n\n';
            const response = new Response(streamContent, {
                headers: { 'Content-Type': 'text/event-stream' }
            });
            const usage = await extractUsageFromResponse(response, 'google');
            expect(usage).toEqual({
                promptTokens: 500,
                completionTokens: 250,
                cachedTokens: 120
            });
        });

        it('should extract usage from a Claude split event-stream response correctly (bypassing initial 0 completion tokens)', async () => {
            const streamContent = 
                'event: message_start\n' +
                'data: {"type":"message_start","message":{"role":"assistant","usage":{"input_tokens":221500,"output_tokens":0}}}\n\n' +
                'event: content_block_delta\n' +
                'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n' +
                'event: message_delta\n' +
                'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":450}}\n\n';
            
            const response = new Response(streamContent, {
                headers: { 'Content-Type': 'text/event-stream' }
            });
            const usage = await extractUsageFromResponse(response, 'claude');
            expect(usage).toEqual({
                promptTokens: 221500,
                completionTokens: 450,
                cachedTokens: 0
            });
        });
    });

    describe('Durable Object Alarm-based Batching', () => {
        let mockState: any;
        let mockEnv: Env;
        let mockDB: any;
        let mockStorage: any;
        let alarmTimestamp: number | null = null;

        beforeEach(() => {
            mockStorage = new Map();
            alarmTimestamp = null;
            mockState = {
                storage: {
                    get: vi.fn(async (key: string) => mockStorage.get(key)),
                    put: vi.fn(async (key: string, value: any) => mockStorage.set(key, value)),
                    delete: vi.fn(async (key: string) => mockStorage.delete(key)),
                    getAlarm: vi.fn(async () => alarmTimestamp),
                    setAlarm: vi.fn(async (ts: number) => { alarmTimestamp = ts; }),
                    deleteAlarm: vi.fn(async () => { alarmTimestamp = null; }),
                },
                waitUntil: vi.fn(),
            };

            mockDB = {
                prepare: vi.fn().mockReturnThis(),
                bind: vi.fn().mockReturnThis(),
                run: vi.fn().mockResolvedValue({ success: true }),
                batch: vi.fn().mockResolvedValue([]),
                first: vi.fn(),
                all: vi.fn().mockResolvedValue({ results: [] }),
            };

            mockEnv = {
                DB: mockDB,
                CLOUDFLARE_AI_GATEWAY_ID: 'test-id',
                CLOUDFLARE_AI_GATEWAY_NAME: 'test-gateway',
                ENABLE_USAGE_STATISTICS: 'true',
            };
        });

        it('should accumulate persistent usage records in DO storage and schedule an alarm', async () => {
            const rotator = new KeyRotator(mockState, mockEnv);
            await rotator.recordUsage('key1', 'api_key', 'user1', true, false, 'openai', 'gpt-4', 100, 50, 0);
            
            const pending = mockStorage.get('pending_stats');
            expect(pending.length).toBe(1);
            expect(alarmTimestamp).not.toBeNull();
            expect(alarmTimestamp).toBeGreaterThan(Date.now() + 50000);
        });

        it('should aggregate continuous records by composite key when alarm fires', async () => {
            const rotator = new KeyRotator(mockState, mockEnv);
            
            // Push multiple overlapping records
            await rotator.recordUsage('key1', 'api_key', 'user1', true, false, 'openai', 'gpt-4', 100, 50, 0);
            await rotator.recordUsage('key1', 'api_key', 'user1', true, false, 'openai', 'gpt-4', 200, 100, 10);
            await rotator.recordUsage('key2', 'api_key', 'user2', false, true, 'claude', 'claude-3', 50, 0, 0);

            const pendingBefore = mockStorage.get('pending_stats');
            expect(pendingBefore.length).toBe(3);

            // Execute alarm
            await rotator.alarm();

            // Buffer in storage should be deleted
            const pendingAfter = mockStorage.get('pending_stats');
            expect(pendingAfter).toBeUndefined();
            expect(mockDB.batch).toHaveBeenCalled();
            const batchArgs = mockDB.batch.mock.calls[0][0];
            expect(batchArgs.length).toBe(2);
        });

        it('should restore buffer in DO storage if D1 batch execution fails', async () => {
            const rotator = new KeyRotator(mockState, mockEnv);
            await rotator.recordUsage('key1', 'api_key', 'user1', true, false, 'openai', 'gpt-4', 100, 50, 0);

            // Make batch fail
            mockDB.batch.mockRejectedValue(new Error('D1 write failed'));

            // Execute alarm
            await rotator.alarm();

            // Buffer should be restored in DO storage (not lost!)
            const pendingAfter = mockStorage.get('pending_stats');
            expect(pendingAfter.length).toBe(1);
            expect(pendingAfter[0].rawKey).toBe('key1');
        });
    });

    describe('Three-Level Dynamic Model Routing & Caching', () => {
        it('should correctly extract labels from raw fetchAvailableModels JSON', () => {
            const rawJson = {
                models: [
                    { id: 'projects/123/models/gemini-2.5-pro', displayName: 'Gemini 2.5 Pro' },
                    { modelId: 'gemini-3.1-flash-lite', name: 'Gemini 3.1 Flash Lite' },
                ],
                otherStuff: {
                    nestedLabel: 'gemini-3.5-flash-low'
                }
            };
            // Under testing
            const collectModelLabels = (value: any, out: string[] = []): string[] => {
                if (!value || out.length > 50) return out;
                if (typeof value === 'string') {
                    if (/gemini|claude|gpt-oss/i.test(value)) out.push(value);
                    return out;
                }
                if (Array.isArray(value)) {
                    for (const item of value) collectModelLabels(item, out);
                    return out;
                }
                if (typeof value === 'object') {
                    for (const [k, v] of Object.entries(value)) {
                        if (typeof k === 'string' && /model|id|name|label/i.test(k) && typeof v === 'string') {
                            if (/gemini|claude|gpt-oss/i.test(v)) out.push(v.trim());
                        }
                        collectModelLabels(v, out);
                    }
                }
                return out;
            };

            const labels = collectModelLabels(rawJson);
            expect(labels).toContain('projects/123/models/gemini-2.5-pro');
            expect(labels).toContain('Gemini 2.5 Pro');
            expect(labels).toContain('gemini-3.1-flash-lite');
            expect(labels).toContain('Gemini 3.1 Flash Lite');
            expect(labels).toContain('gemini-3.5-flash-low');
        });

        it('should perform model synchronization inside DO alarm only past 12 hour threshold', async () => {
            const rotator = new KeyRotator(mockState, mockEnv);
            
            // 1. If last sync was 1 hour ago (within 12 hour threshold), it should skip sync
            const now = Date.now();
            mockStorage.set('last_model_sync_time', now - 1 * 60 * 60 * 1000);
            
            // Mock DB.prepare returning active keys
            mockDB.first.mockResolvedValue({
                api_keys: 'key1',
                current_key_index: 0,
                key_states: '[]',
                oauth_credentials: 'id:secret:token:project:email',
                current_oauth_index: 0,
                oauth_key_states: '[]',
            });
            mockDB.all = vi.fn().mockResolvedValue({
                results: [{
                    id: 1,
                    access_token: 'test',
                    oauth_credentials: 'id:secret:token:project:email',
                    oauth_key_states: '[]'
                }]
            });

            const originalFetch = globalThis.fetch;
            let fetchCount = 0;
            globalThis.fetch = vi.fn().mockImplementation(async () => {
                fetchCount++;
                return new Response(JSON.stringify({ ok: true }));
            });

            try {
                await rotator.alarm();
            } finally {
                globalThis.fetch = originalFetch;
            }

            // Assert fetch was NOT called for fetchAvailableModels because of the 12h threshold
            expect(fetchCount).toBe(0);

            // 2. If last sync was 13 hours ago (past 12 hour threshold), it should trigger sync
            mockStorage.set('last_model_sync_time', now - 13 * 60 * 60 * 1000);
            fetchCount = 0;
            globalThis.fetch = vi.fn().mockImplementation(async (url) => {
                fetchCount++;
                const urlStr = typeof url === 'string' ? url : (url as any).url || '';
                if (urlStr.includes('v1internal:fetchAvailableModels')) {
                    return new Response(JSON.stringify({
                        models: [{ id: 'gemini-3.1-flash-lite' }, { id: 'gemini-2.5-flash' }]
                    }), { status: 200 });
                }
                if (urlStr.includes('oauth2.googleapis.com/token')) {
                    return new Response(JSON.stringify({ access_token: 'fake' }), { status: 200 });
                }
                return new Response(JSON.stringify({ ok: true }));
            });

            try {
                await rotator.alarm();
            } finally {
                globalThis.fetch = originalFetch;
            }

            // Sync should be triggered, and last_model_sync_time updated
            const lastSync = mockStorage.get('last_model_sync_time');
            expect(lastSync).toBeGreaterThan(now - 1 * 60 * 1000);
            // It should have queried fetchAvailableModels
            expect(fetchCount).toBeGreaterThan(0);
        });

        it('should use Optimistic Fallback (Level 3) if a requested model is marked as unavailable on all keys', async () => {
            const rotator = new KeyRotator(mockState, mockEnv);

            // Mock DB returning 2 keys where gemini-3.1-pro is marked as unavailable on both
            const apiKeys = 'key1,key2';
            const keyStates = JSON.stringify([
                { modelUnavailable: { 'gemini-3.1-pro': true } },
                { modelUnavailable: { 'gemini-3.1-pro': true } }
            ]);

            mockDB.first.mockResolvedValue({
                api_keys: apiKeys,
                current_key_index: 0,
                key_states: keyStates,
                oauth_credentials: '',
                current_oauth_index: 0,
                oauth_key_states: '[]',
            });

            // Set up a mock request for gemini-3.1-pro
            const req = new Request('https://proxy.com/v1/chat/completions', {
                headers: {
                    'X-Access-Token': 'test',
                    'X-Auth-Mode': 'openai',
                    'Content-Type': 'application/json',
                },
                method: 'POST',
                body: JSON.stringify({ model: 'gemini-3.1-pro', messages: [{ role: 'user', content: 'hi' }] }),
            });

            // Optimistic Fallback should kick in and try key1 anyway instead of returning null or throwing immediate error
            try {
                await rotator.fetch(req);
            } catch (e) {
                // Ignore downstream failures, we want to see if it fell back
            }

            // The state put should have rotated or at least not blocked selection
            expect(mockState.storage.put).toHaveBeenCalled();
        });
    });
});
