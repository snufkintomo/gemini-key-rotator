import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KeyRotator, Env } from './rotator';

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
});
