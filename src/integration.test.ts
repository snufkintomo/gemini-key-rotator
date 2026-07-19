import { describe, it, expect, vi } from 'vitest';
import { handleGemini } from './utils/gemini';

describe('Native Gemini Protocol Integration', () => {
    const mockGetNextApiBaseUrl = vi.fn().mockResolvedValue('https://generativelanguage.googleapis.com');
    const mockProxyRequest = vi.fn();
    const mockState = {} as any;

    it('should correctly pass through tools and tool_config for native function calling', async () => {
        mockProxyRequest.mockClear();
        const tools = [
            {
                function_declarations: [
                    {
                        name: 'get_weather',
                        description: 'Get the current weather',
                        parameters: {
                            type: 'OBJECT',
                            properties: {
                                location: { type: 'STRING' }
                            }
                        }
                    }
                ]
            }
        ];

        const requestBody = {
            contents: [{ parts: [{ text: 'What is the weather in London?' }] }],
            tools: tools,
            tool_config: {
                function_calling_config: { mode: 'ANY' }
            }
        };

        const request = new Request('https://proxy.com/v1beta/models/gemini-pro:generateContent', {
            method: 'POST',
            body: JSON.stringify(requestBody)
        });

        mockProxyRequest.mockResolvedValue(new Response(JSON.stringify({ ok: true })));

        await handleGemini(
            request,
            'test-api-key',
            mockGetNextApiBaseUrl,
            mockProxyRequest,
            mockState
        );

        const lastCall = mockProxyRequest.mock.calls[0];
        const forwardedRequest = lastCall[0];
        const forwardedBody = await forwardedRequest.json();

        expect(forwardedBody.tools).toEqual(tools);
        expect(forwardedBody.tool_config).toEqual(requestBody.tool_config);
    });

    it('should handle large multimodal requests (base64) without data loss', async () => {
        mockProxyRequest.mockClear();
        // Simulate a "large" request with a fake image data
        const largeFakeImageData = 'A'.repeat(1024 * 1024); // 1MB fake image
        const requestBody = {
            contents: [{
                parts: [
                    { text: 'Describe this image' },
                    {
                        inline_data: {
                            mime_type: 'image/jpeg',
                            data: largeFakeImageData
                        }
                    }
                ]
            }]
        };

        const request = new Request('https://proxy.com/v1beta/models/gemini-1.5-flash:generateContent', {
            method: 'POST',
            body: JSON.stringify(requestBody)
        });

        mockProxyRequest.mockResolvedValue(new Response(JSON.stringify({ ok: true })));

        await handleGemini(
            request,
            'test-api-key',
            mockGetNextApiBaseUrl,
            mockProxyRequest,
            mockState
        );

        const lastCall = mockProxyRequest.mock.calls[0];
        const forwardedRequest = lastCall[0];
        const forwardedBody = await forwardedRequest.json();

        expect(forwardedBody.contents[0].parts[1].inline_data.data).toBe(largeFakeImageData);
    });

    it('should ensure all Google outgoing requests use official gemini-cli headers with no ANTIGRAVITY markers', async () => {
        const originalFetch = globalThis.fetch;
        globalThis.fetch = vi.fn().mockImplementation(async (url) => {
            const urlStr = typeof url === 'string' ? url : (url as any).url || '';
            if (urlStr.includes('oauth2.googleapis.com/token')) {
                return new Response(JSON.stringify({
                    access_token: 'fake-access-token',
                    expires_in: 3600,
                    token_type: 'Bearer'
                }), { status: 200 });
            }
            return new Response(JSON.stringify({ ok: true }));
        });

        mockProxyRequest.mockClear();
        const request = new Request('https://proxy.com/v1beta/models/gemini-pro:generateContent', {
            method: 'POST',
            headers: {
                'X-Auth-Mode': 'gemini-cli'
            },
            body: JSON.stringify({
                contents: [{ parts: [{ text: 'hi' }] }]
            })
        });

        mockProxyRequest.mockResolvedValue(new Response(JSON.stringify({ ok: true })));

        const mockDurableState = {
            storage: {
                get: vi.fn().mockResolvedValue(null),
                put: vi.fn(),
            }
        } as any;

        // Since handleGemini will delegate to handleGeminiCli if the mode or key is an OAuth string,
        // we can test the forwarded headers.
        const oauthKey = 'client_id:client_secret:refresh_token:project_id:email@gmail.com';
        try {
            await handleGemini(
                request,
                oauthKey,
                mockGetNextApiBaseUrl,
                mockProxyRequest,
                mockDurableState
            );
        } finally {
            globalThis.fetch = originalFetch;
        }

        const lastCall = mockProxyRequest.mock.calls[0];
        const forwardedRequest = lastCall[0];
        const headers = forwardedRequest.headers;

        // Assert that headers strictly match official gemini-cli values and contain no ANTIGRAVITY markers
        expect(headers.get('User-Agent')).toBe('google-api-nodejs-client/9.15.1');
        expect(headers.get('X-Goog-Api-Client')).toBe('google-api-nodejs-client/9.15.1');
        expect(headers.get('Client-Metadata')).toBe('ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI');
        
        // Ensure absolutely no "antigravity" references exist in any headers or stringified values
        for (const [key, value] of headers.entries()) {
            expect(key.toLowerCase()).not.toContain('antigravity');
            expect(value.toLowerCase()).not.toContain('antigravity');
        }
    });

    it('should ensure all Google outgoing requests successfully strip the -oauth suffix from model names', async () => {
        const originalFetch = globalThis.fetch;
        globalThis.fetch = vi.fn().mockImplementation(async (url) => {
            const urlStr = typeof url === 'string' ? url : (url as any).url || '';
            if (urlStr.includes('oauth2.googleapis.com/token')) {
                return new Response(JSON.stringify({
                    access_token: 'fake-access-token',
                    expires_in: 3600,
                    token_type: 'Bearer'
                }), { status: 200 });
            }
            return new Response(JSON.stringify({ ok: true }));
        });

        mockProxyRequest.mockClear();
        // Model with -oauth suffix
        const request = new Request('https://proxy.com/v1beta/models/gemini-3-flash-preview-oauth:generateContent', {
            method: 'POST',
            body: JSON.stringify({
                contents: [{ parts: [{ text: 'hi' }] }]
            })
        });

        mockProxyRequest.mockResolvedValue(new Response(JSON.stringify({
            response: {
                candidates: [{ content: { parts: [{ text: 'Response' }] } }]
            }
        })));

        const mockDurableState = {
            storage: {
                get: vi.fn().mockResolvedValue(null),
                put: vi.fn(),
            }
        } as any;

        const oauthKey = 'client_id:client_secret:refresh_token:project_id:email@gmail.com';
        try {
            await handleGemini(
                request,
                oauthKey,
                mockGetNextApiBaseUrl,
                mockProxyRequest,
                mockDurableState,
                'gemini-3-flash-preview-oauth'
            );
        } finally {
            globalThis.fetch = originalFetch;
        }

        const lastCall = mockProxyRequest.mock.calls[0];
        const forwardedRequest = lastCall[0];
        const forwardedBody = await forwardedRequest.json();

        // Assert that model name successfully stripped the -oauth suffix before going upstream
        expect(forwardedBody.model).toBe('gemini-3-flash-preview');
    });

    it('should correctly unwrap Google Companion API response wrapper', async () => {
        const originalFetch = globalThis.fetch;
        globalThis.fetch = vi.fn().mockImplementation(async (url) => {
            const urlStr = typeof url === 'string' ? url : (url as any).url || '';
            if (urlStr.includes('oauth2.googleapis.com/token')) {
                return new Response(JSON.stringify({
                    access_token: 'fake-access-token',
                    expires_in: 3600,
                    token_type: 'Bearer'
                }), { status: 200 });
            }
            return new Response(JSON.stringify({ ok: true }));
        });

        mockProxyRequest.mockClear();
        const request = new Request('https://proxy.com/v1beta/models/gemini-3-flash-preview-oauth:generateContent', {
            method: 'POST',
            body: JSON.stringify({
                contents: [{ parts: [{ text: 'hi' }] }]
            })
        });

        // Simulating the Google Companion API wrapped response format
        const companionWrappedResponse = {
            response: {
                candidates: [{
                    content: {
                        parts: [{ text: 'I am Gemini' }],
                        role: 'model'
                    },
                    finishReason: 'STOP',
                    index: 0
                }],
                usageMetadata: {
                    promptTokenCount: 4,
                    candidatesTokenCount: 13,
                    totalTokenCount: 17
                }
            }
        };

        mockProxyRequest.mockResolvedValue(new Response(JSON.stringify(companionWrappedResponse)));

        const mockDurableState = {
            storage: {
                get: vi.fn().mockResolvedValue(null),
                put: vi.fn(),
            }
        } as any;

        const oauthKey = 'client_id:client_secret:refresh_token:project_id:email@gmail.com';
        let response: Response;
        try {
            response = await handleGemini(
                request,
                oauthKey,
                mockGetNextApiBaseUrl,
                mockProxyRequest,
                mockDurableState,
                'gemini-3-flash-preview-oauth'
            );
        } finally {
            globalThis.fetch = originalFetch;
        }

        const resJson = await response.json() as any;

        // Assert that the wrapped response was successfully unwrapped and formatted back to standard Gemini
        expect(resJson.candidates[0].content.parts[0].text).toBe('I am Gemini');
        expect(resJson.usageMetadata.promptTokenCount).toBe(4);
        expect(resJson.usageMetadata.candidatesTokenCount).toBe(13);
    });
});
