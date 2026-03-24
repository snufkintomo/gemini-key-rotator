import { describe, it, expect, vi } from 'vitest';
import { handleGemini } from './utils/gemini';

describe('Native Gemini Protocol Integration', () => {
    const mockProxyRequest = vi.fn();
    const mockGetNextApiBaseUrl = vi.fn().mockResolvedValue('https://generativelanguage.googleapis.com');
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
        // Clone the request because handleGemini already read it or the mock might be sensitive
        const forwardedBody = await forwardedRequest.clone().json();

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
        const forwardedBody = await forwardedRequest.clone().json();

        expect(forwardedBody.contents[0].parts[1].inline_data.data).toBe(largeFakeImageData);
    });
});
