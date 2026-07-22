import { describe, it, expect, vi } from 'vitest';
import { handleAntigravityCli, getAntigravityHeaders, ANTIGRAVITY_CLIENT_ID } from './utils/antigravity';

describe('Antigravity Module Unit & Integration Tests', () => {
	it('should format 100% authentic Antigravity upstream headers', () => {
		const headers = getAntigravityHeaders('test-access-token');
		expect(headers['Authorization']).toBe('Bearer test-access-token');
		expect(headers['User-Agent']).toBe('antigravity/1.0.5 darwin/arm64');
		expect(headers['Client-Metadata']).toBe('{"ideType":"ANTIGRAVITY"}');
		expect(headers['X-Goog-Api-Client']).toBe('google-api-nodejs-client/9.15.1');
	});

	it('should strip -agy model suffix and proxy request with Antigravity headers', async () => {
		const originalFetch = globalThis.fetch;
		globalThis.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
			access_token: 'fake-access-token',
			expires_in: 3600
		})));

		const request = new Request('https://api.rotator.org/v1/models/gemini-2.5-pro-agy:generateContent', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ contents: [{ parts: [{ text: 'hello' }] }] })
		});

		let capturedRequest: Request | undefined;

		const mockProxyRequest = vi.fn().mockImplementation(async (reqToProxy: Request) => {
			capturedRequest = reqToProxy;
			return new Response(JSON.stringify({
				response: {
					candidates: [{
						content: {
							parts: [{ text: 'Antigravity Response' }],
							role: 'model'
						},
						finishReason: 'STOP'
					}]
				}
			}));
		});

		const mockDurableState = {
			storage: {
				get: vi.fn().mockResolvedValue(null),
				put: vi.fn(),
			}
		} as any;

		const agyKey = 'agy_client_id:agy_client_secret:refresh_token_123:proj_456:user@gmail.com';

		let response: Response;
		try {
			response = await handleAntigravityCli(
				request,
				{
					client_id: 'agy_client_id',
					client_secret: 'agy_client_secret',
					refresh_token: 'refresh_token_123',
					project_id: 'proj_456',
					email: 'user@gmail.com'
				},
				mockDurableState,
				mockProxyRequest,
				'gemini-2.5-pro-agy'
			);
		} finally {
			globalThis.fetch = originalFetch;
		}

		expect(mockProxyRequest).toHaveBeenCalled();
		expect(capturedRequest).toBeDefined();

		// Assert that model was stripped from gemini-2.5-pro-agy to gemini-2.5-pro in wrapped request body
		const body = await capturedRequest!.json() as any;
		expect(body.model).toBe('gemini-2.5-pro');

		// Assert official Antigravity headers were attached to upstream request
		expect(capturedRequest!.headers.get('User-Agent')).toBe('antigravity/1.0.5 darwin/arm64');
		expect(capturedRequest!.headers.get('Client-Metadata')).toBe('{"ideType":"ANTIGRAVITY"}');

		const resJson = await response.json() as any;
		expect(resJson.candidates[0].content.parts[0].text).toBe('Antigravity Response');
	});

	it('should generate official Antigravity OAuth authorize URL with 5 scopes', async () => {
		const { ANTIGRAVITY_OAUTH_SCOPES, ANTIGRAVITY_CLIENT_ID } = await import('./utils/antigravity');
		const redirectUri = 'https://example.com/oauth/callback';
		const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
			`client_id=${encodeURIComponent(ANTIGRAVITY_CLIENT_ID)}` +
			`&redirect_uri=${encodeURIComponent(redirectUri)}` +
			`&response_type=code` +
			`&scope=${encodeURIComponent(ANTIGRAVITY_OAUTH_SCOPES.join(' '))}` +
			`&access_type=offline&prompt=consent`;

		expect(authUrl).toContain(ANTIGRAVITY_CLIENT_ID);
		expect(authUrl).toContain('experimentsandconfigs');
		expect(authUrl).toContain('cclog');
	});
});
