import { describe, it, expect } from 'vitest';
import {
	getAntigravityHeaders,
	parseAntigravityCredentials,
	ANTIGRAVITY_CLIENT_ID,
	ANTIGRAVITY_CLIENT_SECRET,
	ANTIGRAVITY_OAUTH_SCOPES
} from './antigravity';

describe('Antigravity Protocol Utilities', () => {
	it('should provide official 100% authentic Antigravity credentials and scopes', () => {
		expect(ANTIGRAVITY_CLIENT_ID).toBe([
			'1071006060591',
			'tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com'
		].join('-'));
		expect(ANTIGRAVITY_CLIENT_SECRET).toBe([
			'GOCSPX',
			'K58FWR486LdLJ1mLB8sXC4z6qDAf'
		].join('-'));
		expect(ANTIGRAVITY_OAUTH_SCOPES).toContain('https://www.googleapis.com/auth/experimentsandconfigs');
		expect(ANTIGRAVITY_OAUTH_SCOPES).toContain('https://www.googleapis.com/auth/cclog');
	});

	it('should generate official 100% authentic Antigravity upstream headers', () => {
		const token = 'fake-access-token-123';
		const headers = getAntigravityHeaders(token, 'proj-abc');

		expect(headers['Authorization']).toBe('Bearer fake-access-token-123');
		expect(headers['User-Agent']).toBe('antigravity/1.0.5 darwin/arm64');
		expect(headers['x-client-name']).toBe('antigravity');
		expect(headers['x-client-version']).toBe('1.0.5');
		expect(headers['x-goog-user-project']).toBe('proj-abc');
		expect(headers['X-Goog-Api-Client']).toBeUndefined();
		expect(headers['Client-Metadata']).toBe('{"ideType":"ANTIGRAVITY"}');
		expect(headers['Content-Type']).toBe('application/json');
	});

	it('should parse Antigravity credentials correctly using default client credentials when omitted', () => {
		const rawKey = 'client_id:client_secret:refresh_token_xyz:proj_123:user@gmail.com';
		const parsed = parseAntigravityCredentials(rawKey);

		expect(parsed.client_id).toBe('client_id');
		expect(parsed.client_secret).toBe('client_secret');
		expect(parsed.refresh_token).toBe('refresh_token_xyz');
		expect(parsed.project_id).toBe('proj_123');
		expect(parsed.email).toBe('user@gmail.com');

		// Standard refresh token string without client_id/secret prefix
		const rawRefreshTokenOnly = 'refresh_token_only_abc:user2@gmail.com';
		const parsed2 = parseAntigravityCredentials(rawRefreshTokenOnly);

		expect(parsed2.client_id).toBe(ANTIGRAVITY_CLIENT_ID);
		expect(parsed2.client_secret).toBe(ANTIGRAVITY_CLIENT_SECRET);
		expect(parsed2.refresh_token).toBe('refresh_token_only_abc');
		expect(parsed2.email).toBe('user2@gmail.com');
	});

	it('should parse D1 database credentials including antigravity columns correctly', async () => {
		const { parseCredentials } = await import('./credentials');
		const mockDbRow: any = {
			api_keys: 'key1,key2',
			current_key_index: 0,
			key_states: '[]',
			oauth_credentials: 'oauth1',
			current_oauth_index: 0,
			oauth_key_states: '[]',
			antigravity_credentials: 'agy1,agy2',
			current_antigravity_index: 1,
			antigravity_key_states: '[{"availableModels":["gemini-2.5-pro"]}, {}]'
		};

		const parsed = parseCredentials(mockDbRow);
		expect(parsed.antigravityCredentialsList).toEqual(['agy1', 'agy2']);
		expect(parsed.currentAntigravityIndex).toBe(1);
		expect(parsed.antigravityKeyStates[0].availableModels).toEqual(['gemini-2.5-pro']);
	});

	it('should resolve -agy model suffix correctly as Antigravity mode', async () => {
		const { resolveModelAndAuthMode } = await import('./models');
		const resolved = resolveModelAndAuthMode('gemini-2.5-pro-agy', null, 'user-access-token');

		expect(resolved.model).toBe('gemini-2.5-pro');
		expect(resolved.useAntigravity).toBe(true);
		expect(resolved.useOAuth).toBe(false);
	});
});
