import { describe, it, expect, vi } from 'vitest';
import { CompanionClient } from './companion-client';

describe('CompanionClient', () => {
	it('should generate proper Companion authorization headers', () => {
		const headers = CompanionClient.getCompanionHeaders('test_access_token_123', 'my-project-id');
		expect(headers['Authorization']).toBe('Bearer test_access_token_123');
		expect(headers['X-Goog-User-Project']).toBe('my-project-id');
	});

	it('should execute fetch with endpoint fallback if primary endpoint fails with 503', async () => {
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(new Response(null, { status: 503 })) // Primary fails
			.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 })); // Secondary succeeds

		const res = await CompanionClient.fetchWithEndpointFallback(
			'/v1alpha/test',
			{ method: 'GET' },
			{ fetchFn: mockFetch }
		);

		expect(mockFetch).toHaveBeenCalledTimes(2);
		expect(res.status).toBe(200);
	});

	it('should discover project ID from companion response', async () => {
		const mockFetch = vi.fn().mockResolvedValue(
			new Response(JSON.stringify({
				projects: [{ projectId: 'discovered-project-999' }]
			}), { status: 200 })
		);

		// Override fetch in global
		const originalFetch = globalThis.fetch;
		globalThis.fetch = mockFetch;

		try {
			const project = await CompanionClient.discoverProjectId('mock_token');
			expect(project).toBe('discovered-project-999');
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});
