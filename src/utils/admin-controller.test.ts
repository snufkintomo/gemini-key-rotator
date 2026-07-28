import { describe, it, expect, vi } from 'vitest';
import { AdminController } from './admin-controller';

describe('AdminController Endpoint Contracts', () => {
	it('should return null for non-admin request paths', async () => {
		const req = new Request('https://proxy/v1/chat/completions');
		const res = await AdminController.handleRequest(req, {});
		expect(res).toBeNull();
	});

	it('should return null for /api/* paths so index.ts handles full authenticated routes', async () => {
		const req = new Request('https://proxy/api/credentials');
		const res = await AdminController.handleRequest(req, {});
		expect(res).toBeNull();
	});

	it('should reject unauthenticated requests to protected admin api endpoints', async () => {
		const req = new Request('https://proxy/admin/api/stats');
		const res = await AdminController.handleRequest(req, {});
		expect(res).not.toBeNull();
		expect(res?.status).toBe(401);
		const json = await res?.json<any>();
		expect(json?.error).toContain('Unauthorized');
	});

	it('should process logout requests by clearing session cookies', async () => {
		const req = new Request('https://proxy/admin/logout');
		const res = await AdminController.handleRequest(req, {});
		expect(res?.status).toBe(302);
		expect(res?.headers.get('Set-Cookie')).toContain('Max-Age=0');
	});

	it('contract: /admin/api/logs MUST query api_logs ordered by timestamp column', async () => {
		vi.spyOn(AdminController, 'verifySession').mockResolvedValue({ valid: true });

		let lastQuery = '';
		const mockDb = {
			prepare: vi.fn().mockImplementation((query: string) => {
				lastQuery = query;
				return {
					bind: vi.fn().mockReturnValue({
						all: vi.fn().mockResolvedValue({ results: [{ id: 1, timestamp: '2025-03-09' }] })
					})
				};
			})
		};

		const req = new Request('https://proxy/admin/api/logs');
		const res = await AdminController.handleRequest(req, { DB: mockDb });
		expect(res?.status).toBe(200);
		expect(lastQuery).toContain('timestamp');
		expect(lastQuery).not.toContain('created_at');
	});
});
