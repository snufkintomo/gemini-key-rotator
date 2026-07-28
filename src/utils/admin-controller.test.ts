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

	it('contract: /admin/api/stats MUST return summary object payload', async () => {
		vi.spyOn(AdminController, 'verifySession').mockResolvedValue({ valid: true });

		const mockDb = {
			prepare: vi.fn().mockReturnValue({
				first: vi.fn().mockResolvedValue(5)
			})
		};

		const req = new Request('https://proxy/admin/api/stats');
		const res = await AdminController.handleRequest(req, { DB: mockDb });
		expect(res?.status).toBe(200);

		const data = await res?.json<any>();
		expect(typeof data).toBe('object');
		expect(Array.isArray(data)).toBe(false);
		expect(data).toHaveProperty('totalLogs');
	});
});
