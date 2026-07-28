import { describe, it, expect } from 'vitest';
import { AdminController } from './admin-controller';

describe('AdminController', () => {
	it('should return null for non-admin request paths', async () => {
		const req = new Request('https://proxy/v1/chat/completions');
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
});
