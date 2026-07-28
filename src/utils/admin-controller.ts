/**
 * Deep Module: AdminController
 * Encapsulates Admin Console HTTP endpoints (/admin/*), session cookie authentication,
 * and Cloudflare D1 database CRUD operations.
 */

import { verifyLogin } from './session';

function jsonResponse(data: any, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			'Content-Type': 'application/json',
			'Access-Control-Allow-Origin': '*',
			...headers
		}
	});
}

export class AdminController {
	/**
	 * Verifies Admin session cookie via AES-GCM decryption in session.ts.
	 */
	static async verifySession(request: Request, env: any): Promise<{ valid: boolean; email?: string }> {
		const admin = await verifyLogin(request, env);
		if (!admin) return { valid: false };
		return { valid: true, email: admin.email };
	}

	/**
	 * Main entrypoint for handling /admin/* requests.
	 * Returns Response if handled, or null if not an admin path.
	 */
	static async handleRequest(request: Request, env: any): Promise<Response | null> {
		const requestUrl = new URL(request.url);
		const pathname = requestUrl.pathname;

		if (!pathname.startsWith('/admin')) {
			return null;
		}

		// Public Admin Logout route
		if (pathname === '/admin/logout') {
			const redirectUrl = new URL(request.url).origin + '/admin';
			return new Response(null, {
				status: 302,
				headers: {
					'Location': redirectUrl,
					'Set-Cookie': 'session=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0'
				}
			});
		}

		// Verify Session for Protected Admin API routes (/admin/api/*)
		if (pathname.startsWith('/admin/api')) {
			const session = await this.verifySession(request, env);
			if (!session.valid) {
				return jsonResponse({ error: 'Unauthorized session' }, 401);
			}

			if (pathname === '/admin/api/stats') {
				if (!env.DB) return jsonResponse({ error: 'Database binding missing' }, 500);
				try {
					const totalLogs = await env.DB.prepare('SELECT COUNT(*) as count FROM api_logs').first('count');
					const totalKeys = await env.DB.prepare('SELECT COUNT(*) as count FROM api_credentials').first('count');
					return jsonResponse({ totalLogs, totalKeys, timestamp: Date.now() });
				} catch (e: any) {
					return jsonResponse({ error: e.message }, 500);
				}
			}

			if (pathname === '/admin/api/keys') {
				if (!env.DB) return jsonResponse({ error: 'Database binding missing' }, 500);
				try {
					if (request.method === 'GET') {
						const rows = await env.DB.prepare('SELECT id, access_token, api_keys, oauth_credentials, antigravity_credentials FROM api_credentials').all();
						return jsonResponse({ keys: rows.results || [] });
					}
				} catch (e: any) {
					return jsonResponse({ error: e.message }, 500);
				}
			}

			if (pathname === '/admin/api/logs') {
				if (!env.DB) return jsonResponse({ error: 'Database binding missing' }, 500);
				try {
					const limit = parseInt(requestUrl.searchParams.get('limit') || '50', 10);
					const rows = await env.DB.prepare('SELECT * FROM api_logs ORDER BY timestamp DESC LIMIT ?').bind(limit).all();
					return jsonResponse({ logs: rows.results || [] });
				} catch (e: any) {
					return jsonResponse({ error: e.message }, 500);
				}
			}
		}

		return null;
	}
}
