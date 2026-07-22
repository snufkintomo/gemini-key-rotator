/// <reference path="./types.d.ts" />
import adminHtml from './admin.html';
import loginHtml from './login.html';
import * as cookie from 'cookie';
import { KeyRotator } from './rotator';
import { sanitizeLogBody } from './utils/sanitize';
import { sendZeroSuccessRateAlertEmail } from './utils/email';
import { generatePKCE, getDerivedKey, verifyLogin } from './utils/session';
import { logRequest, logResponse, writeCombinedLog } from './utils/logger';
import { discoverProjectId } from './utils/oauth';
import { ANTIGRAVITY_CLIENT_ID, ANTIGRAVITY_CLIENT_SECRET } from './utils/antigravity';

// --- Types ---
export interface Env {
  DB: D1Database;
  GEMINI_API_BASE_URL?: string;
  ADMIN_ACCESS_TOKEN?: string; // Legacy single-token auth
  OAUTH_CLIENT_ID?: string;
  OAUTH_CLIENT_SECRET?: string;
  ADMIN_OAUTH_CLIENT_ID?: string;
  ADMIN_OAUTH_CLIENT_SECRET?: string;
  KEY_ROTATOR: DurableObjectNamespace;
  ENABLE_API_LOGGING?: string;
  RESEND_API_KEY?: string;
  NOTIFICATION_EMAIL?: string;
}

export interface Admin {
  id: number;
  email: string;
  role: 'super_admin' | 'admin';
}

// --- Cloudflare Worker Entry Point ---
export default {
  async scheduled(event: any, env: Env, ctx: any) {
    // Daily cleanup: Delete statistics older than 30 days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 30);
    const cutoffStr = cutoffDate.toLocaleDateString('en-CA', { timeZone: 'Asia/Hong_Kong' });

    try {
      const stmt = env.DB.prepare('DELETE FROM api_key_usage WHERE usage_date < ?');
      const { meta } = await stmt.bind(cutoffStr).run();
      console.log(`Auto-cleanup: Deleted ${meta.changes} statistics entries older than ${cutoffStr}`);
    } catch (e) {
      console.error('Auto-cleanup failed:', e);
    }

    // Daily cleanup: Delete api_logs older than 14 days
    const logCutoffDate = new Date();
    logCutoffDate.setDate(logCutoffDate.getDate() - 14);
    const logCutoffStr = logCutoffDate.toISOString();

    try {
      const stmt = env.DB.prepare('DELETE FROM api_logs WHERE timestamp < ?');
      const { meta } = await stmt.bind(logCutoffStr).run();
      console.log(`Auto-cleanup: Deleted ${meta.changes} log entries older than ${logCutoffStr}`);
    } catch (e) {
      console.error('Auto-cleanup of logs failed:', e);
    }

    // Check for keys with 0% success over the last 7 days and send email notification
    if (env.RESEND_API_KEY && env.NOTIFICATION_EMAIL) {
      try {
        const query = `
          SELECT raw_key, key_type, SUM(request_count) as total_req, SUM(success_count) as total_success, user_access_token, model
          FROM api_key_usage
          WHERE usage_date >= date('now', '-7 days')
          GROUP BY raw_key, key_type, user_access_token, model
          HAVING total_req >= 10 AND total_success = 0
        `;
        const result = await env.DB.prepare(query).all();
        if (result.results && result.results.length > 0) {
          const failedKeys = result.results.map((row: any) => ({
            rawKey: row.raw_key,
            keyType: row.key_type,
            totalRequests: row.total_req,
            model: row.model,
            userToken: row.user_access_token,
          }));
          await sendZeroSuccessRateAlertEmail(env.RESEND_API_KEY, env.NOTIFICATION_EMAIL, failedKeys);
          console.log(`Auto-cleanup: Sent 0% success rate alert email for ${failedKeys.length} items`);
        }
      } catch (e) {
        console.error('Failed to run 0% success rate email alert check:', e);
      }
    }
  },

  async fetch(
    request: Request,
    env: Env,
    ctx: any
  ): Promise<Response> {
    const requestUrl = new URL(request.url);

    // --- Public Route: Retrieve Generated Images (No login required) ---
    if (requestUrl.pathname === '/api/images/retrieve') {
        const id = requestUrl.searchParams.get('id');
        const token = requestUrl.searchParams.get('token');
        if (!id || !token) {
            return new Response('Missing parameters', { status: 400 });
        }

        const stubId = env.KEY_ROTATOR.idFromName(token);
        const stub = env.KEY_ROTATOR.get(stubId, { locationHint: 'wnam' });

        const forwardRequest = new Request(request.url, request);
        forwardRequest.headers.set('X-Access-Token', token);
        forwardRequest.headers.set('X-Auth-Mode', 'google'); // Placeholder mode

        return await stub.fetch(forwardRequest);
    }

    // --- Admin Login Routes ---
    if (requestUrl.pathname === '/admin/google-login') {
        const clientId = env.ADMIN_OAUTH_CLIENT_ID;
        if (!clientId) return jsonResponse({ error: "Admin OAuth not configured" }, 500);

        const redirectUri = new URL(request.url).origin + "/admin/google-callback";
        const state = Math.random().toString(36).substring(2, 15);
        const pkce = await generatePKCE();

        const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
        authUrl.searchParams.set("client_id", clientId);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("scope", "openid email profile");
        authUrl.searchParams.set("state", state);
        authUrl.searchParams.set("code_challenge", pkce.challenge);
        authUrl.searchParams.set("code_challenge_method", "S256");

        return new Response(null, {
            status: 302,
            headers: {
                'Location': authUrl.toString(),
                'Set-Cookie': `admin_pkce_verifier=${pkce.verifier}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600`
            }
        });
    }

    if (requestUrl.pathname === '/admin/google-callback') {
        const code = requestUrl.searchParams.get('code');
        const error = requestUrl.searchParams.get('error');
        if (error) return new Response(`OAuth Error: ${error}`, { status: 400 });
        if (!code) return new Response("Missing code", { status: 400 });

        const cookies = cookie.parse(request.headers.get('Cookie') || '');
        const verifier = cookies['admin_pkce_verifier'];
        if (!verifier) return new Response("Missing verifier", { status: 400 });

        const clientId = env.ADMIN_OAUTH_CLIENT_ID;
        const clientSecret = env.ADMIN_OAUTH_CLIENT_SECRET;
        const redirectUri = new URL(request.url).origin + "/admin/google-callback";

        const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                client_id: clientId!,
                client_secret: clientSecret!,
                code,
                grant_type: "authorization_code",
                redirect_uri: redirectUri,
                code_verifier: verifier,
            }),
        });

        if (!tokenResponse.ok) return new Response("Token exchange failed", { status: 400 });
        const tokens = await tokenResponse.json<any>();
        const idToken = tokens.id_token;
        if (!idToken) return new Response("No ID token", { status: 400 });

        // Decode ID token (JWT) - only need email
        const payload = JSON.parse(atob(idToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        const email = payload.email;

        // Check if admin exists
        const admin = await env.DB.prepare("SELECT id, email, role FROM admins WHERE email = ?").bind(email).first<Admin>();
        if (!admin) {
            const loginUrl = new URL(request.url).origin + "/admin";
            return new Response(null, {
                status: 302,
                headers: {
                    'Location': `${loginUrl}?error=unauthorized&email=${encodeURIComponent(email)}`
                }
            });
        }

        // Create session
        const secret = env.ADMIN_OAUTH_CLIENT_SECRET || env.ADMIN_ACCESS_TOKEN || "fixed-fallback-secret";
        const key = await getDerivedKey(secret);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const expiry = Date.now() + 8 * 60 * 60 * 1000; // 8 hours
        const data = JSON.stringify({ adminId: admin.id, email: admin.email, expiry });

        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(data));
        const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
        const encryptedHex = Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('');

        const sessionCookie = `${ivHex}.${encryptedHex}`;
        const redirectUrl = new URL(request.url).origin + "/admin";
        const headers = new Headers({
            'Location': redirectUrl,
            'Set-Cookie': `session=${sessionCookie}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=28800`
        });
        // Clear verifier cookie
        headers.append('Set-Cookie', `admin_pkce_verifier=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0`);
        
        return new Response(null, {
            status: 302,
            headers
        });
    }

    if (requestUrl.pathname === '/admin/logout') {
        const redirectUrl = new URL(request.url).origin + "/admin";
        return new Response(null, {
            status: 302,
            headers: {
                'Location': redirectUrl,
                'Set-Cookie': `session=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0`
            }
        });
    }

    if (requestUrl.pathname === '/admin/login') {
        // Only allow legacy login if token is configured
        if (request.method === 'POST' && env.ADMIN_ACCESS_TOKEN) {
            try {
                const { token } = await request.json<{ token: string }>();
                if (token === env.ADMIN_ACCESS_TOKEN) {
                    // Legacy login will act as the first admin (usually super_admin)
                    const admin = await env.DB.prepare("SELECT id, email, role FROM admins ORDER BY id ASC LIMIT 1").first<Admin>();
                    if (!admin) return jsonResponse({ error: "System not initialized" }, 500);

                    const secret = env.ADMIN_OAUTH_CLIENT_SECRET || env.ADMIN_ACCESS_TOKEN || "fixed-fallback-secret";
                    const key = await getDerivedKey(secret);
                    const iv = crypto.getRandomValues(new Uint8Array(12));
                    const expiry = Date.now() + 8 * 60 * 60 * 1000;
                    const data = JSON.stringify({ adminId: admin.id, email: admin.email, expiry });

                    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(data));
                    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
                    const encryptedHex = Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('');

                    const sessionCookie = `${ivHex}.${encryptedHex}`;
                    return new Response(JSON.stringify({ success: true }), {
                        status: 200,
                        headers: {
                            'Set-Cookie': `session=${sessionCookie}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=28800`,
                            'Content-Type': 'application/json'
                        }
                    });
                }
                return jsonResponse({ error: 'Invalid token' }, 401);
            } catch {
                return jsonResponse({ error: 'Invalid request' }, 400);
            }
        }
        return new Response('Method Not Allowed', { status: 405 });
    }

    // --- Protected Admin & API Routes ---
    if (requestUrl.pathname.startsWith('/admin') || requestUrl.pathname.startsWith('/api/')) {
        const admin = await verifyLogin(request, env);
        if (!admin) {
            if (requestUrl.pathname.startsWith('/api')) {
                return jsonResponse({ error: 'Unauthorized' }, 401);
            }
            return new Response(loginHtml, { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        // From here on, admin is guaranteed to be non-null
        // Serve the admin panel HTML
        if (request.method === 'GET' && requestUrl.pathname === '/admin') {
          return new Response(adminHtml, {
            headers: { 'Content-Type': 'text/html;charset=UTF-8' },
          });
        }


        // --- OAuth Authorization & Callback ---
        if (requestUrl.pathname === '/api/oauth-authorize') {
            const clientId = requestUrl.searchParams.get('client_id') || env.OAUTH_CLIENT_ID || "";
            // Hardcode to reference code URI to avoid redirect_uri_mismatch
            const redirectUri = "http://localhost:8085/oauth2callback";
            const state = Math.random().toString(36).substring(2, 15);
            
            const pkce = await generatePKCE();
            
            const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
            authUrl.searchParams.set("client_id", clientId);
            authUrl.searchParams.set("response_type", "code");
            authUrl.searchParams.set("redirect_uri", redirectUri);
            authUrl.searchParams.set("scope", "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile");
            authUrl.searchParams.set("state", state);
            authUrl.searchParams.set("access_type", "offline");
            authUrl.searchParams.set("prompt", "consent");
            authUrl.searchParams.set("code_challenge", pkce.challenge);
            authUrl.searchParams.set("code_challenge_method", "S256");

            const response = jsonResponse({ url: authUrl.toString() });
            response.headers.append('Set-Cookie', `pkce_verifier=${pkce.verifier}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600`);
            return response;
        }

        if (requestUrl.pathname === '/api/oauth-callback') {
            const code = requestUrl.searchParams.get('code');
            const state = requestUrl.searchParams.get('state');
            const error = requestUrl.searchParams.get('error');

            if (error) return new Response(`OAuth Error: ${error}`, { status: 400 });
            if (!code) return new Response("Missing code", { status: 400 });

            // The admin UI will handle the actual exchange or we can do it here if we had the client_secret.
            // Since we want the admin UI to receive the "credential string", we'll return a simple HTML that 
            // posts the code back to the opener.
            return new Response(`
                <html>
                <body>
                    <script>
                        if (window.opener) {
                            window.opener.postMessage({ type: 'oauth-code', code: '${code}' }, '*');
                            window.close();
                        } else {
                            document.body.innerHTML = 'Authorization successful. You can close this window and paste this code: <br><code>${code}</code>';
                        }
                    </script>
                </body>
                </html>
            `, { headers: { 'Content-Type': 'text/html' } });
        }

        if (requestUrl.pathname === '/api/oauth-exchange' || requestUrl.pathname === '/api/antigravity/oauth-exchange') {
            if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
            try {
                const bodyJson = await request.json<any>();
                const { code, client_id, client_secret, isAntigravity } = bodyJson;
                const cookies = cookie.parse(request.headers.get('Cookie') || '');
                const verifier = cookies['pkce_verifier'];

                const isAgy = isAntigravity || requestUrl.pathname.includes('antigravity');
                const defaultClientId = isAgy ? ANTIGRAVITY_CLIENT_ID : (env.OAUTH_CLIENT_ID || "");
                const defaultClientSecret = isAgy ? ANTIGRAVITY_CLIENT_SECRET : (env.OAUTH_CLIENT_SECRET || "");

                const finalClientId = client_id || defaultClientId;
                const finalClientSecret = client_secret || defaultClientSecret;
                const finalRedirectUri = "http://localhost:8085/oauth2callback";

                const tokenParams: Record<string, string> = {
                    client_id: finalClientId,
                    client_secret: finalClientSecret,
                    code,
                    grant_type: "authorization_code",
                    redirect_uri: finalRedirectUri,
                };

                if (verifier) {
                    tokenParams['code_verifier'] = verifier;
                }

                const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: new URLSearchParams(tokenParams),
                });

                if (!tokenResponse.ok) {
                    const err = await tokenResponse.text();
                    return jsonResponse({ error: err }, 400);
                }

                const tokens = await tokenResponse.json<any>();
                if (!tokens.refresh_token) {
                    return jsonResponse({ error: "No refresh token returned. Try revoking access first." }, 400);
                }

                const email = decodeJwtEmail(tokens.id_token) || 'unknown_owner';

                let projectId = 'default';
                try {
                    projectId = await discoverProjectId(tokens.access_token, email, isAgy) || 'default';
                } catch (e) {
                    console.error("OAuth Exchange: dynamic project discovery failed:", e);
                }

                const credentialString = `${finalClientId}:${finalClientSecret}:${tokens.refresh_token}:${projectId}:${email}`;
                return jsonResponse({ credential_string: credentialString });
            } catch (e: any) {
                return jsonResponse({ error: e.message }, 500);
            }
        }

        // Handle API calls for credentials
        if (requestUrl.pathname === '/api/credentials' || requestUrl.pathname === '/api/oauth-credentials' || requestUrl.pathname === '/api/antigravity-credentials') {
          const isOAuth = requestUrl.pathname === '/api/oauth-credentials';
          const isAntigravity = requestUrl.pathname === '/api/antigravity-credentials';
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          const clearDoCache = (accessTokenStr: string) => {
            ctx.waitUntil((async () => {
              try {
                const id = env.KEY_ROTATOR.idFromName(accessTokenStr);
                const stub = env.KEY_ROTATOR.get(id);
                await stub.fetch(new Request(`${requestUrl.origin}/admin/clear-cache`, {
                  method: 'POST',
                  headers: { 'X-Access-Token': accessTokenStr }
                }));
              } catch (e) {
                console.error('Failed to clear DO cache:', e);
              }
            })());
          };

          // GET: Fetch existing keys for a token
          if (request.method === 'GET') {
            const accessToken = request.headers.get('X-Access-Token');
            if (!accessToken) {
              // Return list of all configured tokens for this admin
              let query = "SELECT access_token FROM api_credentials WHERE owner_admin_id = ? AND api_keys != ''";
              if (isAntigravity) {
                query = "SELECT access_token FROM api_credentials WHERE owner_admin_id = ? AND antigravity_credentials != ''";
              } else if (isOAuth) {
                query = "SELECT access_token FROM api_credentials WHERE owner_admin_id = ? AND oauth_credentials != ''";
              }
              const result = await env.DB.prepare(query).bind(admin.id).all<any>();
              const tokens = result.results.map((r: any) => r.access_token);
              return jsonResponse({ tokens }, 200, headers);
            }
            let query = "SELECT api_keys, enable_logging, enable_pruning FROM api_credentials WHERE access_token = ? AND owner_admin_id = ? AND api_keys != ''";
            if (isAntigravity) {
              query = "SELECT antigravity_credentials, enable_logging, enable_pruning FROM api_credentials WHERE access_token = ? AND owner_admin_id = ? AND antigravity_credentials != ''";
            } else if (isOAuth) {
              query = "SELECT oauth_credentials, enable_logging, enable_pruning FROM api_credentials WHERE access_token = ? AND owner_admin_id = ? AND oauth_credentials != ''";
            }
            const result = await env.DB.prepare(query).bind(accessToken.trim(), admin.id).first<any>();
            return jsonResponse(result || {}, 200, headers);
          }

          // POST: Create or update credentials
          if (request.method === 'POST') {
            try {
              const clonedRequest = request.clone();
              const body = await clonedRequest.json<any>();
              const accessToken = body.access_token?.trim();

              if (!accessToken || accessToken.length < 10) {
                return jsonResponse({ error: 'A valid Access Token (at least 10 characters) is required.' }, 400, headers);
              }

              // Check if token belongs to someone else
              const existing = await env.DB.prepare("SELECT owner_admin_id FROM api_credentials WHERE access_token = ?").bind(accessToken).first<{owner_admin_id: number}>();
              if (existing && existing.owner_admin_id !== admin.id) {
                return jsonResponse({ error: 'This Access Token is already owned by another admin.' }, 403, headers);
              }

              const enableLogging = (body.enable_logging === true || body.enable_logging === 1 || body.enable_logging === '1') ? 1 : 0;
              const enablePruning = (body.enable_pruning === undefined || body.enable_pruning === true || body.enable_pruning === 1 || body.enable_pruning === '1') ? 1 : 0;

              if (isAntigravity) {
                const agyInput = body.antigravity_credentials;
                if (!agyInput || typeof agyInput !== 'string' || agyInput.trim() === '') {
                  return jsonResponse({ error: 'Antigravity OAuth credentials are required.' }, 400, headers);
                }
                const agyKeys = agyInput.split(/[\s,]+/).map(k => k.trim()).filter(k => k);
                const agyString = agyKeys.join(',');

                const stmt = env.DB.prepare(
                  `INSERT INTO api_credentials (access_token, owner_admin_id, antigravity_credentials, current_antigravity_index, antigravity_key_states, api_keys, current_key_index, key_states, oauth_credentials, current_oauth_index, oauth_key_states, enable_logging, enable_pruning)
                   VALUES (?, ?, ?, 0, '[]', '', 0, '[]', '', 0, '[]', ?, ?)
                   ON CONFLICT(access_token) DO UPDATE SET
                     antigravity_credentials = excluded.antigravity_credentials,
                     current_antigravity_index = 0,
                     antigravity_key_states = '[]',
                     owner_admin_id = excluded.owner_admin_id,
                     enable_logging = excluded.enable_logging,
                     enable_pruning = excluded.enable_pruning`
                );
                await stmt.bind(accessToken, admin.id, agyString, enableLogging, enablePruning).run();
              } else if (isOAuth) {
                const oauthInput = body.oauth_credentials;
                if (!oauthInput || typeof oauthInput !== 'string' || oauthInput.trim() === '') {
                  return jsonResponse({ error: 'OAuth credentials are required.' }, 400, headers);
                }
                const oauthKeys = oauthInput.split(/[\s,]+/).map(k => k.trim()).filter(k => k);
                const oauthString = oauthKeys.join(',');

                const stmt = env.DB.prepare(
                  `INSERT INTO api_credentials (access_token, owner_admin_id, oauth_credentials, current_oauth_index, oauth_key_states, api_keys, current_key_index, key_states, enable_logging, enable_pruning)
                   VALUES (?, ?, ?, 0, '[]', '', 0, '[]', ?, ?)
                   ON CONFLICT(access_token) DO UPDATE SET
                     oauth_credentials = excluded.oauth_credentials,
                     current_oauth_index = 0,
                     oauth_key_states = '[]',
                     owner_admin_id = excluded.owner_admin_id,
                     enable_logging = excluded.enable_logging,
                     enable_pruning = excluded.enable_pruning`
                );
                await stmt.bind(accessToken, admin.id, oauthString, enableLogging, enablePruning).run();
              } else {
                const keysInput = body.api_keys;
                if (!keysInput || typeof keysInput !== 'string' || keysInput.trim() === '') {
                  return jsonResponse({ error: 'API keys are required.' }, 400, headers);
                }
                const apiKeys = keysInput.split(/[\s,]+/).map(k => k.trim()).filter(k => k);
                const apiKeysString = apiKeys.join(',');

                const stmt = env.DB.prepare(
                  `INSERT INTO api_credentials (access_token, owner_admin_id, api_keys, current_key_index, key_states, oauth_credentials, current_oauth_index, oauth_key_states, enable_logging, enable_pruning)
                   VALUES (?, ?, ?, 0, '[]', '', 0, '[]', ?, ?)
                   ON CONFLICT(access_token) DO UPDATE SET
                     api_keys = excluded.api_keys,
                     current_key_index = 0,
                     key_states = '[]',
                     owner_admin_id = excluded.owner_admin_id,
                     enable_logging = excluded.enable_logging,
                     enable_pruning = excluded.enable_pruning`
                );
                await stmt.bind(accessToken, admin.id, apiKeysString, enableLogging, enablePruning).run();
              }

              clearDoCache(accessToken);
              return jsonResponse({ access_token: accessToken }, 200, headers);

            } catch (e: any) {
              console.error("Error creating/updating credentials:", e);
              return jsonResponse({ error: 'Failed to process request. Ensure you are sending valid JSON.' }, 500, headers);
            }
          }
          
          // DELETE: Remove for a token
          if (request.method === 'DELETE') {
            try {
              const accessToken = request.headers.get('X-Access-Token');

              if (!accessToken) {
                return jsonResponse({ error: 'A valid Access Token is required in the X-Access-Token header.' }, 400, headers);
              }

              if (isAntigravity) {
                const stmt = env.DB.prepare("UPDATE api_credentials SET antigravity_credentials = '', current_antigravity_index = 0, antigravity_key_states = '[]' WHERE access_token = ? AND owner_admin_id = ?");
                const { meta } = await stmt.bind(accessToken.trim(), admin.id).run();
                if (meta.changes > 0) {
                  clearDoCache(accessToken.trim());
                  return jsonResponse({ message: 'Antigravity OAuth credentials deleted successfully.' }, 200, headers);
                }
                return jsonResponse({ error: 'No matching Antigravity credentials found to delete.' }, 404, headers);
              } else if (isOAuth) {
                const stmt = env.DB.prepare("UPDATE api_credentials SET oauth_credentials = '', current_oauth_index = 0, oauth_key_states = '[]' WHERE access_token = ? AND owner_admin_id = ?");
                const { meta } = await stmt.bind(accessToken.trim(), admin.id).run();
                if (meta.changes > 0) {
                  clearDoCache(accessToken.trim());
                  return jsonResponse({ message: 'OAuth credentials cleared successfully.' }, 200, headers);
                }
              } else {
                const stmt = env.DB.prepare("DELETE FROM api_credentials WHERE access_token = ? AND owner_admin_id = ?");
                const { meta } = await stmt.bind(accessToken.trim(), admin.id).run();
                if (meta.changes > 0) {
                  clearDoCache(accessToken.trim());
                  return jsonResponse({ message: 'Access Token deleted successfully.' }, 200, headers);
                }
              }
              return jsonResponse({ message: 'Access Token not found or not owned by you.' }, 404, headers);
            } catch (e: any) {
              console.error("Error deleting Access Token:", e);
              return jsonResponse({ error: 'Failed to process request.' }, 500, headers);
            }
          }
          
          headers.set('Allow', 'GET, POST, DELETE, OPTIONS');
          return new Response('Method Not Allowed', { status: 405, headers });
        }

        // Handle API calls for logs
        if (requestUrl.pathname.startsWith('/api/logs')) {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          if (requestUrl.pathname === '/api/logs') {
            // GET: Fetch logs with pagination
            if (request.method === 'GET') {
              try {
                const page = parseInt(requestUrl.searchParams.get('page') || '1');
                const limit = parseInt(requestUrl.searchParams.get('limit') || '50');
                const offset = (page - 1) * limit;
                const showAll = requestUrl.searchParams.get('show_all') === 'true';

                let logs;
                let total = 0;

                if (admin.role === 'super_admin' && showAll) {
                  const stmt = env.DB.prepare("SELECT * FROM api_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?");
                  const result = await stmt.bind(limit, offset).all();
                  logs = result.results;

                  const countStmt = env.DB.prepare("SELECT COUNT(*) as total FROM api_logs");
                  const totalResult = await countStmt.first<{ total: number }>();
                  total = totalResult?.total || 0;
                } else {
                  const stmt = env.DB.prepare(`
                    SELECT * FROM api_logs
                    WHERE access_token IN (
                      SELECT access_token FROM api_credentials WHERE owner_admin_id = ?
                    )
                    ORDER BY timestamp DESC LIMIT ? OFFSET ?
                  `);
                  const result = await stmt.bind(admin.id, limit, offset).all();
                  logs = result.results;

                  const countStmt = env.DB.prepare(`
                    SELECT COUNT(*) as total FROM api_logs
                    WHERE access_token IN (
                      SELECT access_token FROM api_credentials WHERE owner_admin_id = ?
                    )
                  `);
                  const totalResult = await countStmt.bind(admin.id).first<{ total: number }>();
                  total = totalResult?.total || 0;
                }

                return jsonResponse({ logs, total, page, limit }, 200, headers);
              } catch (e: any) {
                console.error("Error fetching logs:", e);
                return jsonResponse({ error: 'Failed to fetch logs.' }, 500, headers);
              }
            }

            // DELETE: Clear logs
            if (request.method === 'DELETE') {
              try {
                const showAll = requestUrl.searchParams.get('show_all') === 'true';
                let stmt;
                
                if (admin.role === 'super_admin' && showAll) {
                  stmt = env.DB.prepare("DELETE FROM api_logs");
                } else {
                  stmt = env.DB.prepare(`
                    DELETE FROM api_logs
                    WHERE access_token IN (
                      SELECT access_token FROM api_credentials WHERE owner_admin_id = ?
                    )
                  `);
                }

                const { meta } = await (admin.role === 'super_admin' && showAll ? stmt.bind().run() : stmt.bind(admin.id).run());

                return jsonResponse({
                  message: 'Logs deleted successfully.',
                  deletedCount: meta.changes
                }, 200, headers);
              } catch (e: any) {
                console.error("Error clearing logs:", e);
                return jsonResponse({ error: 'Failed to clear logs.' }, 500, headers);
              }
            }

            return jsonResponse({ error: 'Method not allowed' }, 405, headers);
          } else {
            // /api/logs/:id
            const pathParts = requestUrl.pathname.split('/');
            if (pathParts.length === 4) {
              const logIdStr = pathParts[3];
              const logId = parseInt(logIdStr);
              if (isNaN(logId)) {
                return jsonResponse({ error: 'Invalid log ID' }, 400, headers);
              }

              // DELETE specific log
              if (request.method === 'DELETE') {
                try {
                  let stmt;
                  if (admin.role === 'super_admin') {
                    stmt = env.DB.prepare("DELETE FROM api_logs WHERE id = ?");
                  } else {
                    stmt = env.DB.prepare(`
                      DELETE FROM api_logs 
                      WHERE id = ? AND access_token IN (
                        SELECT access_token FROM api_credentials WHERE owner_admin_id = ?
                      )
                    `);
                  }
                  
                  const { meta } = await (admin.role === 'super_admin' ? stmt.bind(logId) : stmt.bind(logId, admin.id)).run();

                  if (meta.changes > 0) {
                    return jsonResponse({ message: 'Log deleted successfully.' }, 200, headers);
                  } else {
                    return jsonResponse({ message: 'Log not found or unauthorized.' }, 404, headers);
                  }
                } catch (e: any) {
                  console.error("Error deleting log:", e);
                  return jsonResponse({ error: 'Failed to delete log.' }, 500, headers);
                }
              }
            }
            return jsonResponse({ error: 'Not Found' }, 404, headers);
          }
        }

        // --- Admin Info ---
        if (requestUrl.pathname === '/api/admin-info') {
            return jsonResponse(admin);
        }

        // --- Admin Management API (Super Admin Only) ---
        if (requestUrl.pathname === '/api/admins') {
            if (admin.role !== 'super_admin') return jsonResponse({ error: 'Forbidden' }, 403);
            
            if (request.method === 'GET') {
                const admins = await env.DB.prepare("SELECT * FROM admins ORDER BY id ASC").all();
                return jsonResponse(admins.results);
            }
            if (request.method === 'POST') {
                const { email, role } = await request.json<any>();
                if (!email) return jsonResponse({ error: 'Email required' }, 400);
                await env.DB.prepare("INSERT INTO admins (email, role) VALUES (?, ?) ON CONFLICT(email) DO UPDATE SET role = excluded.role")
                    .bind(email, role || 'admin').run();
                return jsonResponse({ success: true });
            }
            if (request.method === 'DELETE') {
                const email = requestUrl.searchParams.get('email');
                if (!email) return jsonResponse({ error: 'Email required' }, 400);
                if (email === 'remus.to@gmail.com') return jsonResponse({ error: 'Cannot delete primary super admin' }, 403);
                await env.DB.prepare("DELETE FROM admins WHERE email = ?").bind(email).run();
                return jsonResponse({ success: true });
            }
        }

        // Handle Key Health API
        if (requestUrl.pathname === '/api/key-status') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          if (request.method === 'GET') {
            // First check if a token is provided in the query string (for admin convenience)
            let accessToken = requestUrl.searchParams.get('access_token');
            if (!accessToken) {
              accessToken = request.headers.get('X-Access-Token');
            }

            if (!accessToken) {
              return jsonResponse({ error: 'X-Access-Token header is required.' }, 400, headers);
            }

            // Verify ownership
            const existing = await env.DB.prepare("SELECT owner_admin_id FROM api_credentials WHERE access_token = ?").bind(accessToken.trim()).first<{owner_admin_id: number}>();
            if (!existing || existing.owner_admin_id !== admin.id) {
              return jsonResponse({ error: 'Access Token not found or not owned by you.' }, 404, headers);
            }

            const id = env.KEY_ROTATOR.idFromName(accessToken);
            const stub = env.KEY_ROTATOR.get(id, { locationHint: 'wnam' });
            
            const forwardRequest = new Request(request.url, request);
            forwardRequest.headers.set('X-Access-Token', accessToken);
            forwardRequest.headers.set('X-Auth-Mode', 'google'); // Default protocol for internal errors
            
            // Re-route to the internal Durable Object health endpoint
            const internalUrl = new URL(request.url);
            internalUrl.pathname = '/admin/key-status';
            
            const response = await stub.fetch(new Request(internalUrl.toString(), forwardRequest));
            return new Response(response.body, { status: response.status, headers: new Headers(corsHeaders) });
          }
        }

        if (requestUrl.pathname === '/api/reset-key-health') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          if (request.method === 'POST') {
            const body = await request.json<any>();
            const accessToken = body.access_token || request.headers.get('X-Access-Token');

            if (!accessToken) {
              return jsonResponse({ error: 'Access token is required.' }, 400, headers);
            }

            // Verify ownership
            const existing = await env.DB.prepare("SELECT owner_admin_id FROM api_credentials WHERE access_token = ?").bind(accessToken.trim()).first<{owner_admin_id: number}>();
            if (!existing || existing.owner_admin_id !== admin.id) {
              return jsonResponse({ error: 'Access Token not found or not owned by you.' }, 404, headers);
            }

            const id = env.KEY_ROTATOR.idFromName(accessToken);
            const stub = env.KEY_ROTATOR.get(id, { locationHint: 'wnam' });
            
            const forwardHeaders = new Headers(request.headers);
            forwardHeaders.set('X-Access-Token', accessToken);
            forwardHeaders.set('X-Auth-Mode', 'google');
            forwardHeaders.set('Content-Type', 'application/json');

            const forwardRequest = new Request(request.url, {
              method: 'POST',
              headers: forwardHeaders,
              body: JSON.stringify(body)
            });
            
            const internalUrl = new URL(request.url);
            internalUrl.pathname = '/admin/reset-key-health';
            
            const response = await stub.fetch(new Request(internalUrl.toString(), forwardRequest));
            return new Response(response.body, { status: response.status, headers: new Headers(corsHeaders) });
          }
        }

        if (requestUrl.pathname === '/api/key-diagnose') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          if (request.method === 'POST') {
            const body = await request.json<any>();
            const accessToken = body.access_token || request.headers.get('X-Access-Token');

            if (!accessToken) {
              return jsonResponse({ error: 'Access token is required.' }, 400, headers);
            }

            // Verify ownership
            const existing = await env.DB.prepare("SELECT owner_admin_id FROM api_credentials WHERE access_token = ?").bind(accessToken.trim()).first<{owner_admin_id: number}>();
            if (!existing || existing.owner_admin_id !== admin.id) {
              return jsonResponse({ error: 'Access Token not found or not owned by you.' }, 404, headers);
            }

            const id = env.KEY_ROTATOR.idFromName(accessToken);
            const stub = env.KEY_ROTATOR.get(id, { locationHint: 'wnam' });
            
            const forwardHeaders = new Headers(request.headers);
            forwardHeaders.set('X-Access-Token', accessToken);
            forwardHeaders.set('X-Auth-Mode', 'google');
            forwardHeaders.set('Content-Type', 'application/json');

            const forwardRequest = new Request(request.url, {
              method: 'POST',
              headers: forwardHeaders,
              body: JSON.stringify(body)
            });
            
            const internalUrl = new URL(request.url);
            internalUrl.pathname = '/admin/key-diagnose';
            
            const response = await stub.fetch(new Request(internalUrl.toString(), forwardRequest));
            return new Response(response.body, { status: response.status, headers: new Headers(corsHeaders) });
          }
        }

        if (requestUrl.pathname === '/api/key-models') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          if (request.method === 'POST') {
            const body = await request.json<any>();
            let accessToken = body.access_token || request.headers.get('X-Access-Token');

            if (!accessToken) {
              const authHeader = request.headers.get('Authorization');
              if (authHeader && authHeader.startsWith('Bearer ')) {
                accessToken = authHeader.replace('Bearer ', '').trim();
              }
            }

            if (!accessToken) {
              return jsonResponse({ error: 'Access token is required.' }, 400, headers);
            }

            // Verify ownership
            const existing = await env.DB.prepare("SELECT owner_admin_id FROM api_credentials WHERE access_token = ?").bind(accessToken.trim()).first<{owner_admin_id: number}>();
            if (!existing || existing.owner_admin_id !== admin.id) {
              return jsonResponse({ error: 'Access Token not found or not owned by you.' }, 404, headers);
            }

            const id = env.KEY_ROTATOR.idFromName(accessToken);
            const stub = env.KEY_ROTATOR.get(id, { locationHint: 'wnam' });
            
            const forwardHeaders = new Headers(request.headers);
            forwardHeaders.set('X-Access-Token', accessToken);
            forwardHeaders.set('Content-Type', 'application/json');

            const forwardRequest = new Request(request.url, {
              method: 'POST',
              headers: forwardHeaders,
              body: JSON.stringify(body)
            });
            
            const internalUrl = new URL(request.url);
            internalUrl.pathname = '/admin/key-models';
            
            const response = await stub.fetch(new Request(internalUrl.toString(), forwardRequest));
            return new Response(response.body, { status: response.status, headers: new Headers(corsHeaders) });
          }
        }

        // Handle Statistics Trends API
        if (requestUrl.pathname === '/api/statistics/trends') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);
          if (request.method === 'GET') {
            try {
              const allParam = requestUrl.searchParams.get('all') === 'true';
              const showAll = admin.role === 'super_admin' && allParam;

              let stmt;
              if (showAll) {
                // Group usage by date to provide trend data
                stmt = env.DB.prepare(`
                  SELECT 
                    usage_date, 
                    SUM(request_count) as total_requests, 
                    SUM(success_count) as total_success, 
                    SUM(error_429_count) as total_429
                  FROM api_key_usage 
                  GROUP BY usage_date 
                  ORDER BY usage_date DESC
                  LIMIT 30
                `);
              } else {
                stmt = env.DB.prepare(`
                  SELECT 
                    u.usage_date, 
                    SUM(u.request_count) as total_requests, 
                    SUM(u.success_count) as total_success, 
                    SUM(u.error_429_count) as total_429
                  FROM api_key_usage u
                  JOIN api_credentials c ON u.user_access_token = c.access_token
                  WHERE c.owner_admin_id = ?
                  GROUP BY u.usage_date 
                  ORDER BY u.usage_date DESC
                  LIMIT 30
                `).bind(admin.id);
              }
              const result = await stmt.all();
              const trendData = result.results ? [...result.results].reverse() : [];
              return jsonResponse(trendData, 200, headers);
            } catch (e: any) {
              console.error("Error fetching trend statistics:", e);
              return jsonResponse({ error: 'Failed to fetch trend statistics.' }, 500, headers);
            }
          }
        }

        // Handle Statistics API
        if (requestUrl.pathname === '/api/statistics') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          if (request.method === 'GET') {
            try {
              const allParam = requestUrl.searchParams.get('all') === 'true';
              const showAll = admin.role === 'super_admin' && allParam;

              let stmt;
              if (showAll) {
                stmt = env.DB.prepare("SELECT * FROM api_key_usage ORDER BY usage_date DESC, request_count DESC");
              } else {
                stmt = env.DB.prepare(`
                  SELECT u.* 
                  FROM api_key_usage u
                  JOIN api_credentials c ON u.user_access_token = c.access_token
                  WHERE c.owner_admin_id = ?
                  ORDER BY u.usage_date DESC, u.request_count DESC
                `).bind(admin.id);
              }
              const result = await stmt.all();
              return jsonResponse(result.results, 200, headers);
            } catch (e: any) {
              console.error("Error fetching statistics:", e);
              return jsonResponse({ error: 'Failed to fetch statistics.' }, 500, headers);
            }
          }

          if (request.method === 'DELETE') {
            try {
              const allParam = requestUrl.searchParams.get('all') === 'true';
              const deleteAll = admin.role === 'super_admin' && allParam;

              let stmt;
              if (deleteAll) {
                stmt = env.DB.prepare("DELETE FROM api_key_usage");
              } else {
                stmt = env.DB.prepare(`
                  DELETE FROM api_key_usage 
                  WHERE user_access_token IN (
                    SELECT access_token FROM api_credentials WHERE owner_admin_id = ?
                  )
                `).bind(admin.id);
              }
              const { meta } = await stmt.run();
              return jsonResponse({ message: 'Statistics cleared successfully.', deletedCount: meta.changes }, 200, headers);
            } catch (e: any) {
              console.error("Error clearing statistics:", e);
              return jsonResponse({ error: 'Failed to clear statistics.' }, 500, headers);
            }
          }
          return jsonResponse({ error: 'Method not allowed' }, 405, headers);
        }

        return new Response('Not Found', { status: 404 });
    }

    // --- Main Proxy Logic ---
    if (request.method === 'OPTIONS') {
      const enableLogging = env.ENABLE_API_LOGGING === "true";
      const response = handleOptions(request);
      if (enableLogging) {
        ctx.waitUntil(writeCombinedLog(env, request, response.clone(), Date.now()));
      }
      return response;
    }

    try {
      let accessToken: string | null = null;
      let openAIMode = false;
      let googleMode = false;
      let claudeMode = false;

      const authHeader = request.headers.get("Authorization");
      const xApiKeyHeader = request.headers.get("x-api-key");

      if (authHeader && authHeader.startsWith("Bearer sk-ant-api01-")) {
        accessToken = authHeader.substring(7).trim();
        claudeMode = true;
      } else if (xApiKeyHeader) {
        accessToken = xApiKeyHeader.trim();
        claudeMode = true;
      } else if (authHeader && authHeader.startsWith("Bearer ")) {
        accessToken = authHeader.substring(7).trim();
        // Check if this looks like an OAuth token (much longer than typical API keys)
        if (accessToken.length > 100) {
          // This is likely an OAuth access token for internal Gemini APIs
          googleMode = true; // Will be handled by X-Auth-Mode header
        } else {
          openAIMode = true;
        }
      } else {
        const headerKey = request.headers.get("x-goog-api-key");
        if (headerKey) {
          accessToken = headerKey.trim();
          googleMode = true;
        } else {
          const keyParam = requestUrl.searchParams.get("key");
          if (keyParam) {
            accessToken = keyParam.trim();
            googleMode = true;
          }
        }
      }

      if (!accessToken) {
        return new Response("Unauthorized: Access token is required.", { status: 401 });
      }

      const id = env.KEY_ROTATOR.idFromName(accessToken);
      const stub = env.KEY_ROTATOR.get(id, { locationHint: 'wnam' });

      const forwardRequest = new Request(request.url, request);
      forwardRequest.headers.set("X-Access-Token", accessToken);
      forwardRequest.headers.set("X-Original-Url", request.url);
      
      if (openAIMode) {
        forwardRequest.headers.set("X-Auth-Mode", "openai");
      } else if (googleMode) {
        forwardRequest.headers.set("X-Auth-Mode", "google");
      } else if (claudeMode) {
        forwardRequest.headers.set("X-Auth-Mode", "claude");
      }

      const response = await stub.fetch(forwardRequest);

      const resHeaders = new Headers(response.headers);
      const cors = getCorsHeaders(request);
      for (const [key, value] of Object.entries(cors)) {
          resHeaders.set(key, value);
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: resHeaders
      });

    } catch (err: any) {
      console.error("Worker error:", err.stack || err);
      return new Response("Internal Server Error in Worker", { status: 500 });
    }
  },
};

export { KeyRotator };

// --- Utility and CORS Functions ---
function jsonResponse(data: any, status = 200, headers = new Headers()): Response {
  headers.set('Content-Type', 'application/json;charset=UTF-8');
  return new Response(JSON.stringify(data), { status, headers });
}

// --- CORS Handling ---
function getCorsHeaders(request: Request): Record<string, string> {
    const requestOrigin = request.headers.get("Origin");
    
    // Allow all origins for the proxy functionality. 
    // If the request includes credentials (like cookies for admin routes), 
    // the browser requires the specific origin to be echoed back, not *.
    const originHeader = requestOrigin || '*';

    return {
        "Access-Control-Allow-Origin": originHeader,
        "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS, DELETE",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, x-goog-api-key, x-api-key, X-Access-Token, anthropic-dangerous-direct-browser-access, anthropic-version",
        "Access-Control-Max-Age": "86400",
    };
}


function handleOptions(request: Request): Response {
  const corsHeaders = getCorsHeaders(request);

  if (
    request.headers.get("Origin") !== null &&
    request.headers.get("Access-Control-Request-Method") !== null &&
    request.headers.get("Access-Control-Request-Headers") !== null
  ) {
    return new Response(null, { headers: corsHeaders });
  } else {
    return new Response(null, {
      headers: { Allow: "GET, HEAD, POST, OPTIONS, DELETE" },
    });
  }
}

function decodeJwtEmail(idToken: string | undefined): string | undefined {
	if (!idToken) return undefined;
	try {
		const parts = idToken.split('.');
		if (parts.length < 2) return undefined;
		const payloadBase64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
		const payloadJson = atob(payloadBase64);
		const payload = JSON.parse(payloadJson);
		return payload.email;
	} catch (e) {
		return undefined;
	}
}
