/// <reference path="./types.d.ts" />
import adminHtml from './admin.html';
import loginHtml from './login.html';
import * as cookie from 'cookie';
import { KeyRotator } from './rotator';

// --- Types ---
interface Env {
  DB: D1Database;
  GEMINI_API_BASE_URL?: string;
  ADMIN_ACCESS_TOKEN?: string;
  OAUTH_CLIENT_ID?: string;
  OAUTH_CLIENT_SECRET?: string;
  KEY_ROTATOR: DurableObjectNamespace;
  ENABLE_API_LOGGING?: string;
}

// --- Authentication ---
async function sha256(plain: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return crypto.subtle.digest('SHA-256', data);
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const verifier = arrayBufferToBase64Url(array.buffer);
    const challengeBuffer = await sha256(verifier);
    const challenge = arrayBufferToBase64Url(challengeBuffer);
    return { verifier, challenge };
}

async function getDerivedKey(secret: string): Promise<CryptoKey> {
    const secretBuffer = new TextEncoder().encode(secret);
    const hashBuffer = await crypto.subtle.digest('SHA-256', secretBuffer);
    return crypto.subtle.importKey('raw', hashBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function verifyLogin(request: Request, env: Env): Promise<boolean> {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return false;

    const cookies = cookie.parse(cookieHeader);
    const sessionCookie = cookies['session'];
    if (!sessionCookie) return false;

    const [ivHex, encryptedHex] = sessionCookie.split('.');
    if (!ivHex || !encryptedHex) return false;

    try {
        if (!env.ADMIN_ACCESS_TOKEN) {
            console.error("Security configuration error: ADMIN_ACCESS_TOKEN must be set.");
            return false;
        }
        const key = await getDerivedKey(env.ADMIN_ACCESS_TOKEN);
        const iv = new Uint8Array(ivHex.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));
        const encrypted = new Uint8Array(encryptedHex.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );

        const decryptedText = new TextDecoder().decode(decrypted);
        const { token, expiry } = JSON.parse(decryptedText);

        return token === env.ADMIN_ACCESS_TOKEN && Date.now() < expiry;
    } catch (e) {
        console.error("Cookie decryption failed:", e);
        return false;
    }
}

// --- Logging Helper Functions ---
async function logRequest(env: Env, request: Request, accessToken?: string) {
  const startTime = Date.now();
  const headersObj: { [key: string]: string } = {};
  for (const [key, value] of request.headers as any) {
    headersObj[key] = value;
  }

  const logData = {
    timestamp: new Date().toISOString(),
    access_token: accessToken || null,
    request_method: request.method,
    request_url: request.url,
    request_headers: JSON.stringify(headersObj),
    request_body: await request.clone().text(),
  };

  // Insert into D1
  const stmt = env.DB.prepare(`
    INSERT INTO api_logs (timestamp, access_token, request_method, request_url, request_headers, request_body, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `);
  const result = await stmt.bind(
    logData.timestamp,
    logData.access_token,
    logData.request_method,
    logData.request_url,
    logData.request_headers,
    logData.request_body
  ).run();

  return { startTime, logId: result.meta.last_row_id };
}

async function logResponse(env: Env, startTime: number, response: Response, logId: number) {
  const duration = Date.now() - startTime;
  let responseBody: string;
  try {
    responseBody = await response.clone().text();
  } catch (e) {
    responseBody = '<unable to read response>';
  }

  const headersObj: { [key: string]: string } = {};
  for (const [key, value] of response.headers as any) {
    headersObj[key] = value;
  }

  const logData = {
    response_status: response.status,
    response_headers: JSON.stringify(headersObj),
    response_body: responseBody,
    duration_ms: duration,
  };

  // Update the log in D1
  const stmt = env.DB.prepare(`
    UPDATE api_logs SET response_status = ?, response_headers = ?, response_body = ?, duration_ms = ?
    WHERE id = ?
  `);
  await stmt.bind(
    logData.response_status,
    logData.response_headers,
    logData.response_body,
    logData.duration_ms,
    logId
  ).run();
}

// --- Cloudflare Worker Entry Point ---
export default {
  async scheduled(event: any, env: Env, ctx: any) {
    // Daily cleanup: Delete statistics older than 30 days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 30);
    const cutoffStr = cutoffDate.toISOString().split('T')[0];

    try {
      const stmt = env.DB.prepare('DELETE FROM api_key_usage WHERE usage_date < ?');
      const { meta } = await stmt.bind(cutoffStr).run();
      console.log(`Auto-cleanup: Deleted ${meta.changes} statistics entries older than ${cutoffStr}`);
    } catch (e) {
      console.error('Auto-cleanup failed:', e);
    }
  },

  async fetch(
    request: Request,
    env: Env,
    ctx: any
  ): Promise<Response> {
    const requestUrl = new URL(request.url);

    // --- Admin Login Routes ---
    if (requestUrl.pathname === '/admin/login') {
        if (request.method === 'POST') {
            try {
                const clonedRequest = request.clone();
                const { token } = await clonedRequest.json<{ token: string }>();
                if (token === env.ADMIN_ACCESS_TOKEN) {
                    if (!env.ADMIN_ACCESS_TOKEN) {
                        console.error("Security configuration error: ADMIN_ACCESS_TOKEN must be set.");
                        return jsonResponse({ error: "Service is not configured." }, 500);
                    }
                    const key = await getDerivedKey(env.ADMIN_ACCESS_TOKEN);
                    const iv = crypto.getRandomValues(new Uint8Array(12));
                    const expiry = Date.now() + 8 * 60 * 60 * 1000; // 8 hours
                    const data = JSON.stringify({ token, expiry });

                    const encrypted = await crypto.subtle.encrypt(
                        { name: 'AES-GCM', iv: iv },
                        key,
                        new TextEncoder().encode(data)
                    );
                    
                    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
                    const encryptedHex = Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('');

                    const sessionCookie = `${ivHex}.${encryptedHex}`;

                    return new Response(JSON.stringify({ success: true }), {
                        status: 200,
                        headers: {
                            'Set-Cookie': `session=${sessionCookie}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=28800`,
                            'Content-Type': 'application/json'
                        }
                    });
                } else {
                    return jsonResponse({ error: 'Invalid token' }, 401);
                }
            } catch {
                return jsonResponse({ error: 'Invalid request' }, 400);
            }
        }
        return new Response('Method Not Allowed', { status: 405 });
    }

    // --- Protected Admin & API Routes ---
    if (requestUrl.pathname.startsWith('/admin') || requestUrl.pathname.startsWith('/api/')) {
        const isLoggedIn = await verifyLogin(request, env);
        if (!isLoggedIn && requestUrl.pathname !== '/admin/login') {
            if (requestUrl.pathname.startsWith('/api')) {
                return jsonResponse({ error: 'Unauthorized' }, 401);
            }
            return new Response(loginHtml, { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

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

        if (requestUrl.pathname === '/api/oauth-exchange') {
            if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
            try {
                const { code, client_id, client_secret, redirect_uri } = await request.json<any>();
                const cookies = cookie.parse(request.headers.get('Cookie') || '');
                const verifier = cookies['pkce_verifier'];

                const finalClientId = client_id || env.OAUTH_CLIENT_ID || "";
                const finalClientSecret = client_secret || env.OAUTH_CLIENT_SECRET || "";
                // Must match the one used in /api/oauth-authorize
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

                // Discover project ID
                let projectId = 'default';
                try {
                    const pRes = await fetch('https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE', {
                        headers: { 'Authorization': `Bearer ${tokens.access_token}` }
                    });
                    if (pRes.ok) {
                        const pData = await pRes.json<any>();
                        if (pData.projects?.length > 0) projectId = pData.projects[0].projectId;
                    }
                } catch (e) {}

                const credentialString = `${client_id}:${client_secret}:${tokens.refresh_token}:${projectId}`;
                return jsonResponse({ credential_string: credentialString });
            } catch (e: any) {
                return jsonResponse({ error: e.message }, 500);
            }
        }

        // Handle API calls for credentials
        if (requestUrl.pathname === '/api/credentials' || requestUrl.pathname === '/api/oauth-credentials') {
          const isOAuth = requestUrl.pathname === '/api/oauth-credentials';
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          // GET: Fetch existing keys for a token
          if (request.method === 'GET') {
            const accessToken = request.headers.get('X-Access-Token');
            if (!accessToken) {
              return jsonResponse({ error: 'X-Access-Token header is required.' }, 400, headers);
            }
            const query = isOAuth ? "SELECT oauth_credentials FROM api_credentials WHERE access_token = ? AND oauth_credentials != ''" : "SELECT api_keys FROM api_credentials WHERE access_token = ? AND api_keys != ''";
            const result = await env.DB.prepare(query).bind(accessToken.trim()).first<any>();
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

              if (isOAuth) {
                const oauthInput = body.oauth_credentials;
                if (!oauthInput || typeof oauthInput !== 'string' || oauthInput.trim() === '') {
                  return jsonResponse({ error: 'OAuth credentials are required.' }, 400, headers);
                }
                const oauthKeys = oauthInput.split(/[\s,]+/).map(k => k.trim()).filter(k => k);
                const oauthString = oauthKeys.join(',');

                const stmt = env.DB.prepare(
                  `INSERT INTO api_credentials (access_token, oauth_credentials, current_oauth_index, oauth_key_states, api_keys, current_key_index, key_states)
                   VALUES (?, ?, 0, '[]', '', 0, '[]')
                   ON CONFLICT(access_token) DO UPDATE SET
                     oauth_credentials = excluded.oauth_credentials,
                     current_oauth_index = 0,
                     oauth_key_states = '[]'`
                );
                await stmt.bind(accessToken, oauthString).run();
              } else {
                const keysInput = body.api_keys;
                if (!keysInput || typeof keysInput !== 'string' || keysInput.trim() === '') {
                  return jsonResponse({ error: 'API keys are required.' }, 400, headers);
                }
                const apiKeys = keysInput.split(/[\s,]+/).map(k => k.trim()).filter(k => k);
                const apiKeysString = apiKeys.join(',');

                const stmt = env.DB.prepare(
                  `INSERT INTO api_credentials (access_token, api_keys, current_key_index, key_states, oauth_credentials, current_oauth_index, oauth_key_states)
                   VALUES (?, ?, 0, '[]', '', 0, '[]')
                   ON CONFLICT(access_token) DO UPDATE SET
                     api_keys = excluded.api_keys,
                     current_key_index = 0,
                     key_states = '[]'`
                );
                await stmt.bind(accessToken, apiKeysString).run();
              }

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

              if (isOAuth) {
                const stmt = env.DB.prepare("UPDATE api_credentials SET oauth_credentials = '', current_oauth_index = 0, oauth_key_states = '[]' WHERE access_token = ?");
                const { meta } = await stmt.bind(accessToken.trim()).run();
                if (meta.changes > 0) {
                  return jsonResponse({ message: 'OAuth credentials cleared successfully.' }, 200, headers);
                }
              } else {
                const stmt = env.DB.prepare("DELETE FROM api_credentials WHERE access_token = ?");
                const { meta } = await stmt.bind(accessToken.trim()).run();
                if (meta.changes > 0) {
                  return jsonResponse({ message: 'Access Token deleted successfully.' }, 200, headers);
                }
              }
              return jsonResponse({ message: 'Access Token not found.' }, 404, headers);
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

                const stmt = env.DB.prepare("SELECT * FROM api_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?");
                const logs = await stmt.bind(limit, offset).all();

                const countStmt = env.DB.prepare("SELECT COUNT(*) as total FROM api_logs");
                const totalResult = await countStmt.first<{ total: number }>();
                const total = totalResult?.total || 0;

                return jsonResponse({ logs: logs.results, total, page, limit }, 200, headers);
              } catch (e: any) {
                console.error("Error fetching logs:", e);
                return jsonResponse({ error: 'Failed to fetch logs.' }, 500, headers);
              }
            }

            // DELETE: Clear all logs
            if (request.method === 'DELETE') {
              try {
                const stmt = env.DB.prepare("DELETE FROM api_logs");
                const { meta } = await stmt.bind().run();

                return jsonResponse({
                  message: `${meta.changes} logs deleted successfully.`,
                  deletedCount: meta.changes
                }, 200, headers);
              } catch (e: any) {
                console.error("Error clearing all logs:", e);
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
                  const stmt = env.DB.prepare("DELETE FROM api_logs WHERE id = ?");
                  const { meta } = await stmt.bind(logId).run();

                  if (meta.changes > 0) {
                    return jsonResponse({ message: 'Log deleted successfully.' }, 200, headers);
                  } else {
                    return jsonResponse({ message: 'Log not found.' }, 404, headers);
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

        // Handle Statistics Trends API
        if (requestUrl.pathname === '/api/statistics/trends') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);
          if (request.method === 'GET') {
            try {
              // Group usage by date to provide trend data
              const stmt = env.DB.prepare(`
                SELECT 
                  usage_date, 
                  SUM(request_count) as total_requests, 
                  SUM(success_count) as total_success, 
                  SUM(error_429_count) as total_429
                FROM api_key_usage 
                GROUP BY usage_date 
                ORDER BY usage_date ASC
                LIMIT 30
              `);
              const result = await stmt.all();
              return jsonResponse(result.results, 200, headers);
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
              const stmt = env.DB.prepare("SELECT * FROM api_key_usage ORDER BY usage_date DESC, request_count DESC");
              const result = await stmt.all();
              return jsonResponse(result.results, 200, headers);
            } catch (e: any) {
              console.error("Error fetching statistics:", e);
              return jsonResponse({ error: 'Failed to fetch statistics.' }, 500, headers);
            }
          }

          if (request.method === 'DELETE') {
            try {
              const stmt = env.DB.prepare("DELETE FROM api_key_usage");
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
      if (enableLogging) {
        // Log the OPTIONS request and its response
        const result = await logRequest(env, request);
        const startTime = result.startTime;
        const logId = result.logId;
        const response = handleOptions(request);
        ctx.waitUntil(logResponse(env, startTime, response.clone(), logId));
        return response;
      } else {
        return handleOptions(request);
      }
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

      // Initialize logging variables
      let startTime: number = 0;
      let logId: number | undefined;
      const enableLogging = env.ENABLE_API_LOGGING === "true";

      if (enableLogging) {
        // Log the incoming request
        const result = await logRequest(env, request, accessToken);
        startTime = result.startTime;
        logId = result.logId;
      }

      const id = env.KEY_ROTATOR.idFromName(accessToken);
      const stub = env.KEY_ROTATOR.get(id, { locationHint: 'wnam' });

      const forwardRequest = new Request(request.url, request);
      forwardRequest.headers.set("X-Access-Token", accessToken);
      
      if (openAIMode) {
        forwardRequest.headers.set("X-Auth-Mode", "openai");
      } else if (googleMode) {
        forwardRequest.headers.set("X-Auth-Mode", "google");
      } else if (claudeMode) {
        forwardRequest.headers.set("X-Auth-Mode", "claude");
      }

      const response = await stub.fetch(forwardRequest);

      if (enableLogging && logId) {
        // Log the response (async, non-blocking)
        ctx.waitUntil(logResponse(env, startTime, response.clone(), logId));
      }

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
