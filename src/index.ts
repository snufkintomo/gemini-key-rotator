import adminHtml from './admin.html';
import loginHtml from './login.html';
import * as cookie from 'cookie';
import { KeyRotator } from './rotator';

// --- Types ---
interface Env {
  DB: D1Database;
  GEMINI_API_BASE_URL?: string;
  ADMIN_ACCESS_TOKEN?: string;
  KEY_ROTATOR: DurableObjectNamespace;
}

// --- Authentication ---
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

// --- Cloudflare Worker Entry Point ---
export default {
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
                const { token } = await request.json<{ token: string }>();
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
    if (requestUrl.pathname.startsWith('/admin') || requestUrl.pathname.startsWith('/api/credentials')) {
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


        // Handle API calls for credentials
        if (requestUrl.pathname === '/api/credentials') {
          const corsHeaders = getCorsHeaders(request);
          const headers = new Headers(corsHeaders);

          // GET: Fetch existing keys for a token
          if (request.method === 'GET') {
            const accessToken = request.headers.get('X-Access-Token');
            if (!accessToken) {
              return jsonResponse({ error: 'X-Access-Token header is required.' }, 400, headers);
            }
            const stmt = env.DB.prepare("SELECT api_keys FROM api_credentials WHERE access_token = ? AND api_keys != ''");
            const result = await stmt.bind(accessToken.trim()).first<{ api_keys: string }>();
            return jsonResponse(result || {}, 200, headers);
          }

          // POST: Create or update credentials
          if (request.method === 'POST') {
            try {
              const body = await request.json<{ access_token: string; api_keys: string }>();
              const { access_token: rawAccessToken, api_keys: keysInput } = body;
              const accessToken = rawAccessToken?.trim();

              if (!accessToken || accessToken.length < 10) {
                return jsonResponse({ error: 'A valid Access Token (at least 10 characters) is required.' }, 400, headers);
              }
              if (!keysInput || typeof keysInput !== 'string' || keysInput.trim() === '') {
                return jsonResponse({ error: 'API keys are required and must be a non-empty string.' }, 400, headers);
              }

              const apiKeys = keysInput.split(/[\s,]+/).map(k => k.trim()).filter(k => k);
              if (apiKeys.length === 0) {
                return jsonResponse({ error: 'No API keys were provided.' }, 400, headers);
              }
              const apiKeysString = apiKeys.join(',');

              const stmt = env.DB.prepare(
                `INSERT INTO api_credentials (access_token, api_keys, current_key_index, key_states)
                 VALUES (?, ?, 0, '[]')
                 ON CONFLICT(access_token) DO UPDATE SET
                   api_keys = excluded.api_keys,
                   current_key_index = 0,
                   key_states = '[]'`
              );
              await stmt.bind(accessToken, apiKeysString).run();

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

              const stmt = env.DB.prepare("DELETE FROM api_credentials WHERE access_token = ?");
              const { meta } = await stmt.bind(accessToken.trim()).run();

              if (meta.changes > 0) {
                return jsonResponse({ message: 'Access Token deleted successfully.' }, 200, headers);
              } else {
                return jsonResponse({ message: 'Access Token not found.' }, 404, headers);
              }
            } catch (e: any) {
              console.error("Error deleting Access Token:", e);
              return jsonResponse({ error: 'Failed to process request.' }, 500, headers);
            }
          }
          
          headers.set('Allow', 'GET, POST, DELETE, OPTIONS');
          return new Response('Method Not Allowed', { status: 405, headers });
        }
        
        return new Response('Not Found', { status: 404 });
    }

    // --- Main Proxy Logic ---
    if (request.method === 'OPTIONS') {
      return handleOptions(request);
    }

    try {
      let accessToken: string | null = null;
      let openAIMode = false;
      let googleHeaderKeyMode = false;

      const authHeader = request.headers.get("Authorization");
      if (authHeader && authHeader.startsWith("Bearer ")) {
        accessToken = authHeader.substring(7).trim();
        openAIMode = true;
      } else {
        const headerKey = request.headers.get("x-goog-api-key");
        if (headerKey) {
          accessToken = headerKey.trim();
          googleHeaderKeyMode = true;
        } else {
          const keyParam = requestUrl.searchParams.get("key");
          if (keyParam) {
            accessToken = keyParam.trim();
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
      if (openAIMode) {
        forwardRequest.headers.set("X-Auth-Mode", "openai");
      } else if (googleHeaderKeyMode) {
        forwardRequest.headers.set("X-Auth-Mode", "google");
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
    const deploymentOrigin = new URL(request.url).origin;

    const allowedOrigins: string[] = [
        "http://localhost",
        "http://127.0.0.1",
        deploymentOrigin,
    ];

    const origin = requestOrigin || "";
    // Use startsWith for localhost to allow different ports
    if (allowedOrigins.some(allowed => origin.startsWith(allowed))) {
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS, DELETE",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, x-goog-api-key, X-Access-Token",
            "Access-Control-Max-Age": "86400",
        };
    }
    // Default restrictive headers if origin not allowed
    return {
        "Access-Control-Allow-Origin": "null",
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
