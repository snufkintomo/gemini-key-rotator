import adminHtml from './admin.html';
import loginHtml from './login.html';
import * as cookie from 'cookie';

// --- Types ---
interface Env {
  DB: D1Database;
  GEMINI_API_BASE_URL?: string;
  ADMIN_ACCESS_TOKEN?: string;
}

interface KeyState {
  exhaustedUntil?: number;
}

interface ApiCredentials {
  api_keys: string;
  current_key_index: number;
  key_states: string | null; // JSON string of KeyState[]
}

// --- Configuration ---
const DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta2";

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
      const apiBaseUrl = env.GEMINI_API_BASE_URL || DEFAULT_BASE;
      
      // 1. Extract Access Token
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

      // 2. Fetch API Keys, index, and states from D1
      const stmt = env.DB.prepare("SELECT api_keys, current_key_index, key_states FROM api_credentials WHERE access_token = ?");
      const dbResult = await stmt.bind(accessToken).first<ApiCredentials>();

      if (!dbResult || !dbResult.api_keys) {
        return new Response("Unauthorized: Invalid access token.", { status: 401 });
      }

      const apiKeys: string[] = dbResult.api_keys.split(',').map(k => k.trim()).filter(k => k);
      if (apiKeys.length === 0) {
        return new Response("Internal configuration error: No API keys available for this user.", { status: 503 });
      }

      // Parse key states from DB or initialize if null/invalid
      let keyStates: KeyState[];
      try {
        keyStates = dbResult.key_states ? JSON.parse(dbResult.key_states) : [];
        if (keyStates.length !== apiKeys.length) {
           // If the number of keys changed, reset the states
           keyStates = apiKeys.map(() => ({}));
        }
      } catch {
        keyStates = apiKeys.map(() => ({}));
      }

      let keyIndexToUse: number | null = null;
      let startingKeyIndex = dbResult.current_key_index || 0;

      // --- Utility to get next active key index ---
      const getNextKeyIndex = (): number | null => {
        const now = Date.now();
        for (let i = 0; i < apiKeys.length; i++) {
          const idx = (startingKeyIndex + i) % apiKeys.length;
          const state = keyStates[idx];
          if (!state || !state.exhaustedUntil || state.exhaustedUntil < now) {
            return idx;
          }
        }
        return null;
      };

      keyIndexToUse = getNextKeyIndex();

      if (keyIndexToUse === null) {
        return new Response("All API keys for your account are currently exhausted. Please try again later.", { status: 429 });
      }
      let apiKey = apiKeys[keyIndexToUse];

      // 3. Proxy the request
      const targetUrl = new URL(requestUrl.pathname + requestUrl.search, apiBaseUrl);
      const forwardHeaders = new Headers(request.headers);
      ["host", "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "x-forwarded-proto", "x-real-ip"].forEach(h => forwardHeaders.delete(h));

      const updateAuth = (key: string) => {
        if (openAIMode) {
          forwardHeaders.set("Authorization", "Bearer " + key);
        } else if (googleHeaderKeyMode) {
          forwardHeaders.set("x-goog-api-key", key);
        } else {
          if (requestUrl.searchParams.has("key")) {
            targetUrl.searchParams.delete("key");
          }
          targetUrl.searchParams.set("key", key);
        }
      };

      updateAuth(apiKey);

      const methodCanHaveBody = ['POST', 'PUT', 'PATCH'].includes(request.method.toUpperCase());
      const doFetch = () => fetch(targetUrl.toString(), {
        method: request.method,
        headers: forwardHeaders,
        body: methodCanHaveBody && request.body ? request.clone().body : null,
        redirect: 'follow'
      });

      const isStreaming = requestUrl.pathname.includes(":stream") || requestUrl.pathname.includes("streamGenerateContent");

      const doFetchWithContentRetry = async (): Promise<Response> => {
        const maxContentRetries = 3;
        let lastResponse: Response | undefined = undefined;

        for (let i = 0; i < maxContentRetries; i++) {
          const response = await doFetch();
          lastResponse = response;

          if (!response.ok) {
            // Not a 200 OK, so no need to check content.
            // The outer retry loops for 5xx or 429 will handle this.
            return response;
          }

          // If we are here, response.ok is true.
          if (isStreaming) {
            if (!response.body) {
              console.log(`Streaming response body is null, retry ${i + 1}/${maxContentRetries}`);
              if (i < maxContentRetries - 1) await new Promise(res => setTimeout(res, 1000));
              continue;
            }

            const [stream1, stream2] = response.body.tee();
            const reader = stream1.getReader();
            
            try {
              const { value, done } = await reader.read();
              
              if (done) {
                // Stream ended immediately. This is an empty response.
                console.log(`Streaming response was empty, retry ${i + 1}/${maxContentRetries}`);
                if (i < maxContentRetries - 1) await new Promise(res => setTimeout(res, 1000));
                continue; // Retry
              }

              // We have the first chunk, that's good enough. Let the client consume the rest.
              // We must return a new response with the second stream.
              return new Response(stream2, {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
              });

            } catch (e) {
              console.error(`Error reading first chunk of stream, retry ${i + 1}/${maxContentRetries}`, e);
              if (i < maxContentRetries - 1) await new Promise(res => setTimeout(res, 1000));
              continue; // Retry
            } finally {
               reader.releaseLock();
               stream1.cancel().catch(() => {}); // Cancel the inspection stream
            }
          } else {
            // Non-streaming logic
            const clonedResponse = response.clone();
            try {
              const body = await clonedResponse.json() as GeminiResponse;
              if (body.candidates && body.candidates.length > 0 && body.candidates[0].content && body.candidates[0].content.parts && body.candidates[0].content.parts.length > 0) {
                return response; // Good response
              }
              console.log(`Response content invalid, retry ${i + 1}/${maxContentRetries}`);
            } catch (e) {
              console.log(`Response JSON parse failed, retry ${i + 1}/${maxContentRetries}`, e);
            }
          }
          
          // If we reach here, it means a retry is needed for the non-streaming case.
          if (i < maxContentRetries - 1) {
            await new Promise(res => setTimeout(res, 1000 * (i + 1)));
          }
        }
        
        // If all retries fail, return the last response we received.
        return lastResponse!;
      };

      let response = await doFetchWithContentRetry();

      // Retry for transient errors
      const maxRetries = 3;
      for (let i = 0; i < maxRetries && [502, 524].includes(response.status); i++) {
        await new Promise(res => setTimeout(res, 1000 * (i + 1)));
        response = await doFetchWithContentRetry();
      }

      // 4. Retry logic for exhausted keys
      let attemptCount = 1;
      while ([401, 403, 429].includes(response.status) && attemptCount < apiKeys.length) {
        const cooldown = response.status === 429 ? (2 * 60 * 1000) : (1 * 60 * 1000);
        keyStates[keyIndexToUse] = { exhaustedUntil: Date.now() + cooldown };

        const nextKeyIndex = getNextKeyIndex();
        if (nextKeyIndex === null) {
          keyIndexToUse = null; // No more keys to try
          break;
        }
        keyIndexToUse = nextKeyIndex;
        apiKey = apiKeys[keyIndexToUse];
        attemptCount++;
        updateAuth(apiKey);
        response = await doFetchWithContentRetry();
      }

      // 5. Update the key index and states in D1 for the next request
      if (keyIndexToUse !== null) {
        const nextIndexForDb = (keyIndexToUse + 1) % apiKeys.length;
        const keyStatesJson = JSON.stringify(keyStates);
        const updateStmt = env.DB.prepare("UPDATE api_credentials SET current_key_index = ?, key_states = ? WHERE access_token = ?");
        ctx.waitUntil(updateStmt.bind(nextIndexForDb, keyStatesJson, accessToken).run());
      } else {
        // All keys were exhausted, so just save the updated states
        const keyStatesJson = JSON.stringify(keyStates);
        const updateStmt = env.DB.prepare("UPDATE api_credentials SET key_states = ? WHERE access_token = ?");
        ctx.waitUntil(updateStmt.bind(keyStatesJson, accessToken).run());
      }

      if ([401, 403, 429].includes(response.status)) {
        return new Response(`Error: All available API keys are exhausted or invalid. (Last Status: ${response.status})`, { status: 429 });
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
