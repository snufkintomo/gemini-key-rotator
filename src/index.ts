import adminHtml from './admin.html';

// --- Types ---
interface Env {
  DB: D1Database;
  GEMINI_API_BASE_URL?: string;
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

// --- Cloudflare Worker Entry Point ---
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: any
  ): Promise<Response> {
    const requestUrl = new URL(request.url);

    // --- Admin & API Routes ---

    // 1. Serve the admin panel HTML
    if (request.method === 'GET' && requestUrl.pathname === '/admin') {
      return new Response(adminHtml, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // 2. Handle API calls for credentials
    if (requestUrl.pathname === '/api/credentials') {
      // GET: Fetch existing keys for a token
      if (request.method === 'GET') {
        const accessToken = requestUrl.searchParams.get('access_token');
        if (!accessToken) {
          return jsonResponse({ error: 'Access token query parameter is required.' }, 400);
        }
        const stmt = env.DB.prepare("SELECT api_keys FROM api_credentials WHERE access_token = ?");
        const result = await stmt.bind(accessToken).first<{ api_keys: string }>();
        return jsonResponse(result || {});
      }

      // POST: Create or update credentials
      if (request.method === 'POST') {
        try {
          const body = await request.json<{ access_token: string; api_keys: string }>();
          const { access_token: accessToken, api_keys: keysInput } = body;

          if (!accessToken || typeof accessToken !== 'string' || accessToken.length < 10) {
            return jsonResponse({ error: 'A valid Access Token (at least 10 characters) is required.' }, 400);
          }
          if (!keysInput || typeof keysInput !== 'string') {
            return jsonResponse({ error: 'API keys are required and must be a string.' }, 400);
          }

          const apiKeys = keysInput.split(/[\s,]+/).map(k => k.trim()).filter(k => k.startsWith('AIzaSy'));
          if (apiKeys.length === 0) {
            return jsonResponse({ error: 'No valid Gemini API keys were provided.' }, 400);
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

          return jsonResponse({ access_token: accessToken });

        } catch (e: any) {
          console.error("Error creating/updating credentials:", e);
          return jsonResponse({ error: 'Failed to process request. Ensure you are sending valid JSON.' }, 500);
        }
      }
      
      // DELETE: Remove credentials for a token
      if (request.method === 'DELETE') {
        try {
          const body = await request.json<{ access_token: string }>();
          const { access_token: accessToken } = body;

          if (!accessToken || typeof accessToken !== 'string') {
            return jsonResponse({ error: 'Access Token is required.' }, 400);
          }

          const stmt = env.DB.prepare("DELETE FROM api_credentials WHERE access_token = ?");
          const { success } = await stmt.bind(accessToken).run();

          if (success) {
            return jsonResponse({ message: 'Credentials deleted successfully.' });
          } else {
            return jsonResponse({ error: 'Failed to delete credentials.' }, 500);
          }
        } catch (e: any) {
          console.error("Error deleting credentials:", e);
          return jsonResponse({ error: 'Failed to process request. Ensure you are sending valid JSON.' }, 500);
        }
      }
      
      // Return 405 Method Not Allowed for other methods on this path
      return new Response('Method Not Allowed', { status: 405 });
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
        accessToken = authHeader.substring(7);
        openAIMode = true;
      } else {
        const headerKey = request.headers.get("x-goog-api-key");
        if (headerKey) {
          accessToken = headerKey;
          googleHeaderKeyMode = true;
        } else {
          accessToken = requestUrl.searchParams.get("key");
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

      let response = await doFetch();

      // Retry for transient errors
      const maxRetries = 3;
      for (let i = 0; i < maxRetries && [502, 524].includes(response.status); i++) {
        await new Promise(res => setTimeout(res, 1000 * (i + 1)));
        response = await doFetch();
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
        response = await doFetch();
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
      setCorsHeaders(resHeaders);

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
function jsonResponse(data: any, status = 200): Response {
  const headers = new Headers({
    'Content-Type': 'application/json;charset=UTF-8',
  });
  setCorsHeaders(headers);
  return new Response(JSON.stringify(data), { status, headers });
}

// --- CORS Handling ---
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, x-goog-api-key, X-Access-Token",
};

function setCorsHeaders(headers: Headers) {
  Object.entries(corsHeaders).forEach(([key, value]) => {
    headers.set(key, value);
  });
  headers.set("Access-Control-Max-Age", "86400");
}

function handleOptions(request: Request): Response {
  if (
    request.headers.get("Origin") !== null &&
    request.headers.get("Access-Control-Request-Method") !== null &&
    request.headers.get("Access-Control-Request-Headers") !== null
  ) {
    return new Response(null, { headers: corsHeaders });
  } else {
    return new Response(null, {
      headers: { Allow: "GET, HEAD, POST, OPTIONS" },
    });
  }
}
