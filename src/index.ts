// --- Types ---
interface Env {
  // Secrets (configured in Cloudflare dashboard or wrangler.toml)
  API_KEYS: string; // Comma-separated or JSON array string
  ACCESS_TOKEN?: string; // Optional access token (this is the one we expect from the environment)

  // Variables (configured in Cloudflare dashboard or wrangler.toml)
  GEMINI_API_BASE_URL?: string; // Optional override for base URL
}

interface KeyState {
  exhaustedUntil?: number; // Timestamp (ms since epoch) when the key might be available again
}

// --- Configuration & State (Initialized once per worker instance) ---
let apiKeys: string[] = [];
let keyStates: KeyState[] = [];
let currentKeyIndex = 0;
let isInitialized = false; // Flag to prevent re-initialization within the same instance

const DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta2";
let apiBaseUrl = DEFAULT_BASE;
let configuredAccessToken: string | undefined; // Renamed for clarity

// --- Initialization Function (called once per instance) ---
function initializeConfig(env: Env): void {
  if (isInitialized) return;

  console.log("Initializing configuration for worker instance...");

  // Base URL
  apiBaseUrl = env.GEMINI_API_BASE_URL || DEFAULT_BASE;

  // Access Token (from environment)
  configuredAccessToken = env.ACCESS_TOKEN;
  if (configuredAccessToken) {
    console.log("Access token protection via query parameter 'accessToken' enabled.");
  }

  // API Keys
  const keyEnv = env.API_KEYS || "";
  try {
    apiKeys = keyEnv.startsWith("[")
      ? JSON.parse(keyEnv)
      : keyEnv.split(",").map(k => k.trim()).filter(k => k);
  } catch (e) {
    console.error("Error parsing API_KEYS environment variable:", e);
    apiKeys = []; // Ensure it's an empty array on error
  }

  if (apiKeys.length === 0) {
    console.error("FATAL: No API keys loaded. The worker will not function correctly.");
  } else {
    console.log(`Loaded ${apiKeys.length} API keys.`);
  }

  // Initialize key states based on loaded keys
  keyStates = apiKeys.map(() => ({}));

  isInitialized = true;
}

// --- Utility: get next active key index ---
function getNextKeyIndex(): number | null {
  if (apiKeys.length === 0) {
    return null; // No keys loaded
  }

  const now = Date.now();
  for (let i = 0; i < apiKeys.length; i++) {
    const idx = (currentKeyIndex + i) % apiKeys.length;
    const state = keyStates[idx];
    if (!state || !state.exhaustedUntil || state.exhaustedUntil < now) {
      currentKeyIndex = (idx + 1) % apiKeys.length;
      return idx;
    }
  }
  console.warn("All API keys are currently marked as exhausted.");
  return null;
}

// --- Cloudflare Worker Entry Point ---
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {

    initializeConfig(env);

    if (request.method === 'OPTIONS') {
      return handleOptions(request);
    }

    const requestUrl = new URL(request.url); // Parse the incoming request URL

    try {
      let OpenAIMode = 0;
      let GoogleHeaderKeyMode = 0;
      // Optionally enforce access token from query parameter
      if (configuredAccessToken) {
	      const providedBearer = request.headers.get("Authorization");
		    if (providedBearer === "Bearer " + configuredAccessToken) {
		      OpenAIMode = 1;
		    } else {
          const providedHeaderToken = request.headers.get("x-goog-api-key");
          if (providedHeaderToken === configuredAccessToken) {
            GoogleHeaderKeyMode = 1;
          } else {
		        const providedToken = requestUrl.searchParams.get("key");
		        if (providedToken !== configuredAccessToken) {
		          console.log(`Unauthorized access attempt: Missing or incorrect 'key' query parameter or 'x-goog-api-key' header.`);
              return new Response("Unauthorized", { status: 401 });
            }
          }
		    }
      }

      if (apiKeys.length === 0) {
         console.error("Request failed: No API keys configured.");
         return new Response("Internal configuration error: No API keys available.", { status: 503 });
      }

      // Determine target URL
      // Start with the base path and existing query parameters from the incoming request
      const targetUrl = new URL(requestUrl.pathname + requestUrl.search, apiBaseUrl);

      let keyIndex = getNextKeyIndex();
      if (keyIndex === null) {
        console.error("All API keys are exhausted – cannot fulfill request");
        return new Response(`All API keys exhausted (quota exceeded). Please try again later.`, { status: 429 });
      }
      let apiKey = apiKeys[keyIndex];

      if (OpenAIMode === 0 || GoogleHeaderKeyMode === 0 ) {
        // IMPORTANT: Remove the 'key' query parameter if it was used for worker auth,
        // so it's not forwarded to the Gemini API.
        if (configuredAccessToken && targetUrl.searchParams.has("key")) {
          targetUrl.searchParams.delete("key");
        }
		
        targetUrl.searchParams.set("key", apiKey); // Add the Gemini API key
        console.log(`Using key index: ${keyIndex} for path: ${targetUrl.pathname}${targetUrl.search}`);
	    }

      const forwardHeaders = new Headers();
      for (const [h, v] of request.headers) {
        const lower = h.toLowerCase();
        if (lower === "host" || lower === "cf-connecting-ip" || lower === "cf-ipcountry" || lower === "cf-ray" || lower === "cf-visitor" || lower === "x-forwarded-proto" || lower === "x-real-ip" ) continue;
        forwardHeaders.set(h, v);
      }
      if (!forwardHeaders.has("content-type") && request.headers.has("content-type")) {
         forwardHeaders.set("content-type", request.headers.get("content-type")!);
      }
      if (request.method === 'POST' && !forwardHeaders.has('content-type')) {
          forwardHeaders.set('content-type', 'application/json');
      }
      forwardHeaders.set("accept", "application/json");

      if (OpenAIMode === 1) {
	      forwardHeaders.set("Authorization", "Bearer " + apiKey);
	    }

      if (GoogleHeaderKeyMode === 1) {
	      forwardHeaders.set("x-goog-api-key", apiKey);
	    }

      const methodCanHaveBody = ['POST', 'PUT', 'PATCH'].includes(request.method.toUpperCase());
      let response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: forwardHeaders,
		    body: methodCanHaveBody && request.body ? request.clone().body : null,
        redirect: 'follow'
      });

      // Retry logic for transient server errors (502, 524)
      const maxRetries = 3;
      for (let i = 0; i < maxRetries && [502, 524].includes(response.status); i++) {
          console.warn(`Received status ${response.status}. Retrying... (Attempt ${i + 1}/${maxRetries})`);
          await new Promise(res => setTimeout(res, 1000 * (i + 1))); // Linear backoff

          response = await fetch(targetUrl.toString(), {
              method: request.method,
              headers: forwardHeaders,
			        body: methodCanHaveBody && request.body ? request.clone().body : null,
              redirect: 'follow'
          });
      }

      let attemptCount = 1;
      const originalStatus = response.status;

      while ([401, 403, 429].includes(response.status) && attemptCount < apiKeys.length) {
        console.warn(`Key index ${keyIndex} (key starting with: ${apiKey.substring(0,5)}...) returned status ${response.status}. Attempting to switch API key...`);

        //const cooldown = response.status === 429 ? (60 * 60 * 1000) : (5 * 60 * 1000);  //60min and 5min
		    const cooldown = response.status === 429 ? (2 * 60 * 1000) : (1 * 60 * 1000);
        keyStates[keyIndex] = { exhaustedUntil: Date.now() + cooldown };

        const nextKeyIndex = getNextKeyIndex();
        if (nextKeyIndex === null) {
          console.error("No more available API keys to try after encountering status " + response.status);
          break;
        }
        keyIndex = nextKeyIndex;
        apiKey = apiKeys[keyIndex];

        // Update only the 'key' parameter on the targetUrl for retry
        if (OpenAIMode === 1) {
          forwardHeaders.delete("Authorization");
          forwardHeaders.set("Authorization", "Bearer " + apiKey);
        } else if (GoogleHeaderKeyMode === 1) {
          forwardHeaders.delete("x-goog-api-key");
          forwardHeaders.set("x-goog-api-key", apiKey);
        } else {
		      targetUrl.searchParams.set("key", apiKey);
		    }

        attemptCount++;
        console.log(`Retrying with key index: ${keyIndex} (key starting with: ${apiKey.substring(0,5)}...) (Attempt ${attemptCount}/${apiKeys.length}) to ${targetUrl.toString()}`);

        response = await fetch(targetUrl.toString(), {
            method: request.method,
            headers: forwardHeaders,
            body: methodCanHaveBody && request.body ? request.clone().body : null,
            redirect: 'follow'
        });
      }

      if ([401, 403, 429].includes(response.status)) {
          console.error(`All API keys tried failed. Last status: ${response.status}. Initial status: ${originalStatus}. Key index at failure: ${keyIndex}. Returning error to client.`);
          return new Response(`Error: All API keys are exhausted or invalid. (Last Status: ${response.status})`, { status: 429 });
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

// --- CORS Handling ---
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
  // "X-Access-Token" is no longer strictly needed here for THIS auth method,
  // but keeping it doesn't hurt if other parts of an app might use headers.
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Access-Token",
};

function setCorsHeaders(headers: Headers) {
  headers.set("Access-Control-Allow-Origin", corsHeaders["Access-Control-Allow-Origin"]);
  headers.set("Access-Control-Allow-Methods", corsHeaders["Access-Control-Allow-Methods"]);
  headers.set("Access-Control-Allow-Headers", corsHeaders["Access-Control-Allow-Headers"]);
  headers.set("Access-Control-Max-Age", "86400");
}

function handleOptions(request: Request): Response {
  if (
    request.headers.get("Origin") !== null &&
    request.headers.get("Access-Control-Request-Method") !== null &&
    request.headers.get("Access-Control-Request-Headers") !== null
  ) {
    const headers = new Headers(corsHeaders);
    return new Response(null, { headers: headers });
  } else {
    return new Response(null, {
      headers: { Allow: "GET, HEAD, POST, OPTIONS" },
    });
  }
}
