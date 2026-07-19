# Gemini Key Rotator

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/snufkintomo/gemini-key-rotator)

## Overview

The Gemini Key Rotator is a powerful, self-hosted Cloudflare Worker designed to provide resilient and scalable access to Google's Gemini API. It acts as a reverse proxy, intelligently rotating through a pool of Gemini API keys and Google OAuth 2.0 credentials to mitigate rate-limiting issues and ensure high availability.

The project features a modular architecture with native compatibility layers for **OpenAI**, **Claude (Anthropic)**, and **Google Gemini** APIs.

## Key Features

- **Multi-Protocol Support:**
    - **OpenAI Compatibility:** Drop-in replacement for OpenAI API (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`).
    - **Claude Compatibility:** Supports Claude's `/v1/messages` and `/v1/models` endpoints, including "thinking" mode.
    - **Gemini Native Support:** Full support for Google Gemini API formats.
- **Three-Level Dynamic Model Routing & Caching:**
    - **Level 1 (Proactive background sync):** Automatically scans and stores the precise model support maps for all active OAuth credentials during a 12-hour background Durable Object alarm.
    - **Level 2 (Reactive de-authorization):** Instantly flags a specific model as unsupported on a key upon receiving a 404 from Google, preventing future routing of that model to the same key.
    - **Level 3 (Optimistic fallback):** If a model is flagged as unavailable across all keys, the rotator falls back to healthy keys rather than throwing errors.
- **Advanced Key Rotation:**
    - Rotates through standard Gemini API Keys and Google OAuth 2.0 Credentials.
    - **First-Party Google Credentials:** Configured with authentic Google Gemini CLI Client credentials, providing clean, branded Google Consent screens and standard implicit scopes.
    - **Bypass AI Gateway for OAuth:** Stream and non-stream OAuth requests route directly to Google endpoints, bypassing the Cloudflare AI Gateway completely to prevent scope or validation issues.
    - **Sub-Millisecond High-Pressure Rotation:** Leverages in-memory synchronous index tracking and pre-fetch operations to completely remove storage/database writes from the request pathway, reducing key switch overhead to <1ms.
    - **Zero-Delay Failover:** Eliminates sleep delays when switching to a different API key during error recovery.
    - **Smart Handshake Timeout:** 15s connection timeouts prevent hung upstream connections from stalling resources.
    - **Zero-Latency Cache Prefetching:** Configures a 1-hour credentials cache TTL and automatically prefetches updates 5 minutes before expiration to completely eliminate D1 read latency spikes.
    - **Active Cache Invalidation:** Instantly evicts DO cache upon credentials update/delete to keep configuration current in real-time.
- **Secure Admin Panel & Statistics Filtering:** Web-based dashboard for managing access tokens, API keys, and monitoring system health.
    - **Clean Stats Noise Filtering (Scheme 2):** Filters out client-side 404 errors (routing/model typos) from statistics logging to prevent artificial success-rate drops, while preserving 403 errors for admin health monitoring.
    - **Multi-Admin isolation**: Usage stats, trends, and statistics purging are isolated per admin by default, with super-admin toggle overrides.
- **Detailed Logging:** Usage tracking, performance metrics, and request/response logging stored in **Cloudflare D1**.
- **AI Gateway Integration:** Seamless integration with Cloudflare AI Gateway for enhanced observability and caching.
- **OAuth 2.0 Management:** Built-in flow for authorizing and exchanging Google Cloud credentials with PKCE support.
- **Enhanced Statistics & Monitoring:** 
    - Real-time usage tracking by API Key, User Token, and Model.
    - **Advanced Token Performance Metrics:**
        - **Processed Tokens:** Sum of all input prompt tokens processed and output completion tokens generated.
        - **Cached Tokens (⚡):** Tracks prompt tokens served via Google's Context Caching (saving up to 75% on prompt costs for long histories).
        - **Saved Tokens (✨):** Displays the exact volume of input tokens saved by the rotator's built-in **Prompt Pruner**. The context manager dynamically trims redundant system instructions, duplicate history entries, and expired message buffers before sending payloads to Google.
    - Interactive summary cards for daily health checks.
    - Advanced filtering (Date Range, Search, 429 Errors).
    - CSV export for external analysis.
    - Automatic statistics cleanup mechanism.

## Architecture

Built on the latest Cloudflare Workers features:
- **Durable Objects:** Maintains global state for key rotation and rate limits.
- **D1 Database:** Relational storage for credentials and audit logs.
- **Streaming:** High-performance pass-through streaming for all AI protocols.

---

## Setup and Deployment

### 1. Prerequisites
- A Cloudflare account (Paid plan required for Durable Objects).
- Node.js and `npm` installed.
- `wrangler` CLI: `npm install -g wrangler`

### 2. Create Cloudflare Resources

#### a. Create D1 Database
```bash
wrangler d1 create gemini-key-rotator
```
Note the `database_id` from the output.

#### b. Initialize Database Schema
Apply the initial schema to your D1 database:
```bash
wrangler d1 execute gemini-key-rotator --command "
CREATE TABLE api_credentials (
    access_token TEXT PRIMARY KEY,
    api_keys TEXT,
    current_key_index INTEGER DEFAULT 0,
    key_states TEXT DEFAULT '[]',
    oauth_credentials TEXT DEFAULT '',
    current_oauth_index INTEGER DEFAULT 0,
    oauth_key_states TEXT DEFAULT '[]'
);
CREATE TABLE api_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    access_token TEXT,
    request_method TEXT,
    request_url TEXT,
    request_headers TEXT,
    request_body TEXT,
    response_status INTEGER,
    response_headers TEXT,
    response_body TEXT,
    duration_ms INTEGER
);
CREATE TABLE api_key_usage (
    raw_key TEXT,
    key_type TEXT,
    usage_date TEXT,
    user_access_token TEXT,
    mode TEXT,
    model TEXT,
    request_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    error_429_count INTEGER DEFAULT 0,
    PRIMARY KEY (raw_key, usage_date, user_access_token, mode, model)
);"
```

#### c. Create AI Gateway (Optional)
In your Cloudflare Dashboard, go to **AI > AI Gateway** and create a gateway named `gemini`.

### 3. Configuration

1. Copy the example configuration:
   ```bash
   cp wrangler.toml.example wrangler.toml
   ```
2. Update `wrangler.toml` with your `database_id`.
3. Set your environment variables (Secrets):
   ```bash
   wrangler secret put ADMIN_ACCESS_TOKEN    # Your dashboard password
   wrangler secret put OAUTH_CLIENT_ID       # From Google Cloud Console
   wrangler secret put OAUTH_CLIENT_SECRET   # From Google Cloud Console
   ```

### 4. Deploy
```bash
npm install
npm run deploy
```

---

## Usage Guide

### Admin Dashboard
Access the dashboard at `https://your-worker.workers.dev/admin`.
1. Log in with your `ADMIN_ACCESS_TOKEN`.
2. Create an **Access Token** (this is what you'll use in your AI apps).
3. Add **Gemini API Keys** (comma-separated) or use the **OAuth flow** to add Google Cloud credentials.

### API Examples

#### OpenAI Compatibility
```bash
curl https://your-worker.workers.dev/v1/chat/completions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.0-flash",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

#### Claude Compatibility (with Thinking)
```bash
curl https://your-worker.workers.dev/v1/messages \
  -H "x-api-key: YOUR_ACCESS_TOKEN" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-7-sonnet",
    "max_tokens": 1024,
    "thinking": {"type": "enabled", "budget_tokens": 1024},
    "messages": [{"role": "user", "content": "Think deeply about quantum physics."}]
  }'
```

#### Google Gemini Native
```bash
curl -X POST \
  -H "x-goog-api-key: YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Explain how a transformer model works"}]}]}' \
  "https://your-worker.workers.dev/v1beta/models/gemini-2.0-flash:generateContent"
```

---

## Contributing
Contributions are welcome! Please submit a pull request or open an issue.

## License
MIT License
