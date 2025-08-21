# Gemini Key Rotator

## Overview

The Gemini Key Rotator is a powerful, self-hosted Cloudflare Worker designed to provide resilient and scalable access to Google's Gemini API. It acts as a reverse proxy, intelligently rotating through a pool of API keys to mitigate rate-limiting issues and ensure high availability. This project also includes an OpenAI compatibility layer, allowing you to use Gemini with tools and libraries designed for the OpenAI API.

## Key Features

- **API Key Rotation:** Automatically rotates through a list of Gemini API keys to distribute requests and avoid rate limits.
- **OpenAI Compatibility:** A drop-in replacement for the OpenAI API, supporting `/chat/completions`, `/embeddings`, and `/models` endpoints.
- **Durable Objects:** Utilizes Cloudflare's Durable Objects to maintain the state of API keys and ensure consistent performance.
- **Secure Admin Panel:** A user-friendly interface for managing your access tokens and API keys, protected by an admin access token.
- **Multiple Authentication Modes:** Supports OpenAI-style Bearer Tokens, Google-style `x-goog-api-key` headers, and `key` query parameters.
- **CORS Handling:** Includes flexible CORS handling to allow requests from various origins.
- **Easy Deployment:** Deployable in minutes with Cloudflare's `wrangler` CLI.

## How It Works

The Gemini Key Rotator is built around a Cloudflare Worker that intercepts requests to the Gemini API. It uses a Durable Object, `KeyRotator`, to manage a pool of API keys for each access token. When a request comes in, the worker forwards it to the `KeyRotator`, which selects an available API key and proxies the request to the Gemini API. If a key is exhausted or invalid, the rotator automatically tries the next available key.

The project also includes a secure admin panel for managing your credentials. You can create, update, and delete access tokens and their associated API keys. The admin panel is protected by a secret admin access token that you configure in your Cloudflare Worker's environment variables.

## Setup and Deployment

### Prerequisites

- A Cloudflare account
- Node.js and npm installed
- `wrangler` CLI installed (`npm install -g wrangler`)

### 1. Clone the Repository

```bash
git clone https://github.com/snufkintomo/gemini-key-rotator.git
cd gemini-key-rotator
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Create Cloudflare Resources

Before deploying the worker, you'll need to create a D1 database and an AI Gateway.

#### a. Create a D1 Database

You can create a D1 database using the `wrangler` CLI:

```bash
wrangler d1 create gemini-key-rotator-db
```

This command will create a new D1 database and output the `database_id` in your `wrangler.toml` file.

#### b. Create an AI Gateway

Navigate to the **AI Gateway** section in your Cloudflare dashboard and create a new gateway. You can name it whatever you like. Once created, you'll need to note the **Gateway ID** and **Gateway Name** for the next step.

### 4. Configure `wrangler.toml`

Rename `wrangler.toml.example` to `wrangler.toml` and fill in your Cloudflare account details. The `database_id` for your D1 database should already be present.

```toml
name = "gemini-key-rotator"
main = "src/index.ts"
compatibility_date = "2024-05-02"

[[d1_databases]]
binding = "DB"
database_name = "gemini-key-rotator-db"
database_id = "your-database-id"

[durable_objects]
bindings = [
  { name = "KEY_ROTATOR", class_name = "KeyRotator" }
]
```

### 5. Set Environment Variables

You'll need to set a secret admin access token to protect your admin panel. You can do this in the Cloudflare dashboard or via the `wrangler` CLI.

```bash
wrangler secret put ADMIN_ACCESS_TOKEN
```

If you're using the Cloudflare AI Gateway, you'll also need to set the following secrets:

```bash
wrangler secret put CLOUDFLARE_AI_GATEWAY_ID
wrangler secret put CLOUDFLARE_AI_GATEWAY_NAME
```

You can also set an optional `GEMINI_API_BASE_URL` if you need to use a custom Gemini API endpoint.

### 6. Deploy the Worker

```bash
npm run deploy
```

## Usage

Once deployed, you can access the admin panel at `https://your-worker-url/admin`. You'll be prompted to enter your admin access token. After logging in, you can create a new access token and add your Gemini API keys.

The admin panel will provide you with `curl` examples for making requests to the Gemini API through your worker. You can use your access token as a Bearer Token (for OpenAI compatibility), an `x-goog-api-key` header, or a `key` query parameter.

### OpenAI-Style Example

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gemini-pro", "messages": [{"role": "user", "content": "Explain how a transformer model works"}]}' \
  "https://your-worker-url/chat/completions"
```

### Google-Style Example

```bash
curl -X POST \
  -H "x-goog-api-key: YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Explain how a transformer model works"}]}]}' \
  "https://your-worker-url/v1beta/models/gemini-pro:generateContent"
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you have any suggestions or find any bugs.

## License

This project is licensed under the MIT License.
