# Gemini Key Rotator for Cloudflare Workers

This project provides a robust API key rotator for the Google Gemini API, built to run on the Cloudflare Workers serverless platform. It uses Cloudflare D1 for persistent, stateful storage of API keys and access tokens, ensuring true key rotation and cooldowns across all worker instances.

## Features

- **Stateful Key Rotation**: Rotates through a list of Gemini API keys, ensuring each key is used in sequence.
- **Persistent Cooldowns**: If a key is exhausted (e.g., hits a rate limit), it's put on a temporary cooldown that is respected by all worker instances.
- **Secure Admin Panel**: A built-in admin panel, protected by a single `ADMIN_ACCESS_TOKEN`, allows for the secure management of user access tokens and their associated API keys.
- **Multiple Authentication Styles**: Supports OpenAI-style Bearer Tokens, Google-style `x-goog-api-key` headers, and `?key=` query parameters for flexible integration.
- **Secure by Default**: All sensitive credentials are stored in a Cloudflare D1 database. The admin panel is protected by a login system that uses a secure, encrypted, HttpOnly session cookie.

## Setup and Deployment

Follow these steps to set up and deploy your own instance of the Gemini Key Rotator.

### 1. Clone the Repository

```bash
git clone <repository-url>
cd gemini-key-rotator
```

### 2. Install Dependencies

This project uses `wrangler` for managing the Cloudflare Worker and `typescript` for development.

```bash
npm install
```

### 3. Log in to Cloudflare

Authenticate `wrangler` with your Cloudflare account.

```bash
npx wrangler login
```

### 4. Create a D1 Database

Create a new D1 database to store the credentials.

```bash
npx wrangler d1 create gemini-key-rotator
```

Wrangler will output the `database_id`. Copy this ID.

### 5. Configure `wrangler.toml`

Open the `wrangler.toml` file and update the `[[d1_databases]]` section with the `database_id` you just received.

```toml
[[d1_databases]]
binding = "DB" # This binding name is used in the code
database_name = "gemini-key-rotator"
database_id = "your-database-id-here"
preview_database_id = "your-database-id-here"
```

Next, set your `ADMIN_ACCESS_TOKEN` in the `[vars]` section. This token will be your password for the admin panel and will also be used to encrypt session cookies. **Choose a strong, unique value.**

```toml
[vars]
ADMIN_ACCESS_TOKEN = "your-secret-token" # Replace with your actual token
```

### 6. Create the Database Table

Run the following command to create the necessary `api_credentials` table in your new database.

```bash
npx wrangler d1 execute gemini-key-rotator --command="CREATE TABLE IF NOT EXISTS api_credentials (access_token TEXT PRIMARY KEY, api_keys TEXT NOT NULL, current_key_index INTEGER DEFAULT 0, key_states TEXT DEFAULT '[]', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
```

### 7. (Optional) Configure a Custom API Proxy

If you are using your own proxy for the Gemini API, you can configure it in `wrangler.toml`. Open the file and set the `GEMINI_API_BASE_URL` variable.

```toml
[vars]
GEMINI_API_BASE_URL = "https://your-proxy-url.com/"
```

If you are not using a custom proxy, you can leave this variable empty.

### 8. Deploy the Worker

Deploy the worker to your Cloudflare account.

```bash
npx wrangler deploy
```

After deployment, `wrangler` will provide you with your worker's URL (e.g., `https://gemini-key-rotator.your-subdomain.workers.dev`).

## Usage

### Managing Credentials

To manage your API keys, navigate to the admin panel by adding `/admin` to your worker's URL:

**`https://<your-worker-url>/admin`**

You will be prompted to log in with the `ADMIN_ACCESS_TOKEN` you configured in `wrangler.toml`.

On the admin page, you can:
- **Create**: Enter a new, unique Access Token and paste your Gemini API keys (one per line or comma-separated) to create a new credential set.
- **Update**: Enter an existing Access Token to load and edit the associated API keys.
- **Delete**: Enter an existing Access Token and click the "Delete" button to remove the credentials.

### Making API Requests

Once you have saved your credentials, you can make requests to the Gemini API through your worker's URL. Use your Access Token in one of the following ways.

*Replace `<your-worker-url>` with your actual worker URL and `<your-access-token>` with the token you configured.*

#### 1. OpenAI-Style (Bearer Token)
Use this for compatibility with OpenAI libraries.

```bash
curl -X POST \\
  -H "Authorization: Bearer <your-access-token>" \\
  -H "Content-Type: application/json" \\
  -d '{"model": "gemini-pro", "messages": [{"role": "user", "content": "Explain how a transformer model works"}]}' \\
  "https://<your-worker-url>/v1beta/openai/chat/completions"
```

#### 2. Google-Style (Header)

```bash
curl -X POST \\
  -H "x-goog-api-key: <your-access-token>" \\
  -H "Content-Type: application/json" \\
  -d '{"contents":[{"parts":[{"text":"Explain how a transformer model works"}]}]}' \\
  "https://<your-worker-url>/v1beta/models/gemini-pro:generateContent"
```

#### 3. Google-Style (Query Parameter)

```bash
curl -X POST \\
  -H "Content-Type: application/json" \\
  -d '{"contents":[{"parts":[{"text":"Explain how a transformer model works"}]}]}' \\
  "https://<your-worker-url>/v1beta/models/gemini-pro:generateContent?key=<your-access-token>"
```
