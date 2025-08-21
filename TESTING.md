# Testing Cloudflare Worker Gemini Key Rotator - Comprehensive AI API Calls

This document provides comprehensive `curl` commands to test all supported AI API endpoints through the deployed Cloudflare Worker, covering both Gemini-style and OpenAI-style requests. These tests assume that API keys have already been configured and associated with an access token via the admin panel (or directly in D1).

**Before you begin:**
- Replace `<your-worker-url>` with the actual URL of your deployed Cloudflare Worker (e.g., `https://gemini-key-rotator.your-subdomain.workers.dev`).
- Replace `<your-access-token>` with an access token that has associated Gemini API keys.
- Ensure your access token is linked to valid Gemini API keys.

---

## OpenAI-Compatible API Endpoints

These tests use the OpenAI compatibility layer provided by the worker. The worker will automatically route requests through the Cloudflare AI Gateway if `GEMINI_API_BASE_URL` is not set.

### 1. Chat Completions (`/chat/completions`) - POST

Tests the core chat functionality.

```bash
curl -X POST \
  -H "Authorization: Bearer <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [
      {"role": "user", "content": "Explain the concept of quantum entanglement in simple terms."}
    ]
  }' \
  "https://<your-worker-url>/chat/completions"
```

**Expected Output:** A JSON response containing the AI model's completion.

### 2. Embeddings (`/embeddings`) - POST

Tests the embedding generation functionality.

```bash
curl -X POST \
  -H "Authorization: Bearer <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "text-embedding-004",
    "input": "The quick brown fox jumps over the lazy dog."
  }' \
  "https://<your-worker-url>/embeddings"
```

**Expected Output:** A JSON response containing the embedding vector.

### 3. List Models (`/models`) - GET

Tests retrieving a list of available models.

```bash
curl -X GET \
  -H "Authorization: Bearer <your-access-token>" \
  "https://<your-worker-url>/models"
```

**Expected Output:** A JSON response listing available models in an OpenAI-compatible format.

### 4. Retrieve Specific Model (`/models/{model_id}`) - GET

Tests retrieving details for a specific model.

```bash
curl -X GET \
  -H "Authorization: Bearer <your-access-token>" \
  "https://<your-worker-url>/models/gemini-2.5-flash"
```

**Expected Output:** A JSON response with details for `gemini-2.5-flash` in an OpenAI-compatible format.

### 5. Chat Completions Stream (`/chat/completions`) - POST

Tests streaming chat completions.

```bash
curl -X POST \
  -H "Authorization: Bearer <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{ "model": "gemini-2.5-flash", "messages": [ { "role": "user", "content": "Tell me a very short story about a cat." } ], "stream": true }' \
  "https://<your-worker-url>/chat/completions"
```

**Expected Output:** A stream of JSON objects, each containing a chunk of the AI model's completion.

---

## Google Gemini API Endpoints

These tests use the native Google Gemini API style. The worker will automatically route requests through the Cloudflare AI Gateway if `GEMINI_API_BASE_URL` is not set.

### 6. Generate Content (`/v1beta/models/{model}:generateContent`) - POST (Header Auth)

Tests content generation using `x-goog-api-key` header authentication.

```bash
curl -X POST \
  -H "x-goog-api-key: <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [
      {"parts": [{"text": "Write a short poem about a starry night."}]}
    ]
  }' \
  "https://<your-worker-url>/v1beta/models/gemini-2.5-flash:generateContent"
```

**Expected Output:** A JSON response containing the AI model's generated content.

### 7. Generate Content (`/v1beta/models/{model}:generateContent`) - POST (Query Parameter Auth)

Tests content generation using `key` query parameter authentication.

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [
      {"parts": [{"text": "Write a short poem about a starry night."}]}
    ]
  }' \
  "https://<your-worker-url>/v1beta/models/gemini-2.5-flash:generateContent?key=<your-access-token>"
```

**Expected Output:** A JSON response containing the AI model's generated content.

### 8. Embed Content (`/v1beta/models/{model}:embedContent`) - POST

Tests single embedding generation.

```bash
curl -X POST \
  -H "x-goog-api-key: <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{ "model": "models/text-embedding-004", "content": { "parts": [ { "text": "A single sentence for embedding." } ] } }' \
  "https://<your-worker-url>/v1beta/models/text-embedding-004:embedContent"
```

**Expected Output:** A JSON response containing a single embedding vector.

### 9. Batch Embed Contents (`/v1beta/models/{model}:batchEmbedContents`) - POST

Tests batch embedding generation.

```bash
curl -X POST \
  -H "x-goog-api-key: <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "model": "models/text-embedding-004",
        "content": {"parts": [{"text": "First sentence for embedding."}]}
      },
      {
        "model": "models/text-embedding-004",
        "content": {"parts": [{"text": "Second sentence for embedding."}]}
      }
    ]
  }' \
  "https://<your-worker-url>/v1beta/models/text-embedding-004:batchEmbedContents"
```

**Expected Output:** A JSON response containing a list of embedding vectors.

### 10. List Models (`/v1beta/models`) - GET

Tests retrieving a list of available models in Gemini native format.

```bash
curl -X GET \
  -H "x-goog-api-key: <your-access-token>" \
  "https://<your-worker-url>/v1beta/models"
```

**Expected Output:** A JSON response listing available models in Gemini native format.

### 11. Retrieve Specific Model (`/v1beta/models/{model_id}`) - GET

Tests retrieving details for a specific model in Gemini native format.

```bash
curl -X GET \
  -H "x-goog-api-key: <your-access-token>" \
  "https://<your-worker-url>/v1beta/models/gemini-2.5-flash"
```

**Expected Output:** A JSON response with details for `gemini-2.5-flash` in Gemini native format.

### 12. Generate Content Stream (`/v1beta/models/{model}:streamGenerateContent`) - POST

Tests streaming content generation.

```bash
curl -X POST \
  -H "x-goog-api-key: <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{ "contents": [ { "parts": [ { "text": "Tell me a very short story about a dog." } ] } ], "stream": true }' \
  "https://<your-worker-url>/v1beta/models/gemini-2.5-flash:streamGenerateContent"
```

**Expected Output:** A stream of JSON objects, each containing a chunk of the AI model's generated content.
