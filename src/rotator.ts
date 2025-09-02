import type { ChatCompletion, ChatCompletionCreateParams } from 'openai/resources/chat/completions';
import type {
	ClaudeCompletionRequest,
	ClaudeCompletionResponseChunk,
	ClaudeMessage,
	ClaudeMessagePart,
	ClaudeTool,
	GeminiResponse,
	GeminiCandidate,
} from './types.d';

// --- Types ---
interface Env {
	DB: D1Database;
	GEMINI_API_BASE_URL?: string;
	CLOUDFLARE_AI_GATEWAY_ID: string;
	CLOUDFLARE_AI_GATEWAY_NAME: string;
	// No CLAUDE_API_BASE_URL needed as we are transforming to Gemini
}

interface KeyState {
	exhaustedUntil?: { [model: string]: number };
	invalid?: boolean;
}

interface ApiCredentials {
	api_keys: string;
	current_key_index: number;
	key_states: string | null; // JSON string of KeyState[]
}

interface GeminiModel {
	name: string;
	description: string;
	[key: string]: any;
}

interface GeminiModelsList {
	models: GeminiModel[];
}
  
// --- Configuration ---
const CLOUDFLARE_AI_GATEWAY_BASE = (env: Env) => `https://gateway.ai.cloudflare.com/v1/${env.CLOUDFLARE_AI_GATEWAY_ID}/${env.CLOUDFLARE_AI_GATEWAY_NAME}`;
const API_VERSION = 'v1beta';
  const API_CLIENT = 'genai-js/0.21.0';
  
  class HttpError extends Error {
	status: number;
	constructor(message: string, status: number) {
	  super(message);
	  this.name = this.constructor.name;
	  this.status = status;
	}
  }

  // Function to map Claude models to Gemini models
  function getGeminiModelForClaude(claudeModel: string): string {
	// If the model is already a Gemini model, use it directly
	if (claudeModel.startsWith('gemini-')) {
		return claudeModel;
	}
	if (claudeModel.includes('opus')) {
		return 'gemini-2.5-flash';
	}
	if (claudeModel.includes('sonnet')) {
		return 'gemini-2.5-flash';
	}
	if (claudeModel.includes('haiku')) {
		return 'gemini-2.5-flash';
	}
	// Default to a general-purpose Gemini model if no specific mapping is found
	return 'gemini-2.5-flash';
  }
  
  const makeHeaders = (apiKey: string, more?: Record<string, string>) => ({
	'x-goog-api-client': API_CLIENT,
	...(apiKey && { 'x-goog-api-key': apiKey }),
	...more,
  });
  
  export class KeyRotator {
	state: DurableObjectState;
	env: Env;
  
	constructor(state: DurableObjectState, env: Env) {
	  this.state = state;
	  this.env = env;
	}
  
	async fetch(request: Request): Promise<Response> {
	  const clonedRequest = request.clone();
	  const requestUrl = new URL(request.url);
	  const accessToken = request.headers.get("X-Access-Token");
	  const authMode = request.headers.get("X-Auth-Mode");
	  let model: string | undefined;
  
	  if (!accessToken) {
		return new Response("Unauthorized: Access token is required.", { status: 401 });
	  }

	  if (authMode === "openai" && request.method === 'POST' && requestUrl.pathname.endsWith('/chat/completions')) {
		try {
			const body: ChatCompletionCreateParams = await request.clone().json();
			if (typeof body.model === 'string') {
				model = body.model.startsWith('models/') ? body.model.substring(7) : body.model;
			}
		} catch (e) {
			console.error("Could not parse request body to get model:", e);
		}
	} else if (authMode !== "openai") {
		// For google native and other modes, model is in the URL
		const modelMatch = requestUrl.pathname.match(/models\/([^/:]+)/);
		if (modelMatch) {
			model = modelMatch[1];
		}
	}
  
	  // 2. Fetch API Keys, index, and states from D1
	  const stmt = this.env.DB.prepare("SELECT api_keys, current_key_index, key_states FROM api_credentials WHERE access_token = ?");
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
	  const getNextKeyIndex = (model?: string): number | null => {
		const now = Date.now();
		for (let i = 0; i < apiKeys.length; i++) {
		  const idx = (startingKeyIndex + i) % apiKeys.length;
		  const state = keyStates[idx];
  
		  if (state?.invalid) {
			continue;
		  }
  
		  if (state?.exhaustedUntil) {
			// Clean up expired model-specific exhaustions
			Object.keys(state.exhaustedUntil).forEach(m => {
				if (state.exhaustedUntil![m] < now) {
					delete state.exhaustedUntil![m];
				}
			});
			if (Object.keys(state.exhaustedUntil).length === 0) {
				delete state.exhaustedUntil;
			}
		  }
  
		  // If a model is provided, check if it's exhausted for that model
		  if (model && state?.exhaustedUntil?.[model]) {
			continue;
		  }
  
		  // If no model is provided, and the key has any exhaustion, we can't use it.
		  if (!model && state?.exhaustedUntil) {
			continue;
		  }
  
		  return idx;
		}
		return null;
	  };
  
	  const modelForExhaustion = model || "_general_";
	  keyIndexToUse = getNextKeyIndex(modelForExhaustion);
  
	  if (keyIndexToUse === null) {
		return new Response("All API keys for your account are currently exhausted. Please try again later.", { status: 429 });
	  }
	  let apiKey = apiKeys[keyIndexToUse];
  
	  const doProxy = (apiKey: string, requestToProxy: Request) => {
		const pathname = requestUrl.pathname;
		if (authMode === "openai") {
		  return this.handleOpenAI(requestToProxy, apiKey);
		} else if (authMode === "claude") {
			return this.handleClaude(requestToProxy, apiKey);
		}
  
		let apiBaseUrl: string;
		let targetUrl: URL;

		if (this.env.GEMINI_API_BASE_URL) {
			apiBaseUrl = this.env.GEMINI_API_BASE_URL;
			targetUrl = new URL(requestUrl.pathname + requestUrl.search, apiBaseUrl);
		} else {
			// Use Cloudflare AI Gateway for Google AI Studio
			apiBaseUrl = `${CLOUDFLARE_AI_GATEWAY_BASE}/google-ai-studio`;
			// The path for AI Gateway is /v1/models/{model}:{generative_ai_rest_resource}
			// The AI Gateway expects paths like /v1beta/models or /v1beta/models/model_id:task
			// The original requestUrl.pathname already contains this structure.
			// So, we just need to append it directly to the AI Gateway base.
			targetUrl = new URL(`${apiBaseUrl}${requestUrl.pathname}${requestUrl.search}`);
		}

		const forwardHeaders = new Headers(requestToProxy.headers);
		["host", "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "x-forwarded-proto", "x-real-ip", "x-access-token", "x-auth-mode"].forEach(h => forwardHeaders.delete(h));
  
		if (authMode === "google") {
		  forwardHeaders.set("x-goog-api-key", apiKey);
		}
		if (targetUrl.searchParams.has("key")) {
			targetUrl.searchParams.delete("key");
		 }
		//targetUrl.searchParams.set("key", apiKey);
  
		const methodCanHaveBody = ['POST', 'PUT', 'PATCH'].includes(requestToProxy.method.toUpperCase());
		const isStreaming = requestUrl.pathname.includes(":stream") || requestUrl.pathname.includes("streamGenerateContent");
  
		return this.proxyRequest(
		  new Request(targetUrl.toString(), {
			method: requestToProxy.method,
			headers: forwardHeaders,
			body: methodCanHaveBody && requestToProxy.body ? requestToProxy.body : null,
			redirect: 'follow',
			cf: requestToProxy.cf as CfProperties<unknown> // Preserve the cf property and cast to CfProperties<unknown>
		  }),
		  isStreaming
		);
	  };
  
	  let response = await doProxy(apiKey, clonedRequest.clone() as Request<unknown, CfProperties<unknown>>);
  
	  let attemptCount = 1;
	  let maxAttempts = apiKeys.length > 3 ? 3 : apiKeys.length; // Cap at 3 keys or total keys if fewer than 3
	  while ([400, 401, 403, 429, 500, 502, 503, 524].includes(response.status) && attemptCount < maxAttempts) {
		if (response.status === 401) {
		  keyStates[keyIndexToUse] = { ...keyStates[keyIndexToUse], invalid: true };
		} else {
		  //const cooldown = response.status === 429 ? (2 * 60 * 1000) : (1 * 60 * 1000);
		  //keyStates[keyIndexToUse] = { exhaustedUntil: Date.now() + cooldown };
		  if ([429].includes(response.status)) {
			const cooldown = 2 * 60 * 1000;
			const currentState = keyStates[keyIndexToUse] || {};
			const currentExhausted = currentState.exhaustedUntil || {};
			keyStates[keyIndexToUse] = {
				...currentState,
				exhaustedUntil: {
					...currentExhausted,
					[modelForExhaustion]: Date.now() + cooldown,
				},
			};
		  }
		}
  
		const nextKeyIndex = getNextKeyIndex(modelForExhaustion);
		if (nextKeyIndex === null) {
		  keyIndexToUse = null;
		  break;
		}
		keyIndexToUse = nextKeyIndex;
		apiKey = apiKeys[keyIndexToUse];
		attemptCount++;
		response = await doProxy(apiKey, clonedRequest.clone() as Request<unknown, CfProperties<unknown>>);
	  }
  
	  if (keyIndexToUse !== null) {
		const nextIndexForDb = (keyIndexToUse + 1) % apiKeys.length;
		const keyStatesJson = JSON.stringify(keyStates);
		const updateStmt = this.env.DB.prepare("UPDATE api_credentials SET current_key_index = ?, key_states = ? WHERE access_token = ?");
		await updateStmt.bind(nextIndexForDb, keyStatesJson, accessToken).run();
	  } else {
		const keyStatesJson = JSON.stringify(keyStates);
		const updateStmt = this.env.DB.prepare("UPDATE api_credentials SET key_states = ? WHERE access_token = ?");
		await updateStmt.bind(keyStatesJson, accessToken).run();
	  }
  
	  return response;
	}
  
	private async proxyRequest(request: Request, isStreaming: boolean): Promise<Response> {
	  const doFetch = () => fetch(request.url, request);
  
	  const doFetchWithContentRetry = async (): Promise<Response> => {
		const maxContentRetries = 3;
		for (let i = 0; i < maxContentRetries; i++) {
		  const response = await doFetch();
		  if (!response.ok) return response;
  
		  if (isStreaming) {
			if (!response.body) {
			  if (i < maxContentRetries - 1) await new Promise(res => setTimeout(res, 1000));
			  continue;
			}
			const [stream1, stream2] = response.body.tee();
			const reader = stream1.getReader();
			try {
			  const { done } = await reader.read();
			  if (done) {
				if (i < maxContentRetries - 1) await new Promise(res => setTimeout(res, 1000));
				continue;
			  }
			  return new Response(stream2, { status: response.status, statusText: response.statusText, headers: response.headers });
			} catch (e) {
			  if (i < maxContentRetries - 1) await new Promise(res => setTimeout(res, 1000));
			  continue;
			} finally {
			  reader.releaseLock();
			  stream1.cancel().catch(() => {});
			}
		  } else {
			const clonedResponse = response.clone();
			try {
			  await clonedResponse.json();
			  return response;
			} catch (e) { /* ignore and retry */ }
		  }
		  if (i < maxContentRetries - 1) await new Promise(res => setTimeout(res, 1000 * (i + 1)));
		}
		
		const errorResponse = { error: { code: 503, message: "Upstream API failed to provide a valid response.", status: "SERVICE_UNAVAILABLE" } };
		return new Response(JSON.stringify(errorResponse), { status: 503, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
	  };
  
	  let response = await doFetchWithContentRetry();
  
	  const maxRetries = 3;
	  for (let i = 0; i < maxRetries && [500, 502, 503, 524].includes(response.status); i++) {
		await new Promise(res => setTimeout(res, 1000 * (i + 1)));
		response = await doFetchWithContentRetry();
	  }
  
	  return response;
	}
  
	// --- OpenAI Compatibility Layer ---
  
	private async handleOpenAI(request: Request, apiKey: string): Promise<Response> {
	  const requestUrl = new URL(request.url);
	  const pathname = requestUrl.pathname;
  
	  const errHandler = (err: Error) => {
		console.error(err);
		const status = err instanceof HttpError ? err.status : 500;
		return new Response(err.message ?? 'Internal Server Error', { status });
	  };
  
	  try {
		if (pathname.endsWith('/chat/completions')) {
		  if (request.method !== 'POST') throw new HttpError('Method not allowed', 405);
		  return this.handleCompletions(await request.json(), apiKey).catch(errHandler);
		}
		if (pathname.endsWith('/embeddings')) {
			if (request.method !== 'POST') throw new HttpError('Method not allowed', 405);
			return this.handleEmbeddings(await request.json(), apiKey).catch(errHandler);
		}
		const modelsMatch = pathname.match(/models\/([^/]+)$/);
		const isModelsList = pathname.endsWith('/models');

		if (modelsMatch || isModelsList) {
			if (request.method !== 'GET') throw new HttpError('Method not allowed', 405);
			const modelId = modelsMatch ? modelsMatch[1] : undefined;
			const authMode = request.headers.get("X-Auth-Mode") || "openai";
			return this.handleModels(apiKey, modelId, authMode).catch(errHandler);
		}
		throw new HttpError('Not Found', 404);
	  } catch (e) {
		return errHandler(e as Error);
	  }
	}

	async handleModels(apiKey: string, modelId?: string, authMode: string = "openai") {
		const apiBaseUrl = this.env.GEMINI_API_BASE_URL || `${CLOUDFLARE_AI_GATEWAY_BASE}/google-ai-studio`;
		const apiVersionToUse = this.env.GEMINI_API_BASE_URL ? API_VERSION : 'v1'; // Use 'v1' for AI Gateway
		const url = modelId
			? `${apiBaseUrl}/${apiVersionToUse}/models/${modelId}`
			: `${apiBaseUrl}/${apiVersionToUse}/models`;

		const response = await fetch(url, {
			headers: makeHeaders(apiKey),
		});

		if (authMode === "google") {
			return response;
		}

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			const originalBody = await response.json() as GeminiModel | GeminiModelsList;
			if (modelId) {
				const model = originalBody as GeminiModel;
				switch (authMode) {
					case "openai":
						responseBody = JSON.stringify({
							id: model.name.replace('models/', ''),
							object: 'model',
							created: 0,
							owned_by: 'google',
						});
						break;
					case "claude":
						responseBody = JSON.stringify({
							id: model.name.replace('models/', ''),
							type: 'model',
							description: model.description,
							name: model.name,
							display_name: model.name,
						});
						break;
					default:
						responseBody = JSON.stringify(model);
				}
			} else {
				const { models } = originalBody as GeminiModelsList;
				switch (authMode) {
					case "openai":
						responseBody = JSON.stringify(
							{
								object: 'list',
								data: models.map((model: any) => ({
									id: model.name.replace('models/', ''),
									object: 'model',
									created: 0,
									owned_by: 'google',
								})),
							},
							null,
							'  '
						);
						break;
					case "claude":
						responseBody = JSON.stringify({
							data: models.map((model: any) => ({
								id: model.name.replace('models/', ''),
								type: 'model',
								description: model.description,
								name: model.name,
								display_name: model.name,
							})),
						});
						break;
					default:
						responseBody = JSON.stringify({ models });
				}
			}
		}
		return new Response(responseBody, response);
	}

	async handleEmbeddings(req: any, apiKey: string) {
		const DEFAULT_EMBEDDINGS_MODEL = 'text-embedding-004';

		if (typeof req.model !== 'string') {
			throw new HttpError('model is not specified', 400);
		}

		let modelName = req.model;
		if (modelName.startsWith('models/')) {
			modelName = modelName.substring(7);
		}

		// Use default unless it's a known embedding model pattern
		if (!modelName.startsWith('text-embedding-') && !modelName.startsWith('embedding-') && !modelName.startsWith('gemini-')) {
			modelName = DEFAULT_EMBEDDINGS_MODEL;
		}

		const model = `models/${modelName}`;


		if (!Array.isArray(req.input)) {
			req.input = [req.input];
		}

		const apiBaseUrl = this.env.GEMINI_API_BASE_URL || `${CLOUDFLARE_AI_GATEWAY_BASE}/google-ai-studio`;
		const apiVersionToUse = this.env.GEMINI_API_BASE_URL ? API_VERSION : 'v1'; // Use 'v1' for AI Gateway
		
		const response = await fetch(`${apiBaseUrl}/${apiVersionToUse}/${model}:batchEmbedContents`, {
			method: 'POST',
			headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
			body: JSON.stringify({
				requests: req.input.map((text: string) => ({
					model,
					content: { parts: [{ text }] },
					outputDimensionality: req.dimensions,
				})),
			}),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			const { embeddings } = JSON.parse(await response.text());
			responseBody = JSON.stringify(
				{
					object: 'list',
					data: embeddings.map(({ values }: any, index: number) => ({
						object: 'embedding',
						index,
						embedding: values,
					})),
					model: modelName,
				},
				null,
				'  '
			);
		}
		return new Response(responseBody, response);
	}
  
	private async handleCompletions(req: ChatCompletionCreateParams, apiKey: string): Promise<Response> {
		const DEFAULT_MODEL = 'gemini-2.5-flash';
		let model = DEFAULT_MODEL;

		if ((req as any).input && !req.messages) {
			req.messages = [{ role: 'user', content: (req as any).input }];
		}

		switch (true) {
			case typeof req.model !== 'string':
				break;
			case req.model.startsWith('models/'):
				model = req.model.substring(7);
				break;
			case req.model.startsWith('gemini-'):
			case req.model.startsWith('gemma-'):
			case req.model.startsWith('learnlm-'):
				model = req.model;
		}

		let body = await this.transformRequest(req);
		const extra = (req as any).extra_body?.google;

		if (extra) {
			if (extra.safety_settings) {
				body.safetySettings = extra.safety_settings;
			}
			if (extra.cached_content) {
				body.cachedContent = extra.cached_content;
			}
			if (extra.thinking_config) {
				body.generationConfig.thinkingConfig = extra.thinking_config;
			}
		}

		switch (true) {
			case model.endsWith(':search'):
				model = model.substring(0, model.length - 7);
			case req.model.endsWith('-search-preview'):
			case req.tools?.some((tool: any) => tool.function?.name === 'googleSearch'):
				body.tools = body.tools || [];
				body.tools.push({ function_declarations: [{ name: 'googleSearch', parameters: {} }] });
		}

		const TASK = req.stream ? 'streamGenerateContent' : 'generateContent';
		const apiBaseUrl = this.env.GEMINI_API_BASE_URL || `${CLOUDFLARE_AI_GATEWAY_BASE}/google-ai-studio`;
		const apiVersionToUse = this.env.GEMINI_API_BASE_URL ? API_VERSION : 'v1'; // Use 'v1' for AI Gateway
		let url = `${apiBaseUrl}/${apiVersionToUse}/models/${model}:${TASK}`;
		if (req.stream) {
			url += '?alt=sse';
		}

		const response = await fetch(url, {
			method: 'POST',
			headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
			body: JSON.stringify(body),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			let id = 'chatcmpl-' + this.generateId();
			const shared = {};

			if (req.stream) {
				responseBody = response
					.body!.pipeThrough(new TextDecoderStream())
					.pipeThrough(
						new TransformStream({
							transform: this.parseStream,
							flush: this.parseStreamFlush,
							buffer: '',
							shared,
						} as any)
					)
					.pipeThrough(
						new TransformStream({
							transform: this.toOpenAiStream,
							flush: this.toOpenAiStreamFlush,
							streamIncludeUsage: req.stream_options?.include_usage,
							model,
							id,
							last: [],
							shared,
						} as any)
					)
					.pipeThrough(new TextEncoderStream());
			} else {
				let body: any = await response.text();
				try {
					body = JSON.parse(body);
					if (!body.candidates) {
						throw new Error('Invalid completion object');
					}
				} catch (err) {
					console.error('Error parsing response:', err);
					return new Response(JSON.stringify({ error: 'Failed to parse response' }), {
						...response,
						status: 500,
					});
				}
				responseBody = this.processCompletionsResponse(body, model, id);
			}
		}
		return new Response(responseBody, response);
	}

	// 辅助方法
	private generateId(): string {
		const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const randomChar = () => characters[Math.floor(Math.random() * characters.length)];
		return Array.from({ length: 29 }, randomChar).join('');
	}

	private async transformRequest(req: any) {
		const harmCategory = [
			'HARM_CATEGORY_HATE_SPEECH',
			'HARM_CATEGORY_SEXUALLY_EXPLICIT',
			'HARM_CATEGORY_DANGEROUS_CONTENT',
			'HARM_CATEGORY_HARASSMENT',
			'HARM_CATEGORY_CIVIC_INTEGRITY',
		];

		const safetySettings = harmCategory.map((category) => ({
			category,
			threshold: 'BLOCK_NONE',
		}));

		return {
			...(await this.transformMessages(req.messages)),
			safetySettings,
			generationConfig: this.transformConfig(req),
			...this.transformTools(req),
			cachedContent: undefined as any,
		};
	}

	private transformConfig(req: any) {
		const fieldsMap: Record<string, string> = {
			frequency_penalty: 'frequencyPenalty',
			max_completion_tokens: 'maxOutputTokens',
			max_tokens: 'maxOutputTokens',
			n: 'candidateCount',
			presence_penalty: 'presencePenalty',
			seed: 'seed',
			stop: 'stopSequences',
			temperature: 'temperature',
			top_k: 'topK',
			top_p: 'topP',
		};

		const thinkingBudgetMap: Record<string, number> = {
			low: 1024,
			medium: 8192,
			high: 24576,
		};

		let cfg: any = {};
		for (let key in req) {
			const matchedKey = fieldsMap[key];
			if (matchedKey) {
				cfg[matchedKey] = req[key];
			}
		}

		if (req.response_format) {
			switch (req.response_format.type) {
				case 'json_schema':
					cfg.responseSchema = req.response_format.json_schema?.schema;
					if (cfg.responseSchema && 'enum' in cfg.responseSchema) {
						cfg.responseMimeType = 'text/x.enum';
						break;
					}
				case 'json_object':
					cfg.responseMimeType = 'application/json';
					break;
				case 'text':
					cfg.responseMimeType = 'text/plain';
					break;
				default:
					throw new HttpError('Unsupported response_format.type', 400);
			}
		}
		if (req.reasoning_effort) {
			cfg.thinkingConfig = { thinkingBudget: thinkingBudgetMap[req.reasoning_effort] };
		}

		return cfg;
	}

	private async transformMessages(messages: ChatCompletionCreateParams['messages']) {
		if (!messages) {
			return {};
		}

		const contents: any[] = [];
		let system_instruction;

		for (const item of messages) {
			switch (item.role) {
				case 'system':
					system_instruction = { parts: await this.transformMsg(item) };
					continue;
				case 'assistant':
					(item as any).role = 'model';
					break;
				case 'user':
				case 'developer': // Treat 'developer' role as 'user' for content transformation
					break;
				default:
					throw new HttpError(`Unknown message role: "${item.role}"`, 400);
			}

			contents.push({
				role: item.role,
				parts: await this.transformMsg(item),
			});
		}

		return { system_instruction, contents };
	}

	private async transformMsg({ content }: any) {
		const parts = [];
		if (!Array.isArray(content)) {
			parts.push({ text: content });
			return parts;
		}

		for (const item of content) {
			switch (item.type) {
				case 'text':
					parts.push({ text: item.text });
					break;
				case 'image_url':
					// 简化的图片处理
					//parts.push({ text: '[图片内容]' });
					const imageUrl = item.image_url.url;
					if (imageUrl.startsWith('data:')) {
						// Handle data URI
						const [header, base64Data] = imageUrl.split(',');
						const mimeType = header.match(/:(.*?);/)?.[1];
						if (mimeType && base64Data) {
							parts.push({ inlineData: { mimeType, data: base64Data } });
						}
					} else {
						// Handle remote URL (requires an external fetch)
						// Note: This adds latency and requires egress bandwidth.
						const imageResponse = await fetch(imageUrl);
						const mimeType = imageResponse.headers.get('content-type');
						const buffer = await imageResponse.arrayBuffer();
						const base64Data = btoa(String.fromCharCode(...new Uint8Array(buffer)));
						if (mimeType) {
							parts.push({ inlineData: { mimeType, data: base64Data } });
						}
					}
					break;
					//break;
				default:
					throw new HttpError(`Unknown "content" item type: "${item.type}"`, 400);
			}
		}

		return parts;
	}

	private transformTools(req: any) {
		let tools, tool_config;
		if (req.tools) {
			const funcs = req.tools.filter((tool: any) => tool.type === 'function' && tool.function?.name !== 'googleSearch');
			if (funcs.length > 0) {
				tools = [{ function_declarations: funcs.map((schema: any) => schema.function) }];
			}
		}
		if (req.tool_choice) {
			if (req.tool_choice === 'none') {
				tool_config = { function_calling_config: { mode: 'NONE' } };
			} else if (typeof req.tool_choice === 'object' && req.tool_choice.type === 'function') {
				tool_config = {
					function_calling_config: {
						mode: 'ANY',
						allowed_function_names: [req.tool_choice.function.name],
					},
				};
			}
		}
		return { tools, tool_config };
	}

	private processCompletionsResponse(data: any, model: string, id: string) {
		const reasonsMap: Record<string, string> = {
			STOP: 'stop',
			MAX_TOKENS: 'length',
			SAFETY: 'content_filter',
			RECITATION: 'content_filter',
		};

		const transformCandidatesMessage = (cand: any) => {
			const message = { role: 'assistant', content: [] as string[] };
			for (const part of cand.content?.parts ?? []) {
				if (part.text) {
					message.content.push(part.text);
				}
			}

			return {
				index: cand.index || 0,
				message: {
					...message,
					content: message.content.join('') || null,
				},
				logprobs: null,
				finish_reason: reasonsMap[cand.finishReason] || cand.finishReason,
			};
		};

		const obj = {
			id,
			choices: data.candidates.map(transformCandidatesMessage),
			created: Math.floor(Date.now() / 1000),
			model: data.modelVersion ?? model,
			object: 'chat.completion',
			usage: data.usageMetadata && {
				completion_tokens: data.usageMetadata.candidatesTokenCount,
				prompt_tokens: data.usageMetadata.promptTokenCount,
				total_tokens: data.usageMetadata.totalTokenCount,
			},
		};

		return JSON.stringify(obj);
	}

	// 流处理方法
	private parseStream(this: any, chunk: string, controller: any) {
		this.buffer += chunk;
		const lines = this.buffer.split('\n');
		this.buffer = lines.pop()!;

		for (const line of lines) {
			if (line.startsWith('data: ')) {
				const data = line.substring(6);
				if (data.startsWith('{')) {
					controller.enqueue(JSON.parse(data));
				}
			}
		}
	}

	private parseStreamFlush(this: any, controller: any) {
		if (this.buffer) {
			try {
				controller.enqueue(JSON.parse(this.buffer));
			} catch (e) {
				console.error('Error parsing remaining buffer:', e);
			}
		}
	}

	private toOpenAiStream(this: any, line: any, controller: any) {
		const reasonsMap: Record<string, string> = {
			STOP: 'stop',
			MAX_TOKENS: 'length',
			SAFETY: 'content_filter',
			RECITATION: 'content_filter',
		};

		const { candidates, usageMetadata } = line;
		if (usageMetadata) {
			this.shared.usage = {
				completion_tokens: usageMetadata.candidatesTokenCount,
				prompt_tokens: usageMetadata.promptTokenCount,
				total_tokens: usageMetadata.totalTokenCount,
			};
		}

		if (candidates) {
			for (const cand of candidates) {
				const { index, content, finishReason } = cand;
				const { parts } = content;
				const text = parts.map((p: any) => p.text).join('');

				if (this.last[index] === undefined) {
					this.last[index] = '';
				}

				const lastText = this.last[index] || '';
				let delta = '';

				if (text.startsWith(lastText)) {
					delta = text.substring(lastText.length);
				} else {
					// Find the common prefix
					let i = 0;
					while (i < text.length && i < lastText.length && text[i] === lastText[i]) {
						i++;
					}
					// Send the rest of the new text as delta.
					// This might not be perfect for all clients, but it prevents data loss.
					//delta = text.substring(i);
					delta = text;
				}

				this.last[index] = text;

				const obj = {
					id: this.id,
					object: 'chat.completion.chunk',
					created: Math.floor(Date.now() / 1000),
					model: this.model,
					choices: [
						{
							index,
							delta: { content: delta },
							finish_reason: reasonsMap[finishReason] || finishReason,
						},
					],
				};
				controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
			}
		}
	}

	private toOpenAiStreamFlush(this: any, controller: any) {
		if (this.streamIncludeUsage && this.shared.usage) {
			const obj = {
				id: this.id,
				object: 'chat.completion.chunk',
				created: Math.floor(Date.now() / 1000),
				model: this.model,
				choices: [
					{
						index: 0,
						delta: {},
						finish_reason: 'stop',
					},
				],
				usage: this.shared.usage,
			};
			controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
		}
		controller.enqueue('data: [DONE]\n\n');
	}

	// --- Claude Compatibility Layer ---

	private async transformClaudeMessagesToGeminiContents(
		messages: ClaudeMessage[]
	): Promise<{ contents: any[]; system_instruction?: any }> {
		const contents: any[] = [];
		let system_instruction: any;

		for (const item of messages) {
			if (item.role === 'user' || item.role === 'assistant') {
				const parts: any[] = [];
				if (typeof item.content === 'string') {
					parts.push({ text: item.content });
				} else {
					for (const part of item.content) {
						switch (part.type) {
							case 'text':
								parts.push({ text: part.text });
								break;
							case 'image':
								if (part.source?.type === 'base64') {
									parts.push({
										inlineData: {
											mimeType: part.source.media_type,
											data: part.source.data,
										},
									});
								}
								break;
							case 'tool_use':
								parts.push({
									functionCall: {
										name: part.input?.name, // Claude's tool_use.input is the function call
										args: part.input,
									},
								});
								break;
							case 'tool_result':
								parts.push({
									functionResponse: {
										name: part.tool_use_id, // Claude's tool_result.tool_use_id maps to Gemini's function name
										response: part.content,
									},
								});
								break;
							default:
								console.warn('Unknown Claude message part type:', part.type);
								break;
						}
					}
				}
				contents.push({
					role: item.role === 'assistant' ? 'model' : 'user',
					parts: parts,
				});
			} else if (item.role === 'system') {
				system_instruction = { parts: [{ text: item.content as string }] };
			}
		}
		return { contents, system_instruction };
	}

	private transformClaudeToolsToGeminiTools(
		claudeTools?: ClaudeTool[],
		claudeToolChoice?: ClaudeCompletionRequest['tool_choice']
	): { tools?: any[]; tool_config?: any } {
		const geminiTools: any[] = [];
		if (claudeTools && claudeTools.length > 0) {
			geminiTools.push({
				function_declarations: claudeTools.map((tool) => ({
					name: tool.name,
					description: tool.description,
					parameters: tool.input_schema,
				})),
			});
		}

		let tool_config: any;
		if (claudeToolChoice) {
			if (claudeToolChoice.type === 'auto') {
				tool_config = { function_calling_config: { mode: 'AUTO' } };
			} else if (claudeToolChoice.type === 'tool' && claudeToolChoice.tool?.name) {
				tool_config = {
					function_calling_config: {
						mode: 'ANY',
						allowed_function_names: [claudeToolChoice.tool.name],
					},
				};
			} else if (claudeToolChoice.type === 'none') {
				tool_config = { function_calling_config: { mode: 'NONE' } };
			}
		}

		return { tools: geminiTools.length > 0 ? geminiTools : undefined, tool_config };
	}

	private async transformClaudeToGeminiRequest(
		claudeReq: ClaudeCompletionRequest & { thinking?: any }
	): Promise<any> {
		const { contents, system_instruction } = await this.transformClaudeMessagesToGeminiContents(
			claudeReq.messages
		);
		const { tools, tool_config } = this.transformClaudeToolsToGeminiTools(
			claudeReq.tools,
			claudeReq.tool_choice
		);

		const generationConfig: any = {};
		if (claudeReq.max_tokens) {
			generationConfig.maxOutputTokens = claudeReq.max_tokens;
		}
		if (claudeReq.temperature) {
			generationConfig.temperature = claudeReq.temperature;
		}
		if (claudeReq.top_p) {
			generationConfig.topP = claudeReq.top_p;
		}
		if (claudeReq.top_k) {
			generationConfig.topK = claudeReq.top_k;
		}
		if (claudeReq.stop_sequences && claudeReq.stop_sequences.length > 0) {
			generationConfig.stopSequences = claudeReq.stop_sequences;
		}

		// Handle Claude's thinking parameter
		if (claudeReq.thinking && claudeReq.thinking.type === 'enabled') {
			if (claudeReq.thinking.budget_tokens) {
				generationConfig.thinkingConfig = {
					thinkingBudget: claudeReq.thinking.budget_tokens
				};
			} else {
				generationConfig.thinkingConfig = {
					thinkingBudget: 1024 // Default budget
				};
			}
		}

		const harmCategory = [
			'HARM_CATEGORY_HATE_SPEECH',
			'HARM_CATEGORY_SEXUALLY_EXPLICIT',
			'HARM_CATEGORY_DANGEROUS_CONTENT',
			'HARM_CATEGORY_HARASSMENT',
			'HARM_CATEGORY_CIVIC_INTEGRITY',
		];

		const safetySettings = harmCategory.map((category) => ({
			category,
			threshold: 'BLOCK_NONE',
		}));

		return {
			contents,
			system_instruction,
			generationConfig: Object.keys(generationConfig).length > 0 ? generationConfig : undefined,
			safetySettings,
			tools,
			tool_config,
		};
	}

	private transformGeminiToClaudeResponse(
		geminiRes: GeminiResponse,
		model: string,
		id: string,
		thinking?: string
	): Response {
		const claudeContent: ClaudeMessagePart[] = [];
		let stopReason: string | null = null;
		let stopSequence: string | null = null;
		let accumulatedThinking = thinking || '';

		if (geminiRes.candidates && geminiRes.candidates.length > 0) {
			const candidate = geminiRes.candidates[0]; // Claude expects a single response
			if (candidate.content?.parts) {
				for (const part of candidate.content.parts) {
					if (part.text) {
						claudeContent.push({ type: 'text', text: part.text });
					} else if (part.functionCall) {
						claudeContent.push({
							type: 'tool_use',
							id: `toolu_${this.generateId()}`,
							name: part.functionCall.name,
							input: part.functionCall.args,
						});
					} else if ((part as any).toolCode && typeof (part as any).toolCode === 'string') {
						// Accumulate toolCode as thinking content
						accumulatedThinking += (part as any).toolCode;
					} else if ((part as any).reasoning && typeof (part as any).reasoning === 'string') {
						// Check for reasoning field which might contain thinking content
						accumulatedThinking += (part as any).reasoning;
					} else if ((part as any).thought && typeof (part as any).thought === 'string') {
						// Check for thought field
						accumulatedThinking += (part as any).thought;
					} else if ((part as any).thinking && typeof (part as any).thinking === 'string') {
						// Check for thinking field
						accumulatedThinking += (part as any).thinking;
					}
				}
			}

			// Map Gemini finishReason to Claude stop_reason
			switch (candidate.finishReason) {
				case 'STOP':
					stopReason = 'end_turn';
					break;
				case 'MAX_TOKENS':
					stopReason = 'max_tokens';
					break;
				case 'SAFETY':
				case 'RECITATION':
					stopReason = 'stop_sequence';
					if (claudeContent.length === 0) {
						claudeContent.push({
							type: 'text',
							text: `[Content blocked due to safety concerns: ${candidate.finishReason}]`,
						});
					}
					break;
				case 'OTHER':
				default:
					stopReason = 'end_turn';
					break;
			}
		}

		// Add thinking content if present
		if (accumulatedThinking) {
			claudeContent.unshift({ type: 'thinking', thinking: accumulatedThinking });
		}

		const usage = {
			input_tokens: geminiRes.usageMetadata?.promptTokenCount || 0,
			output_tokens: geminiRes.usageMetadata?.candidatesTokenCount || 0,
		};

		const claudeResponse = {
			id: id,
			type: 'message',
			role: 'assistant',
			model: model,
			content: claudeContent,
			stop_reason: stopReason,
			stop_sequence: stopSequence,
			usage: usage,
		};

		return new Response(JSON.stringify(claudeResponse), {
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	private transformGeminiToClaudeStreamStart(this: any, controller: any) {
		controller.enqueue(
			`event: message_start\ndata: ${JSON.stringify({
				type: 'message_start',
				message: {
					id: this.id,
					type: 'message',
					role: 'assistant',
					model: this.model,
					content: [],
					stop_reason: null,
					stop_sequence: null,
					usage: { input_tokens: 0, output_tokens: 0 },
				},
			})}\n\n`
		);
		controller.enqueue(`event: ping\ndata: ${JSON.stringify({ type: 'ping' })}\n\n`);
	}

	private transformGeminiToClaudeStream(this: any, geminiChunk: any, controller: any) {
		const reasonsMap: Record<string, string> = {
			STOP: 'end_turn',
			MAX_TOKENS: 'max_tokens',
			SAFETY: 'stop_sequence',
			RECITATION: 'stop_sequence',
			OTHER: 'end_turn',
		};

		const { candidates, usageMetadata } = geminiChunk;

		if (candidates && candidates.length > 0) {
			const candidate = candidates[0];
			const { content, finishReason } = candidate;

			if (content?.parts) {
				for (const part of content.parts) {
					if (part.text) {
						if (!this.shared.sentTextBlock) {
							controller.enqueue(
								`event: content_block_start\ndata: ${JSON.stringify({
									type: 'content_block_start',
									index: this.shared.contentIndex || 0,
									content_block: { type: 'text', text: '' },
								})}\n\n`
							);
							this.shared.sentTextBlock = true;
						}
						controller.enqueue(
							`event: content_block_delta\ndata: ${JSON.stringify({
								type: 'content_block_delta',
								index: this.shared.contentIndex || 0,
								delta: { type: 'text_delta', text: part.text },
							})}\n\n`
						);
					} else if (part.functionCall) {
						const toolIndex = this.shared.contentIndex || 0;
						controller.enqueue(
							`event: content_block_start\ndata: ${JSON.stringify({
								type: 'content_block_start',
								index: toolIndex,
								content_block: {
									type: 'tool_use',
									id: `toolu_${this.generateId()}`,
									name: part.functionCall.name,
									input: part.functionCall.args,
								},
							})}\n\n`
						);
						controller.enqueue(
							`event: content_block_stop\ndata: ${JSON.stringify({
								type: 'content_block_stop',
								index: toolIndex,
							})}\n\n`
						);
						this.shared.contentIndex = (this.shared.contentIndex || 0) + 1;
					} else if ((part as any).toolCode) {
						// Send thinking content as streaming delta
						if (!this.shared.sentThinkingBlock) {
							const thinkingIndex = this.shared.contentIndex || 0;
							controller.enqueue(
								`event: content_block_start\ndata: ${JSON.stringify({
									type: 'content_block_start',
									index: thinkingIndex,
									content_block: { type: 'thinking', thinking: '' },
								})}\n\n`
							);
							this.shared.sentThinkingBlock = true;
						}
						const thinkingIndex = this.shared.contentIndex || 0;
						controller.enqueue(
							`event: content_block_delta\ndata: ${JSON.stringify({
								type: 'content_block_delta',
								index: thinkingIndex,
								delta: { type: 'thinking_delta', thinking: part.toolCode },
							})}\n\n`
						);
						// Accumulate thinking for final response
						this.shared.thinking = (this.shared.thinking || '') + part.toolCode;
					}
				}
			}

			if (finishReason) {
				this.shared.stopReason = reasonsMap[finishReason] || finishReason.toLowerCase();
			}
		}

		if (usageMetadata) {
			this.shared.usage = {
				output_tokens: usageMetadata.candidatesTokenCount || 0,
			};
		}
	}

	private transformGeminiToClaudeStreamFlush(this: any, controller: any) {
		if (this.shared.sentContentStart) {
			controller.enqueue(
				`event: content_block_stop\ndata: ${JSON.stringify({
					type: 'content_block_stop',
					index: 0,
				})}\n\n`
			);
		}

		const finalDelta = {
			type: 'message_delta',
			delta: { stop_reason: this.shared.stopReason || 'end_turn' },
			usage: this.shared.usage || { output_tokens: 0 },
		};

		controller.enqueue(`event: message_delta\ndata: ${JSON.stringify(finalDelta)}\n\n`);

		controller.enqueue(
			`event: message_stop\ndata: ${JSON.stringify({
				type: 'message_stop',
			})}\n\n`
		);
	}

	private async handleClaude(request: Request, apiKey: string): Promise<Response> {
		const requestUrl = new URL(request.url);
		const pathname = requestUrl.pathname;

		const errHandler = (err: Error) => {
			console.error(err);
			const status = err instanceof HttpError ? err.status : 500;
			return new Response(err.message ?? 'Internal Server Error', { status });
		};

		try {
			if (pathname.endsWith('/messages')) {
				if (request.method !== 'POST') throw new HttpError('Method not allowed', 405);

				const claudeReq: ClaudeCompletionRequest = await request.json();
				const geminiReqBody = await this.transformClaudeToGeminiRequest(claudeReq);

				const claudeModel = claudeReq.model;
				const geminiModel = getGeminiModelForClaude(claudeModel);
				const TASK = claudeReq.stream ? 'streamGenerateContent' : 'generateContent';
				const apiBaseUrl = this.env.GEMINI_API_BASE_URL || `${CLOUDFLARE_AI_GATEWAY_BASE}/google-ai-studio`;
				const apiVersionToUse = this.env.GEMINI_API_BASE_URL ? API_VERSION : 'v1';
				let url = `${apiBaseUrl}/${apiVersionToUse}/models/${geminiModel}:${TASK}`;
				if (claudeReq.stream) {
					url += '?alt=sse';
				}

				const geminiResponse = await fetch(url, {
					method: 'POST',
					headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
					body: JSON.stringify(geminiReqBody),
				});

				if (!geminiResponse.ok) {
					return geminiResponse; // Pass through non-ok responses directly
				}

				const id = 'claude-proxy-' + this.generateId();

				if (claudeReq.stream) {
					const { readable, writable } = new TransformStream();
					geminiResponse
						.body!.pipeThrough(new TextDecoderStream())
						.pipeThrough(
							new TransformStream({
								transform: this.parseStream, // Reuse Gemini stream parser
								flush: this.parseStreamFlush,
								buffer: '',
								shared: {},
							} as any)
						)
						.pipeThrough(
							new TransformStream({
								start: this.transformGeminiToClaudeStreamStart,
								transform: this.transformGeminiToClaudeStream,
								flush: this.transformGeminiToClaudeStreamFlush,
								model: claudeModel,
								id,
								shared: {}, // for state
							} as any)
						)
						.pipeThrough(new TextEncoderStream())
						.pipeTo(writable);

					return new Response(readable, {
						status: 200,
						headers: {
							'Content-Type': 'text/event-stream',
							'Cache-Control': 'no-cache',
							Connection: 'keep-alive',
						},
					});
				} else {
					const geminiResponseBody: GeminiResponse = await geminiResponse.json();
					return this.transformGeminiToClaudeResponse(geminiResponseBody, claudeModel, id);
				}
			}
			
			const modelsMatch = pathname.match(/models\/([^/]+)$/);
			const isModelsList = pathname.endsWith('/models');
	
			if (modelsMatch || isModelsList) {
				if (request.method !== 'GET') throw new HttpError('Method not allowed', 405);
				const modelId = modelsMatch ? modelsMatch[1] : undefined;
				const authMode = request.headers.get("X-Auth-Mode") || "claude";
				return this.handleModels(apiKey, modelId, authMode).catch(errHandler);
			}

			throw new HttpError('Not Found', 404);
		} catch (e) {
			return errHandler(e as Error);
		}
	}
}
