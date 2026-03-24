import { ApiCredentials, KeyState } from './types';
import {
	handleModels,
	parseRequestModel,
	resolveModelAndAuthMode,
} from './utils/models';
import { handleOpenAI, handleEmbeddings } from './utils/openai';
import { handleClaude } from './utils/claude';
import { handleGemini } from './utils/gemini';
import { proxyRequest } from './utils/proxy';
import { SystemContext } from './utils/context';
import { createErrorResponse, Protocol } from './utils/errors';
import { StorageHelper } from './utils/storage';
import { getStandardRotationIndex, parseCredentials } from './utils/credentials';
import { sendInvalidTokenEmail, sendExhaustedEmail } from './utils/email';

// --- Types ---
export interface Env {
	DB: D1Database;
	GEMINI_API_BASE_URL?: string;
	OAUTH_CLIENT_ID?: string;
	OAUTH_CLIENT_SECRET?: string;
	CLOUDFLARE_AI_GATEWAY_ID: string;
	CLOUDFLARE_AI_GATEWAY_NAME: string;
	ENABLE_API_LOGGING?: string;
	ENABLE_CLOUDFLARE_AI_GATEWAY?: string;
	ENABLE_ORG_GEMINI_API_BASE_URL?: string;
	ENABLE_USAGE_STATISTICS?: string;
	NOTIFICATION_EMAIL?: string;
	RESEND_API_KEY?: string;
}

export class KeyRotator {
	ctx: SystemContext;
	storage: StorageHelper;

	constructor(state: DurableObjectState, env: Env) {
		this.ctx = new SystemContext(state, env);
		this.storage = new StorageHelper(state.storage);
	}

	async getNextApiBaseUrl(): Promise<string> {
		const endpoints: string[] = [];
		if (this.ctx.isCloudflareAIGatewayEnabled) {
			endpoints.push(`${this.ctx.cloudflareAIGatewayBase}/google-ai-studio`);
		}
		if (this.ctx.isOrgGeminiApiEnabled) {
			endpoints.push(this.ctx.orgGeminiApiBaseUrl);
		}
		if (this.ctx.env.GEMINI_API_BASE_URL) {
			endpoints.push(this.ctx.env.GEMINI_API_BASE_URL);
		}

		let currentIndex = await this.storage.getApiBaseUrlIndex();
		const nextIndex = (currentIndex + 1) % endpoints.length;
		this.ctx.waitUntil(this.storage.setApiBaseUrlIndex(nextIndex));

		return endpoints[currentIndex];
	}

	async recordUsage(
		rawKey: string,
		keyType: 'api_key' | 'oauth',
		userToken: string,
		success: boolean,
		is429: boolean,
		mode: string,
		model: string
	) {
		if (!this.ctx.isUsageStatisticsEnabled) return;

		const today = new Date().toISOString().split('T')[0];
		const successInc = success ? 1 : 0;
		const error429Inc = is429 ? 1 : 0;
		const safeMode = mode || 'unknown';
		const safeModel = model || 'unknown';

		const query = `
			INSERT INTO api_key_usage (raw_key, key_type, usage_date, user_access_token, mode, model, request_count, success_count, error_429_count)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
			ON CONFLICT(raw_key, usage_date, user_access_token, mode, model) DO UPDATE SET
				request_count = request_count + 1,
				success_count = success_count + ?,
				error_429_count = error_429_count + ?
		`;

		try {
			await this.ctx.env.DB.prepare(query)
				.bind(
					rawKey,
					keyType,
					today,
					userToken,
					safeMode,
					safeModel,
					successInc,
					error429Inc,
					successInc,
					error429Inc
				)
				.run();
		} catch (e) {
			console.error('Error recording usage statistics:', e);
		}
	}

	async notifyInvalidToken(tokenType: 'api_key' | 'oauth', rawToken: string, reason: string) {
		const resendKey = this.ctx.resendApiKey;
		const toEmail = this.ctx.notificationEmail;

		if (resendKey && toEmail) {
			this.ctx.waitUntil(sendInvalidTokenEmail(resendKey, toEmail, tokenType, rawToken, reason));
		}
	}

	async notifyExhausted(userToken: string, hasFallbackOAuth: boolean, model: string) {
		const resendKey = this.ctx.resendApiKey;
		const toEmail = this.ctx.notificationEmail;

		if (!resendKey || !toEmail) return;

		// Cooldown: 1 hour (3600000 ms)
		const cooldown = 3600000;
		const now = Date.now();
		const lastSentKey = `last_exhausted_email_${userToken}`;
		const lastSent = await this.storage.get<number>(lastSentKey);

		if (!lastSent || now - lastSent > cooldown) {
			await this.storage.put(lastSentKey, now);
			this.ctx.waitUntil(sendExhaustedEmail(resendKey, toEmail, userToken, hasFallbackOAuth, model));
		}
	}

	async fetch(request: Request): Promise<Response> {
		const clonedRequest = request.clone();
		const requestUrl = new URL(request.url);
		const userAccessToken = request.headers.get('X-Access-Token');
		const authMode = request.headers.get('X-Auth-Mode');
		const protocol = authMode as Protocol;

		// Handle key health status requests (Internal/Admin only)
		if (requestUrl.pathname === '/admin/key-status' && request.method === 'GET') {
			if (!userAccessToken) return createErrorResponse('Unauthorized', 401, protocol);

			const stmt = this.ctx.env.DB.prepare(
				'SELECT api_keys, key_states, oauth_credentials, oauth_key_states FROM api_credentials WHERE access_token = ?'
			);
			const dbResult = await stmt.bind(userAccessToken).first<any>();
			if (!dbResult) return createErrorResponse('Not Found', 404, protocol);

			return new Response(
				JSON.stringify({
					api_keys: dbResult.api_keys ? dbResult.api_keys.split(',') : [],
					key_states: JSON.parse(dbResult.key_states || '[]'),
					oauth_credentials: dbResult.oauth_credentials ? dbResult.oauth_credentials.split(',') : [],
					oauth_key_states: JSON.parse(dbResult.oauth_key_states || '[]'),
				}),
				{ headers: { 'Content-Type': 'application/json' } }
			);
		}

		// Handle key health reset requests (Internal/Admin only)
		if (requestUrl.pathname === '/admin/reset-key-health' && request.method === 'POST') {
			if (!userAccessToken) return createErrorResponse('Unauthorized', 401, protocol);

			const { key, isOAuth } = (await request.json()) as { key: string; isOAuth: boolean };
			if (!key) return createErrorResponse('Key is required', 400, protocol);

			const stmt = this.ctx.env.DB.prepare(
				'SELECT api_keys, key_states, oauth_credentials, oauth_key_states FROM api_credentials WHERE access_token = ?'
			);
			const dbResult = await stmt.bind(userAccessToken).first<any>();
			if (!dbResult) return createErrorResponse('Not Found', 404, protocol);

			const { apiKeys, keyStates, oauthCredentialsList, oauthKeyStates } = parseCredentials(dbResult);

			if (isOAuth) {
				const index = oauthCredentialsList.indexOf(key);
				if (index !== -1 && oauthKeyStates[index]) {
					oauthKeyStates[index] = {}; // Reset state
					await this.ctx.env.DB.prepare(
						'UPDATE api_credentials SET oauth_key_states = ? WHERE access_token = ?'
					)
						.bind(JSON.stringify(oauthKeyStates), userAccessToken)
						.run();
				}
			} else {
				const index = apiKeys.indexOf(key);
				if (index !== -1 && keyStates[index]) {
					keyStates[index] = {}; // Reset state
					await this.ctx.env.DB.prepare(
						'UPDATE api_credentials SET key_states = ? WHERE access_token = ?'
					)
						.bind(JSON.stringify(keyStates), userAccessToken)
						.run();
				}
			}

			return new Response(JSON.stringify({ success: true }), {
				headers: { 'Content-Type': 'application/json' },
			});
		}

		if (!userAccessToken) {
			return createErrorResponse('Unauthorized: Access token is required.', 401, protocol);
		}

		const pathname = requestUrl.pathname;
		const isMetadataRequest =
			request.method === 'GET' &&
			(pathname.endsWith('/models') ||
				pathname.includes('/models/') ||
				pathname.includes('/v1/models') ||
				pathname.includes('/v1beta/models'));

		const rawModel = await parseRequestModel(clonedRequest.clone() as any);
		const resolved = resolveModelAndAuthMode(rawModel, authMode, userAccessToken);

		// Handle /oauth/models explicitly to force OAuth mode
		if (pathname.includes('/oauth/models')) {
			resolved.useOAuth = true;
		}
		const model = resolved.model;
		const isOAuthMode = resolved.useOAuth;

		const stmt = this.ctx.env.DB.prepare(
			'SELECT api_keys, current_key_index, key_states, oauth_credentials, current_oauth_index, oauth_key_states FROM api_credentials WHERE access_token = ?'
		);
		const dbResult = await stmt.bind(userAccessToken).first<ApiCredentials>();

		if (!dbResult) {
			return createErrorResponse('Unauthorized: Invalid access token.', 401, protocol);
		}

		const {
			apiKeys,
			keyStates,
			oauthCredentialsList,
			oauthKeyStates,
			currentKeyIndex,
			currentOauthIndex,
		} = parseCredentials(dbResult);

		const modelForExhaustion = model || '_general_';

		let apiKey = '';
		let keyIndexToUse: number | null = null;
		let oauthIndexToUse: number | null = null;
		let effectivelyOAuth = isOAuthMode;

		if (isOAuthMode) {
			oauthIndexToUse = getStandardRotationIndex(
				oauthCredentialsList,
				currentOauthIndex,
				oauthKeyStates,
				modelForExhaustion,
				Date.now()
			);

			if (oauthIndexToUse === null) {
				if (oauthCredentialsList.length > 0) {
					return createErrorResponse(
						'All OAuth credentials for your account are currently exhausted. Please try again later.',
						429,
						protocol
					);
				}
				return createErrorResponse('No OAuth credentials configured for this account.', 401, protocol);
			}
			apiKey = oauthCredentialsList[oauthIndexToUse];
		} else {
			keyIndexToUse = getStandardRotationIndex(
				apiKeys,
				currentKeyIndex,
				keyStates,
				modelForExhaustion,
				Date.now()
			);

			if (keyIndexToUse === null) {
				// Standard keys are exhausted, try fallback to OAuth
				let hasOAuthAvailable = oauthCredentialsList.length > 0;
				let oauthFallbacked = false;

				if (hasOAuthAvailable) {
					oauthIndexToUse = getStandardRotationIndex(
						oauthCredentialsList,
						currentOauthIndex,
						oauthKeyStates,
						modelForExhaustion,
						Date.now()
					);
					if (oauthIndexToUse !== null) {
						apiKey = oauthCredentialsList[oauthIndexToUse];
						effectivelyOAuth = true;
						oauthFallbacked = true;
					}
				}

				// Trigger notification for standard key exhaustion
				this.ctx.waitUntil(this.notifyExhausted(userAccessToken, oauthFallbacked, modelForExhaustion));

				if (!apiKey) {
					return createErrorResponse(
						'All API keys (and fallback OAuth credentials) for your account are currently exhausted. Please try again later.',
						429,
						protocol
					);
				}
			} else {
				apiKey = apiKeys[keyIndexToUse];
			}
		}

		const doProxy = async (apiKeyToUse: string, requestToProxy: Request) => {
			const proxyReqBody =
				requestToProxy.method === 'POST'
					? await requestToProxy
							.clone()
							.text()
							.then((t) => (t ? JSON.parse(t) : null))
					: null;
			const pathname = new URL(requestToProxy.url).pathname;

			const handleGeminiRef = (req: Request, key: string, mod?: string) =>
				handleGemini(
					req as any,
					key,
					this.getNextApiBaseUrl.bind(this),
					(r: Request, stream: boolean, token?: string) =>
						proxyRequest(
							r,
							stream,
							this.ctx.env.DB,
							this.ctx.waitUntil.bind(this.ctx),
							this.ctx.isLoggingEnabled,
							token
						),
					this.ctx.state,
					mod,
					this.ctx.env.OAUTH_CLIENT_ID,
					this.ctx.env.OAUTH_CLIENT_SECRET,
					this.ctx
				);

			if (authMode === 'openai') {
				return handleOpenAI(
					proxyReqBody,
					pathname,
					requestToProxy.method,
					apiKeyToUse,
					model,
					handleGeminiRef as any,
					((key: string, mid: string | undefined, am: string, mod?: string) =>
						handleModels(key, mid, am, handleGeminiRef as any, mod)) as any,
					((req: any, key: string, resModel: string | undefined) =>
						handleEmbeddings(req, key, handleGeminiRef as any, resModel)) as any
				);
			} else if (authMode === 'claude') {
				return handleClaude(
					proxyReqBody as any,
					pathname,
					requestToProxy.method,
					apiKeyToUse,
					model,
					handleGeminiRef as any,
					((key: string, mid: string | undefined, am: string, mod?: string) =>
						handleModels(key, mid, am, handleGeminiRef as any, mod)) as any
				);
			}

			return handleGeminiRef(requestToProxy, apiKeyToUse, model);
		};

		let response = await doProxy(apiKey, clonedRequest.clone() as any);

		// Record initial usage (exclude metadata requests)
		if (!isMetadataRequest) {
			this.ctx.waitUntil(
				this.recordUsage(
					apiKey,
					effectivelyOAuth ? "oauth" : "api_key",
					userAccessToken,
					response.ok,
					response.status === 429,
					authMode || "google",
					model || "unknown"
				)
			);
		}

		let attemptCount = 1;
		let activeKeys = effectivelyOAuth ? oauthCredentialsList : apiKeys;
		let activeStates = effectivelyOAuth ? oauthKeyStates : keyStates;
		let activeIndex = effectivelyOAuth ? oauthIndexToUse! : keyIndexToUse!;

		let maxAttempts = Math.min(activeKeys.length, 3);
		while (
			[401, 403, 429, 500, 502, 503, 524].includes(response.status) &&
			attemptCount < maxAttempts
		) {
			if (response.status === 401 || response.status === 403) {
				activeStates[activeIndex] = {
					...activeStates[activeIndex],
					invalid: true,
				};
				this.ctx.waitUntil(
					this.notifyInvalidToken(
						effectivelyOAuth ? "oauth" : "api_key",
						apiKey,
						`API returned ${response.status}`
					)
				);
			} else if (response.status === 429) {
				const currentState = activeStates[activeIndex] || {};
				const currentExhausted = currentState.exhaustedUntil || {};
				const lastExhaustedUntil = currentExhausted[modelForExhaustion] || 0;
				const now = Date.now();

				// Exponential backoff: Start with 1 minute, double it each time if hit again before previous cooldown was fully cleared
				let cooldown = 60 * 1000;
				if (lastExhaustedUntil > now - 300 * 1000) {
					const prevCooldown = lastExhaustedUntil - (now - cooldown);
					cooldown = Math.min(
						Math.max(prevCooldown * 2, cooldown * 2),
						1800 * 1000
					); // Max half hour
				}

				activeStates[activeIndex] = {
					...currentState,
					exhaustedUntil: {
						...currentExhausted,
						[modelForExhaustion]: now + cooldown,
					},
				};
			}

			let nextIndex: number | null = null;
			const now = Date.now();
			for (let i = 1; i < activeKeys.length; i++) {
				const idx = (activeIndex + i) % activeKeys.length;
				if (activeStates[idx]?.invalid) continue;
				if (
					modelForExhaustion &&
					activeStates[idx]?.exhaustedUntil?.[modelForExhaustion] &&
					activeStates[idx].exhaustedUntil![modelForExhaustion] > now
				)
					continue;
				nextIndex = idx;
				break;
			}

			if (nextIndex === null || nextIndex === activeIndex) break;
			activeIndex = nextIndex;
			if (effectivelyOAuth) oauthIndexToUse = nextIndex;
			else keyIndexToUse = nextIndex;
			apiKey = activeKeys[activeIndex];
			attemptCount++;
			response = await doProxy(apiKey, clonedRequest.clone() as any);

			// Record retry usage (exclude metadata requests)
			if (!isMetadataRequest) {
				this.ctx.waitUntil(
					this.recordUsage(
						apiKey,
						effectivelyOAuth ? "oauth" : "api_key",
						userAccessToken,
						response.ok,
						response.status === 429,
						authMode || "google",
						model || "unknown"
					)
				);
			}
		}

		let updatePromise;
		if (effectivelyOAuth) {
			const nextOauthIndexForDb =
				oauthIndexToUse !== null
					? (oauthIndexToUse + 1) % oauthCredentialsList.length
					: currentOauthIndex;
			updatePromise = this.ctx.env.DB.prepare(
				"UPDATE api_credentials SET current_oauth_index = ?, oauth_key_states = ? WHERE access_token = ?"
			)
				.bind(nextOauthIndexForDb, JSON.stringify(oauthKeyStates), userAccessToken)
				.run();
		} else {
			const nextKeyIndexForDb =
				keyIndexToUse !== null
					? (keyIndexToUse + 1) % apiKeys.length
					: currentKeyIndex;
			updatePromise = this.ctx.env.DB.prepare(
				"UPDATE api_credentials SET current_key_index = ?, key_states = ? WHERE access_token = ?"
			)
				.bind(nextKeyIndexForDb, JSON.stringify(keyStates), userAccessToken)
				.run();
		}
		this.ctx.waitUntil(updatePromise);

		return response;
	}
}
