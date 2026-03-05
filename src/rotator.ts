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

	async fetch(request: Request): Promise<Response> {
		const clonedRequest = request.clone();
		const userAccessToken = request.headers.get('X-Access-Token');
		const authMode = request.headers.get('X-Auth-Mode');
		const protocol = authMode as Protocol;

		if (!userAccessToken) {
			return createErrorResponse('Unauthorized: Access token is required.', 401, protocol);
		}

		const rawModel = await parseRequestModel(clonedRequest.clone() as any);
		const resolved = resolveModelAndAuthMode(rawModel, authMode, userAccessToken);
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
			if (apiKeys.length === 0) {
				return createErrorResponse(
					'Internal configuration error: No API keys available for this user.',
					503,
					protocol
				);
			}

			keyIndexToUse = getStandardRotationIndex(
				apiKeys,
				currentKeyIndex,
				keyStates,
				modelForExhaustion,
				Date.now()
			);

			if (keyIndexToUse === null) {
				return createErrorResponse(
					'All API keys for your account are currently exhausted. Please try again later.',
					429,
					protocol
				);
			}
			apiKey = apiKeys[keyIndexToUse];
		}

		const doProxy = async (apiKeyToUse: string, requestToProxy: Request) => {
			const proxyReqBody = requestToProxy.method === 'POST' ? await requestToProxy.clone().json() : null;
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
			this.ctx.env.OAUTH_CLIENT_SECRET
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

		let attemptCount = 1;
		let activeKeys = isOAuthMode ? oauthCredentialsList : apiKeys;
		let activeStates = isOAuthMode ? oauthKeyStates : keyStates;
		let activeIndex = isOAuthMode ? oauthIndexToUse! : keyIndexToUse!;

		let maxAttempts = Math.min(activeKeys.length, 3);
		while ([401, 403, 429, 500, 502, 503, 524].includes(response.status) && attemptCount < maxAttempts) {
			if (response.status === 401 || response.status === 403) {
				activeStates[activeIndex] = { ...activeStates[activeIndex], invalid: true };
			} else if (response.status === 429) {
				const cooldown = 60 * 1000;
				const currentState = activeStates[activeIndex] || {};
				const currentExhausted = currentState.exhaustedUntil || {};
				activeStates[activeIndex] = {
					...currentState,
					exhaustedUntil: {
						...currentExhausted,
						[modelForExhaustion]: Date.now() + cooldown,
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
			if (isOAuthMode) oauthIndexToUse = nextIndex;
			else keyIndexToUse = nextIndex;
			apiKey = activeKeys[activeIndex];
			attemptCount++;
			response = await doProxy(apiKey, clonedRequest.clone() as any);
		}

		let updatePromise;
		if (isOAuthMode) {
			const nextOauthIndexForDb =
				oauthIndexToUse !== null
					? (oauthIndexToUse + 1) % oauthCredentialsList.length
					: currentOauthIndex;
			updatePromise = this.ctx.env.DB.prepare(
				'UPDATE api_credentials SET current_oauth_index = ?, oauth_key_states = ? WHERE access_token = ?'
			)
				.bind(nextOauthIndexForDb, JSON.stringify(oauthKeyStates), userAccessToken)
				.run();
		} else {
			const nextKeyIndexForDb =
				keyIndexToUse !== null ? (keyIndexToUse + 1) % apiKeys.length : currentKeyIndex;
			updatePromise = this.ctx.env.DB.prepare(
				'UPDATE api_credentials SET current_key_index = ?, key_states = ? WHERE access_token = ?'
			)
				.bind(nextKeyIndexForDb, JSON.stringify(keyStates), userAccessToken)
				.run();
		}
		this.ctx.waitUntil(updatePromise);

		return response;
	}
}
