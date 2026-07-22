import { OAuthCredentials, SystemContext } from '../types';
import { getOAuthAccessToken, discoverProjectId, saveDiscoveredProjectId } from './oauth';
import { fetchAvailableModelsForToken } from './oauth';
import { safeLiteCompress, generateUuid } from './gemini';
import { resolveModelWithOAuthSupport } from './models';

// Official Antigravity OAuth Client Credentials
export const ANTIGRAVITY_CLIENT_ID = [
	'1071006060591',
	'tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com'
].join('-');
export const ANTIGRAVITY_CLIENT_SECRET = [
	'GOCSPX',
	'K58FWR486LdLJ1mLB8sXC4z6qDAf'
].join('-');

// Official Antigravity OAuth Scopes
export const ANTIGRAVITY_OAUTH_SCOPES = [
	'https://www.googleapis.com/auth/cloud-platform',
	'https://www.googleapis.com/auth/userinfo.email',
	'https://www.googleapis.com/auth/userinfo.profile',
	'https://www.googleapis.com/auth/cclog',
	'https://www.googleapis.com/auth/experimentsandconfigs',
];

/**
 * Returns 100% authentic Antigravity HTTP headers required for Google Cloud Code Companion API.
 */
export function getAntigravityHeaders(accessToken: string, projectId?: string): Record<string, string> {
	const headers: Record<string, string> = {
		'Authorization': `Bearer ${accessToken}`,
		'Content-Type': 'application/json',
		'Accept': 'text/event-stream',
		'User-Agent': 'antigravity/1.0.5 darwin/arm64',
		'Client-Metadata': JSON.stringify({ ideType: 'ANTIGRAVITY' }),
		'x-client-name': 'antigravity',
		'x-client-version': '1.0.5',
		'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
	};

	if (projectId && projectId !== 'default' && projectId !== 'test-project') {
		headers['x-goog-user-project'] = projectId;
	}

	return headers;
}

export const ANTIGRAVITY_ENDPOINTS = [
	'https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal',
	'https://daily-cloudcode-pa.googleapis.com/v1internal',
	'https://cloudcode-pa.googleapis.com/v1internal',
];

/**
 * Parses raw Antigravity OAuth credential string into an OAuthCredentials object.
 */
export function parseAntigravityCredentials(
	rawKey: string,
	defaultClientId: string = ANTIGRAVITY_CLIENT_ID,
	defaultClientSecret: string = ANTIGRAVITY_CLIENT_SECRET
): OAuthCredentials {
	const parts = rawKey.split(':');
	if (parts.length >= 5) {
		return {
			client_id: parts[0],
			client_secret: parts[1],
			refresh_token: parts[2],
			project_id: parts[3],
			email: parts[4],
		};
	} else if (parts.length === 2) {
		return {
			client_id: defaultClientId,
			client_secret: defaultClientSecret,
			refresh_token: parts[0],
			email: parts[1],
		};
	} else if (parts.length === 1 && parts[0]) {
		return {
			client_id: defaultClientId,
			client_secret: defaultClientSecret,
			refresh_token: parts[0],
		};
	}
	throw new Error(`Invalid Antigravity credential format: ${rawKey}`);
}

/**
 * Handles incoming Gemini requests specifically in Antigravity mode.
 * - Enforces 100% authentic Antigravity upstream headers.
 * - Strips `-agy` suffix from requested models.
 * - Handles Companion API response unwrapping.
 */
export async function handleAntigravityCli(
	request: Request,
	credentials: OAuthCredentials,
	state: DurableObjectState,
	proxyRequest: (request: Request, isStreaming: boolean, accessToken?: string) => Promise<Response>,
	model?: string,
	ctx?: SystemContext,
	antigravityKeyStates: any[] = []
): Promise<Response> {
	try {
		const reqAny = request as any;
		const requestUrl = new URL(request.url);

		const accessToken = await getOAuthAccessToken(state, credentials, ctx);
		let projectId = credentials.project_id;
		const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(projectId || '');
		if (!projectId || projectId === 'default' || isUuid) {
			projectId = await discoverProjectId(accessToken, credentials.email, true);
			await saveDiscoveredProjectId(credentials, projectId, ctx);
		}

		// Handle OAuth Model List for Antigravity (via retrieveUserQuota)
		if (requestUrl.pathname.includes('/oauth/models') || requestUrl.pathname.includes('/antigravity/models')) {
			const buckets = await fetchAvailableModelsForToken(accessToken, projectId);
			const models = buckets
				.filter((b: any) => b.modelId)
				.map((b: any) => ({
					name: `models/${b.modelId}`,
					displayName: b.modelId,
					description: `Antigravity Cloud Code Model (Remaining: ${b.remainingAmount || 'unknown'})`,
					supportedGenerationMethods: ['generateContent', 'countTokens'],
					quota: b,
				}));

			return new Response(JSON.stringify({ models, buckets }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			});
		}

		const modelMatch = requestUrl.pathname.match(/\/models\/([^/:]+)/);
		const urlModel = modelMatch ? modelMatch[1] : undefined;

		const nativeBody = await reqAny.json() as any;
		let rawModel = model || urlModel || nativeBody.model || 'gemini-2.5-pro';
		
		// Strip Antigravity suffix '-agy'
		if (rawModel && rawModel.endsWith('-agy')) {
			rawModel = rawModel.substring(0, rawModel.length - 4);
		}

		const effectiveModel = resolveModelWithOAuthSupport(rawModel, antigravityKeyStates);

		const internalRequest: any = {
			contents: safeLiteCompress((nativeBody.contents || []).map((c: any) => ({
				role: c.role || 'user',
				parts: c.parts || [],
			}))),
			generationConfig: {
				temperature: 1,
				...nativeBody.generationConfig,
				...(nativeBody.thinkingConfig || (nativeBody.generationConfig && nativeBody.generationConfig.thinkingConfig)
					? {
							thinkingConfig:
								nativeBody.thinkingConfig || nativeBody.generationConfig.thinkingConfig,
					  }
					: {}),
			},
			safetySettings: nativeBody.safetySettings || [
				{ category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
				{ category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
				{ category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' },
				{ category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
				{ category: 'HARM_CATEGORY_CIVIC_INTEGRITY', threshold: 'BLOCK_NONE' },
			],
			tools: nativeBody.tools,
			toolConfig: nativeBody.toolConfig,
			systemInstruction: nativeBody.systemInstruction || nativeBody.system_instruction,
		};

		const isStreaming =
			requestUrl.pathname.includes(':stream') || requestUrl.pathname.includes('streamGenerateContent');
		const methodVerb = isStreaming ? 'streamGenerateContent' : 'generateContent';
		const promptId = generateUuid();

		const wrappedBody = {
			project: projectId,
			model: effectiveModel,
			user_prompt_id: promptId,
			request: internalRequest,
		};

		const outgoingHeaders = getAntigravityHeaders(accessToken, projectId);

		let lastResponse: Response | null = null;

		for (let i = 0; i < ANTIGRAVITY_ENDPOINTS.length; i++) {
			const endpointBase = ANTIGRAVITY_ENDPOINTS[i];
			const url = `${endpointBase}:${methodVerb}${isStreaming ? '?alt=sse' : ''}`;

			const outgoingRequest = new Request(url, {
				method: 'POST',
				headers: outgoingHeaders,
				body: JSON.stringify(wrappedBody),
			});

			const upstreamResponse = await proxyRequest(outgoingRequest, isStreaming, accessToken);

			if (upstreamResponse.ok || (upstreamResponse.status < 500 && upstreamResponse.status !== 429 && upstreamResponse.status !== 403)) {
				if (!isStreaming && upstreamResponse.ok) {
					try {
						const responseData = await upstreamResponse.json() as any;
						const actualData = responseData.response || responseData;
						return new Response(JSON.stringify(actualData), {
							status: upstreamResponse.status,
							headers: { 'Content-Type': 'application/json' },
						});
					} catch (e) {
						return upstreamResponse;
					}
				}
				return upstreamResponse;
			}

			// Handle 403: retry without x-goog-user-project if present
			if (upstreamResponse.status === 403 && outgoingHeaders['x-goog-user-project']) {
				const retryHeaders = { ...outgoingHeaders };
				delete retryHeaders['x-goog-user-project'];
				const retryReq = new Request(url, {
					method: 'POST',
					headers: retryHeaders,
					body: JSON.stringify(wrappedBody),
				});
				const retryRes = await proxyRequest(retryReq, isStreaming, accessToken);
				if (retryRes.ok || (retryRes.status < 500 && retryRes.status !== 429)) {
					if (!isStreaming && retryRes.ok) {
						try {
							const responseData = await retryRes.json() as any;
							const actualData = responseData.response || responseData;
							return new Response(JSON.stringify(actualData), {
								status: retryRes.status,
								headers: { 'Content-Type': 'application/json' },
							});
						} catch (e) {
							return retryRes;
						}
					}
					return retryRes;
				}
				lastResponse = retryRes;
			} else {
				lastResponse = upstreamResponse;
			}

			console.warn(`Antigravity Endpoint Fallback: ${endpointBase} returned ${upstreamResponse.status}, trying next fallback endpoint...`);
		}

		if (lastResponse) {
			if (!isStreaming && lastResponse.ok) {
				try {
					const responseData = await lastResponse.json() as any;
					const actualData = responseData.response || responseData;
					return new Response(JSON.stringify(actualData), {
						status: lastResponse.status,
						headers: { 'Content-Type': 'application/json' },
					});
				} catch (e) {
					return lastResponse;
				}
			}
			return lastResponse;
		}

		return new Response('Antigravity All Endpoints Exhausted', { status: 503 });
	} catch (e: any) {
		return new Response(`Antigravity Error: ${e.message}`, { status: 500 });
	}
}
