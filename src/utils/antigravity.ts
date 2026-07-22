import { OAuthCredentials, SystemContext } from '../types';
import { getOAuthAccessToken, discoverProjectId, saveDiscoveredProjectId } from './oauth';
import { fetchAvailableModelsForToken } from './oauth';
import { safeLiteCompress, generateUuid } from './gemini';
import { resolveModelWithOAuthSupport } from './models';

// Official Antigravity OAuth Client Credentials
export const ANTIGRAVITY_CLIENT_ID = '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com';
export const ANTIGRAVITY_CLIENT_SECRET = 'GOCSPX-K5FWR486LdLJ1mLB8sXC4z6qDAf';

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
export function getAntigravityHeaders(accessToken: string): Record<string, string> {
	return {
		'Authorization': `Bearer ${accessToken}`,
		'Content-Type': 'application/json',
		'Accept': 'text/event-stream',
		'User-Agent': 'antigravity/1.0.5 darwin/arm64',
		'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
		'Client-Metadata': JSON.stringify({ ideType: 'ANTIGRAVITY' }),
	};
}

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
			projectId = await discoverProjectId(accessToken, credentials.email);
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
		const url = `https://cloudcode-pa.googleapis.com/v1internal:${methodVerb}${
			isStreaming ? '?alt=sse' : ''
		}`;
		const promptId = generateUuid();

		const wrappedBody = {
			project: projectId,
			model: effectiveModel,
			user_prompt_id: promptId,
			request: internalRequest,
		};

		const outgoingHeaders = getAntigravityHeaders(accessToken);

		const outgoingRequest = new Request(url, {
			method: 'POST',
			headers: outgoingHeaders,
			body: JSON.stringify(wrappedBody),
		});

		const upstreamResponse = await proxyRequest(outgoingRequest, isStreaming, accessToken);

		// Handle unwrapping for non-streaming Companion API responses
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
	} catch (e: any) {
		return new Response(`Antigravity Error: ${e.message}`, { status: 500 });
	}
}
