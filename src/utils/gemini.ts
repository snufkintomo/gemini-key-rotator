import { getOAuthAccessToken, discoverProjectId, parseOAuthCredentials, saveDiscoveredProjectId, fetchAvailableModelsForToken } from './oauth';
import { parseStream, parseStreamFlush } from './streams';
import { getGeminiModelForGemini, mapModelForInternalApi } from './models';
import type { OAuthCredentials } from '../types';
import { SystemContext } from './context';

const API_VERSION = 'v1beta';

const CODE_ASSIST_HEADERS = {
	'User-Agent': 'google-api-nodejs-client/9.15.1',
	'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
	'Client-Metadata': 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI',
} as const;

function generateUuid(): string {
	return crypto.randomUUID();
}

export function safeLiteCompress(contents: any[]): any[] {
	if (!contents || !Array.isArray(contents)) return contents;

	return contents.map((item: any) => {
		if (!item || !item.parts || !Array.isArray(item.parts)) return item;

		const newParts = item.parts.map((part: any) => {
			if (part && part.text && typeof part.text === 'string') {
				let text = part.text;

				// 1. Remove trailing whitespace on each line safely
				text = text.replace(/[ \t]+$/gm, '');

				// 2. Collapse 3 or more consecutive newlines to maximum of 2 newlines (1 blank line)
				text = text.replace(/\n{3,}/g, '\n\n');

				// 3. Trim outer leading and trailing spaces
				text = text.trim();

				return { ...part, text };
			}
			return part;
		});

		return { ...item, parts: newParts };
	});
}

export async function handleGeminiCli(
	request: Request,
	credentials: OAuthCredentials,
	state: DurableObjectState,
	proxyRequest: (request: Request, isStreaming: boolean, accessToken?: string) => Promise<Response>,
	model?: string,
	ctx?: SystemContext,
	oauthKeyStates: any[] = []
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

		// Handle OAuth Model List (via retrieveUserQuota)
		if (requestUrl.pathname.includes('/oauth/models')) {
			const buckets = await fetchAvailableModelsForToken(accessToken, projectId);
			
			// Transform to Gemini listModels format from buckets
			const models = buckets
				.filter((b: any) => b.modelId)
				.map((b: any) => ({
					name: `models/${b.modelId}`,
					displayName: b.modelId,
					description: `Cloud Code Internal Model (Remaining: ${b.remainingAmount || 'unknown'})`,
					supportedGenerationMethods: ['generateContent', 'countTokens'],
					quota: b, // Extra information for debugging/advanced usage
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
		if (rawModel && rawModel.endsWith('-oauth')) {
			rawModel = rawModel.substring(0, rawModel.length - 6);
		}
		const { resolveModelWithOAuthSupport } = await import('./models');
		const effectiveModel = resolveModelWithOAuthSupport(rawModel, oauthKeyStates);

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

		const companionHeaders = {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${accessToken}`,
			...CODE_ASSIST_HEADERS,
		};

		let response = await proxyRequest(
			new Request(url, {
				method: 'POST',
				headers: companionHeaders,
				body: JSON.stringify(wrappedBody),
			} as any),
			isStreaming,
			accessToken
		);

		if (!response.ok) {
			const cloneRes = response.clone();
			try {
				const errorJson = await cloneRes.json() as any;
				const isPermissionOrNotFound = response.status === 403 || response.status === 404;
				const hasCompanionIndicator = JSON.stringify(errorJson).includes('cloudaicompanion.googleapis.com') || JSON.stringify(errorJson).includes('Permission denied on resource project');
				
				if (isPermissionOrNotFound && hasCompanionIndicator) {
					// Dynamically import enableCompanionApi to avoid circular dependencies
					const { enableCompanionApi } = await import('./oauth');
					const enabled = await enableCompanionApi(accessToken, projectId);
					if (enabled) {
						// Wait 1.5 seconds for Google Cloud API enablement to propagate
						await new Promise((resolve) => setTimeout(resolve, 1500));
						// Retry the request once
						response = await proxyRequest(
							new Request(url, {
								method: 'POST',
								headers: companionHeaders,
								body: JSON.stringify(wrappedBody),
							} as any),
							isStreaming,
							accessToken
						);
					}
				}
			} catch (e) {
				// Ignore parsing errors and fall through
			}
		}

		if (!response.ok) return response;

		if (isStreaming) {
			const unwrapStream = new TransformStream({
				transform(chunk, controller) {
					if (chunk && typeof chunk === 'object' && 'response' in chunk) {
						controller.enqueue(chunk.response);
					} else {
						controller.enqueue(chunk);
					}
				}
			});

			const standardStream = response.body!
				.pipeThrough(new TextDecoderStream())
				.pipeThrough(new TransformStream({ transform: parseStream, flush: parseStreamFlush, buffer: '', shared: {} } as any))
				.pipeThrough(unwrapStream)
				.pipeThrough(new TransformStream({
					transform(data, controller) {
						controller.enqueue(`data: ${JSON.stringify(data)}\n\n`);
					}
				}))
				.pipeThrough(new TextEncoderStream());

			return new Response(standardStream, {
				status: 200,
				headers: {
					'Content-Type': 'text/event-stream',
					'Cache-Control': 'no-cache',
					Connection: 'keep-alive',
				},
			});
		} else {
			const data = await response.json() as any;
			if (data && data.error) {
				return new Response(JSON.stringify(data), {
					status: data.error.code || 400,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			// Simple transform back to Gemini format
			const actualData = data.response || data;
			const transformed = {
				candidates: (actualData.candidates || []).map((cand: any) => ({
					content: {
						parts: (cand.content?.parts || []).map((p: any) => ({
							text: p.text || '',
						})),
						role: cand.content?.role || 'model',
					},
					finishReason: cand.finishReason || 'STOP',
					index: cand.index || 0,
					safetyRatings: cand.safetySettings || [],
				})),
				usageMetadata: actualData.usageMetadata || {
					promptTokenCount: 0,
					candidatesTokenCount: 0,
					totalTokenCount: 0,
				},
			};

			return new Response(JSON.stringify(transformed), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	} catch (e: any) {
		return new Response(JSON.stringify({ error: { message: e.message } }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

export function getGeminiModelFromPath(pathname: string): string | undefined {
	const match = pathname.match(/\/models\/([^/:]+)/);
	return match ? match[1] : undefined;
}

function makeHeaders(apiKey: string): { [key: string]: string } {
    return {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey
    };
}

export async function handleGemini(
	request: Request,
	apiKey: string,
	getNextApiBaseUrl: (isStreaming: boolean) => Promise<string>,
	proxyRequest: (request: Request, isStreaming: boolean, accessToken?: string) => Promise<Response>,
	state: DurableObjectState,
	model?: string,
	defaultClientId?: string,
	defaultClientSecret?: string,
	ctx?: SystemContext,
	oauthKeyStates: any[] = []
): Promise<Response> {
	const requestUrl = new URL(request.url);

	if (apiKey.includes(':') || requestUrl.pathname.includes('/oauth/models')) {
		try {
			const credentials = parseOAuthCredentials(apiKey, defaultClientId, defaultClientSecret);
			return await handleGeminiCli(request, credentials, state, proxyRequest, model, ctx, oauthKeyStates);
		} catch (e: any) {
			return new Response(`OAuth Error: ${e.message}`, { status: 401 });
		}
	}
	const isStreaming = requestUrl.pathname.includes(":stream") || requestUrl.pathname.includes("streamGenerateContent");
    let apiBaseUrl = await getNextApiBaseUrl(isStreaming);
    const urlModel = getGeminiModelFromPath(requestUrl.pathname);
    
    let newPathname = requestUrl.pathname;
    if (urlModel) {
        const newModel = model || getGeminiModelForGemini(urlModel);
        if (urlModel !== newModel && newModel) {
            newPathname = requestUrl.pathname.replace(urlModel, newModel);
        }
    }
    
    let targetUrl = new URL(`${apiBaseUrl}${newPathname}${requestUrl.search}`);
    if (targetUrl.searchParams.has("key")) targetUrl.searchParams.delete("key");
    
    if (isStreaming) {
        targetUrl.searchParams.set("alt", "sse");
    }
    
    let requestBody: any = ['POST', 'PUT', 'PATCH'].includes(request.method.toUpperCase()) && request.body ? await request.clone().json() : null;
    if (requestBody && requestBody.contents) {
        requestBody.contents = safeLiteCompress(requestBody.contents);
    }
    
    return proxyRequest(
        new Request(targetUrl.toString(), { 
            method: request.method, 
            headers: new Headers(makeHeaders(apiKey)), 
            body: requestBody ? JSON.stringify(requestBody) : null, 
            redirect: 'follow' 
        } as any), 
        isStreaming, 
        apiKey
    );
}
