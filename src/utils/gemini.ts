import { getOAuthAccessToken, discoverProjectId, parseOAuthCredentials } from './oauth';
import { parseStream, parseStreamFlush } from './streams';
import { getGeminiModelForGemini, mapModelForInternalApi } from './models';
import type { OAuthCredentials } from '../types';

const API_VERSION = 'v1beta';

const CODE_ASSIST_HEADERS = {
	'User-Agent': 'google-api-nodejs-client/9.15.1',
	'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
	'Client-Metadata': 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI',
} as const;

function generateUuid(): string {
	return crypto.randomUUID();
}

export async function handleGeminiCli(
	request: Request,
	credentials: OAuthCredentials,
	state: DurableObjectState,
	proxyRequest: (request: Request, isStreaming: boolean, accessToken?: string) => Promise<Response>,
	model?: string
): Promise<Response> {
	try {
		const reqAny = request as any;
		const requestUrl = new URL(request.url);
		const modelMatch = requestUrl.pathname.match(/\/models\/([^/:]+)/);
		const urlModel = modelMatch ? modelMatch[1] : undefined;

		const accessToken = await getOAuthAccessToken(state, credentials);
		let projectId = credentials.project_id;
		if (!projectId) {
			projectId = await discoverProjectId(accessToken);
			credentials.project_id = projectId;
		}

		const nativeBody = await reqAny.json() as any;
		const rawModel = model || urlModel || nativeBody.model || 'gemini-2.5-pro';
		const effectiveModel = mapModelForInternalApi(rawModel);

		const internalRequest: any = {
			contents: (nativeBody.contents || []).map((c: any) => ({
				role: c.role || 'user',
				parts: c.parts || [],
			})),
			generationConfig: {
				maxOutputTokens: 64000,
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

		const headers = {
			Authorization: `Bearer ${accessToken}`,
			'Content-Type': 'application/json',
			...CODE_ASSIST_HEADERS,
			'x-activity-request-id': promptId,
		};

		const wrappedBody = {
			project: projectId,
			model: effectiveModel,
			user_prompt_id: promptId,
			request: internalRequest,
		};

		const response = await proxyRequest(
			new Request(url, {
				method: 'POST',
				headers,
				body: JSON.stringify(wrappedBody),
			} as any),
			isStreaming,
			accessToken
		);

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
				headers: {
					'Content-Type': 'text/event-stream',
					'Cache-Control': 'no-cache',
					'Connection': 'keep-alive',
				}
			});
		} else {
			const data = await response.json() as any;
			if (data && typeof data === 'object' && 'response' in data) {
				return new Response(JSON.stringify(data.response), {
					status: response.status,
					headers: { 'Content-Type': 'application/json' }
				});
			}
			return new Response(JSON.stringify(data), {
				status: response.status,
				headers: { 'Content-Type': 'application/json' }
			});
		}
	} catch (error) {
		console.error('Gemini CLI request failed:', error);
		return new Response(`Gemini CLI Error: ${error}`, { status: 500 });
	}
}

export function makeHeaders(apiKey: string, more?: Record<string, string>) {
    return {
        ...(apiKey && { 'x-goog-api-key': apiKey }),
        ...more,
    };
}

export function getGeminiModelFromPath(pathname: string): string | undefined {
    const modelMatch = pathname.match(/models\/([^/:]+)/);
    if (modelMatch && modelMatch[1] && modelMatch[1] !== 'models') {
        return modelMatch[1];
    }
    return undefined;
}

export async function handleGemini(
	request: Request,
	apiKey: string,
	getNextApiBaseUrl: () => Promise<string>,
	proxyRequest: (request: Request, isStreaming: boolean, accessToken?: string) => Promise<Response>,
	state: DurableObjectState,
	model?: string,
	defaultClientId?: string,
	defaultClientSecret?: string
): Promise<Response> {
	if (apiKey.includes(':')) {
		try {
			const credentials = parseOAuthCredentials(apiKey, defaultClientId, defaultClientSecret);
			return await handleGeminiCli(request, credentials, state, proxyRequest, model);
		} catch (e: any) {
			return new Response(`OAuth Error: ${e.message}`, { status: 401 });
		}
	}

	const requestUrl = new URL(request.url);
    let apiBaseUrl = await getNextApiBaseUrl();
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
    
    const isStreaming = requestUrl.pathname.includes(":stream") || requestUrl.pathname.includes("streamGenerateContent");
    if (isStreaming) {
        targetUrl.searchParams.set("alt", "sse");
    }
    
    let requestBody: any = ['POST', 'PUT', 'PATCH'].includes(request.method.toUpperCase()) && request.body ? await request.clone().json() : null;
    
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
