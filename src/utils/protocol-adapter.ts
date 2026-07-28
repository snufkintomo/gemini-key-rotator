/**
 * Deep Module: ProtocolAdapter Seam
 * Unifies request translation, model mapping, and response/stream formatting
 * across OpenAI, Claude, Gemini, and Antigravity protocols.
 */

import { mapModelForInternalApi } from './models';

export interface NormalizedPayload {
	contents: any[];
	model: string;
	systemInstruction?: any;
	tools?: any[];
	generationConfig?: any;
	rawPayload?: any;
}

export interface ProtocolAdapter {
	translateRequest(req: Request, targetModel?: string): Promise<NormalizedPayload>;
	translateResponse(res: Response, isStreaming?: boolean): Promise<Response>;
}

/**
 * Safely parses the JSON body from an incoming HTTP Request clone.
 */
async function parseRequestBody(req: Request): Promise<any> {
	try {
		return await req.clone().json();
	} catch {
		return {};
	}
}

/**
 * OpenAI Protocol Adapter
 */
export class OpenAIAdapter implements ProtocolAdapter {
	async translateRequest(req: Request, targetModel?: string): Promise<NormalizedPayload> {
		const body = await parseRequestBody(req);
		const rawModel = targetModel || body.model || 'gpt-4o';
		const mappedModel = mapModelForInternalApi(rawModel);

		return {
			contents: body.messages || [],
			model: mappedModel,
			tools: body.tools,
			rawPayload: body
		};
	}

	async translateResponse(res: Response, isStreaming?: boolean): Promise<Response> {
		if (!res.ok) return res;
		return res;
	}
}

/**
 * Claude Protocol Adapter
 */
export class ClaudeAdapter implements ProtocolAdapter {
	async translateRequest(req: Request, targetModel?: string): Promise<NormalizedPayload> {
		const body = await parseRequestBody(req);
		const rawModel = targetModel || body.model || 'claude-3-7-sonnet';
		const mappedModel = mapModelForInternalApi(rawModel);

		return {
			contents: body.messages || [],
			model: mappedModel,
			systemInstruction: body.system,
			tools: body.tools,
			rawPayload: body
		};
	}

	async translateResponse(res: Response, isStreaming?: boolean): Promise<Response> {
		if (!res.ok) return res;
		return res;
	}
}

/**
 * Gemini Native Adapter
 */
export class GeminiAdapter implements ProtocolAdapter {
	async translateRequest(req: Request, targetModel?: string): Promise<NormalizedPayload> {
		const body = await parseRequestBody(req);
		const rawModel = targetModel || body.model || 'gemini-2.5-flash';
		const mappedModel = mapModelForInternalApi(rawModel);

		return {
			contents: body.contents || [],
			model: mappedModel,
			systemInstruction: body.systemInstruction,
			tools: body.tools,
			generationConfig: body.generationConfig,
			rawPayload: body
		};
	}

	async translateResponse(res: Response, isStreaming?: boolean): Promise<Response> {
		return res;
	}
}

/**
 * Antigravity Protocol Adapter
 */
export class AntigravityAdapter implements ProtocolAdapter {
	async translateRequest(req: Request, targetModel?: string): Promise<NormalizedPayload> {
		const body = await parseRequestBody(req);
		const rawModel = targetModel || body.model || 'gemini-2.5-flash-agy';
		const mappedModel = mapModelForInternalApi(rawModel);

		return {
			contents: body.contents || body.messages || [],
			model: mappedModel,
			tools: body.tools,
			rawPayload: body
		};
	}

	async translateResponse(res: Response, isStreaming?: boolean): Promise<Response> {
		return res;
	}
}

/**
 * Factory function returning the appropriate ProtocolAdapter for a given mode string.
 */
export function getProtocolAdapter(mode: string): ProtocolAdapter {
	switch (mode?.toLowerCase()) {
		case 'openai':
			return new OpenAIAdapter();
		case 'claude':
			return new ClaudeAdapter();
		case 'antigravity':
			return new AntigravityAdapter();
		case 'google':
		case 'gemini':
		default:
			return new GeminiAdapter();
	}
}
