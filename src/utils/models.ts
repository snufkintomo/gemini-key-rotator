// Function to map Gemini models to latest versions
export function getGeminiModelForGemini(geminiModel: string): string {
	// Explicitly map old Gemini models to latest versions
	//if (geminiModel === 'gemini-2.5-pro') {
	//	return 'gemini-pro-latest';
	//} else if (geminiModel === 'gemini-2.5-flash') {
	//	return 'gemini-flash-latest';
	//} else if (geminiModel === 'gemini-2.5-flash-lite') {
	//	return 'gemini-flash-lite-latest';
	//}
	// If the model is not an old 2.5 version, use it directly
	if (geminiModel === 'gemini-translate') {
		return 'gemini-3.1-flash-lite-preview';
	}
	return geminiModel;
}

// Function to map Claude models to Gemini models
export function getGeminiModelForClaude(claudeModel: string): string {
	// If the model is already a Gemini model (and not an old 2.5 version), use it directly
	if (claudeModel.startsWith('gemini-') || claudeModel.startsWith('gemma-') || claudeModel.startsWith('learnlm-')) {
		return getGeminiModelForGemini(claudeModel);
	}
	if (claudeModel.includes('opus')) {
		return 'gemini-pro-latest';
	}
	if (claudeModel.includes('sonnet')) {
		return 'gemini-flash-latest';
	}
	if (claudeModel.includes('haiku')) {
		return 'gemini-flash-lite-latest';
	}
	// Default to a general-purpose Gemini model if no specific mapping is found
	return 'gemini-flash-latest';
}

// Function to map OpenAI models to Gemini models
export function getGeminiModelForOpenAI(openAIModel: string): string {
	// If the model is already a Gemini model (and not an old 2.5 version), use it directly
	if (openAIModel.startsWith('gemini-') || openAIModel.startsWith('gemma-') || openAIModel.startsWith('learnlm-')) {
		return getGeminiModelForGemini(openAIModel);
	}

	// Image Generation
	if (openAIModel.includes('dall-e')) {
		return 'imagen-4.0-generate-001';
	}

	if (openAIModel.includes('-mini')) {
		return 'gemini-flash-latest';
	}
	if (openAIModel.includes('-nano')) {
		return 'gemini-flash-lite-latest';
	}
	if (openAIModel.includes('-pro')) {
		return 'gemini-pro-latest';
	}

	// Map specific OpenAI models to Gemini equivalents
	switch (openAIModel.toLowerCase()) {
		case 'o3':
		case 'o3-mini':
		case 'gpt-5':
			return 'gemini-pro-latest';
		case 'gpt-4':
		case 'gpt-4o':
			return 'gemini-flash-latest';
		case 'o1':
		case 'o1-mini':
		case 'o1-preview':
			return 'gemini-flash-latest';
		case 'gpt-4o-mini':
		case 'gpt-3.5-turbo':
			return 'gemini-flash-lite-latest';
		default:
			// For unknown models, try to extract a valid Gemini model name if embedded
			if (openAIModel.includes('gemini-')) {
				const geminiMatch = openAIModel.match(/gemini-[a-z0-9.-]+/);
				if (geminiMatch) return geminiMatch[0];
			}
			// Default fallback for unknown OpenAI models
			return 'gemini-flash-latest';
	}
}

export function resolveModelAndAuthMode(rawModel: string | undefined, authMode: string | null, accessToken: string): { model: string | undefined, useOAuth: boolean } {
	let model = rawModel;
	let oauthExplicitlyRequested = false;

	if (model && model.endsWith('-oauth')) {
		model = model.substring(0, model.length - 6);
		oauthExplicitlyRequested = true;
	}

	// Protocol transformation if needed
	let resolvedModel = model;
	if (model) {
		if (authMode === 'openai') {
			resolvedModel = getGeminiModelForOpenAI(model);
		} else if (authMode === 'claude') {
			resolvedModel = getGeminiModelForClaude(model);
		} else {
			resolvedModel = getGeminiModelForGemini(model);
		}
	}

	// Determine OAuth
	let useOAuth = oauthExplicitlyRequested;
	if (!useOAuth) {
		if (accessToken.includes(':')) {
			useOAuth = true;
		} else if (authMode === "google" && accessToken.length > 100) {
			useOAuth = true;
		} else if (resolvedModel && resolvedModel.includes("-pro")) {
			useOAuth = true;
		}
	}

	return { model: resolvedModel, useOAuth };
}

// Function to map Gemini models to supported internal model names for CLI/Internal APIs
export function mapModelForInternalApi(model: string): string {
	const MODEL_FALLBACKS: Record<string, string> = {
		'gemini-2.5-flash-image': 'gemini-2.5-flash',
		'gemini-pro-latest': 'gemini-3.1-pro-preview',
		'gemini-flash-latest': 'gemini-3-flash-preview',
		'gemini-flash-lite-latest': 'gemini-3.1-flash-lite-preview',
	};
	return MODEL_FALLBACKS[model] || model;
}

import { getGeminiModelFromPath } from './gemini';

export async function parseRequestModel(request: Request): Promise<string | undefined> {
	const requestUrl = new URL(request.url);
	let model: string | undefined;

	if (
		request.method === 'POST' &&
		(requestUrl.pathname.endsWith('/chat/completions') || requestUrl.pathname.endsWith('/messages'))
	) {
		try {
			const body: any = await request.json();
			if (typeof body.model === 'string') {
				model = body.model;
			}
		} catch (e) {
			console.error('Could not parse request body to get model:', e);
		}
	} else {
		model = getGeminiModelFromPath(requestUrl.pathname);
	}
	return model;
}

import type { GeminiModel } from '../types';

const API_VERSION = 'v1beta';

export async function handleModels(
	apiKey: string,
	modelId: string | undefined,
	authMode: string = 'openai',
	handleGemini: (request: Request, apiKey: string, model?: string) => Promise<Response>,
	model?: string
) {
	const path = modelId ? `${API_VERSION}/models/${modelId}` : `${API_VERSION}/models`;

	const geminiUrl = new URL(`https://localhost/${path}`);
	const geminiRequest = new Request(geminiUrl.toString(), {
		method: 'GET',
	});

	const response = await handleGemini(geminiRequest, apiKey, model);
	if (authMode === 'google' || !response.ok) return response;
	let responseBody: BodyInit | null = response.body;
	if (response.ok) {
		const originalBody = (await response.json()) as any;
		if (modelId) {
			const mod = originalBody as GeminiModel;
			switch (authMode) {
				case 'openai':
					responseBody = JSON.stringify({
						id: mod.name.replace('models/', ''),
						object: 'model',
						created: 0,
						owned_by: 'google',
					});
					break;
				case 'claude':
					responseBody = JSON.stringify({
						id: mod.name.replace('models/', ''),
						type: 'model',
						description: mod.description,
						name: mod.name,
						display_name: mod.name,
					});
					break;
				default:
					responseBody = JSON.stringify(mod);
			}
		} else {
			const { models } = originalBody;
			switch (authMode) {
				case 'openai':
					responseBody = JSON.stringify({
						object: 'list',
						data: models.map((m: any) => ({
							id: m.name.replace('models/', ''),
							object: 'model',
							created: 0,
							owned_by: 'google',
						})),
					});
					break;
				case 'claude':
					responseBody = JSON.stringify({
						data: models.map((m: any) => ({
							id: m.name.replace('models/', ''),
							type: 'model',
							description: m.description,
							name: m.name,
							display_name: m.name,
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
