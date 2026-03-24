import type { ChatCompletionCreateParams } from 'openai/resources/chat/completions';
import { fetchAndEncodeMedia } from './media';
import { getGeminiModelForOpenAI } from './models';
import { parseStream, parseStreamFlush } from './streams';

const API_VERSION = 'v1beta';

class HttpError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = this.constructor.name;
		this.status = status;
	}
}

export function generateId(): string {
	const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	const randomChar = () => characters[Math.floor(Math.random() * characters.length)];
	return Array.from({ length: 29 }, randomChar).join('');
}

export function transformConfig(req: any) {
	const fieldsMap: Record<string, string> = {
		frequency_penalty: 'frequencyPenalty',
		max_completion_tokens: 'maxOutputTokens',
		max_tokens: 'maxOutputTokens',
		n: 'candidateCount',
		presence_penalty: 'presencePenalty',
		seed: 'seed',
		stop: 'stopSequences',
		stop_sequences: 'stopSequences',
		temperature: 'temperature',
		top_k: 'topK',
		top_p: 'topP',
	};
	let cfg: any = {};
	for (let key in req) {
		const matchedKey = fieldsMap[key];
		if (matchedKey) {
			if (key === 'temperature' && req[key] === 0) cfg[matchedKey] = 0.6;
			else cfg[matchedKey] = req[key];
		}
	}
	if (req.response_format) {
		switch (req.response_format.type) {
			case 'json_schema':
				if (req.response_format.json_schema?.schema) {
					const { additionalProperties, $schema, ...rest } = req.response_format.json_schema.schema;
					cfg.responseSchema = rest;
				}
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

	// Handle thinking/reasoning config
	const thinking = req.thinking || req.thinking_config;
	if (req.reasoning_effort || thinking) {
		const budgets: Record<string, number> = { low: 1024, medium: 8192, high: 32768 };
		const budget = budgets[req.reasoning_effort] || thinking?.budget_tokens || thinking?.budget || 8192;
		cfg.thinkingConfig = {
			thinkingBudget: budget,
			includeThoughts: true,
		};
	}
	return cfg;
}

export async function transformOpenAIMsgToGeminiParts(message: any) {
	const parts = [];
	const { content, tool_calls, tool_call_id } = message;

	if (tool_calls && Array.isArray(tool_calls)) {
		for (const tool_call of tool_calls) {
			if (tool_call.type === 'function') {
				parts.push({
					functionCall: {
						name: tool_call.function.name,
						args: JSON.parse(tool_call.function.arguments),
					},
				});
			}
		}
	}

	if (tool_call_id) {
		parts.push({
			functionResponse: {
				name: message.name || tool_call_id,
				response: { content: content },
			},
		});
	}

	if (!content) return parts;

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
					parts.push(await fetchAndEncodeMedia(item.image_url.url, 'Image'));
					break;
				case 'input_audio':
					if (item.input_audio.data) {
						parts.push({
							inlineData: {
								mimeType: item.input_audio.format === 'mp3' ? 'audio/mpeg' : `audio/${item.input_audio.format}`,
								data: item.input_audio.data,
							},
						});
					}
					break;
				default:
					console.warn(`Unknown OpenAI content item type: "${item.type}"`);
			}
		}
	return parts;
}

export async function transformOpenAIMessagesToGeminiContents(messages: ChatCompletionCreateParams['messages']) {
	if (!messages) return {};
	const contents: any[] = [];
	let system_instruction_parts: any[] = [];
	for (const item of messages) {
		let roleToUse: string;
		const parts = await transformOpenAIMsgToGeminiParts(item);
		if (parts.length === 0) continue;

		if (item.role === 'system' || item.role === 'developer') {
			// Gemini system instructions only support text parts
			const textParts = parts.filter((p: any) => p.text);
			system_instruction_parts.push(...textParts);
			continue;
		}

		switch (item.role) {
			case 'user':
				roleToUse = 'user';
				break;
			case 'assistant':
			case 'tool':
				roleToUse = 'model';
				break;
			default:
				throw new HttpError(`Unknown message role: "${item.role}"`, 400);
		}
		contents.push({ role: roleToUse, parts });
	}
	return {
		system_instruction: system_instruction_parts.length > 0 ? { parts: system_instruction_parts } : undefined,
		contents,
	};
}

function cleanSchema(schema: any): any {
	if (!schema || typeof schema !== 'object') return schema;
	const { $schema, additionalProperties, ...rest } = schema;
	const newSchema: any = rest;
	if (newSchema.properties) {
		for (const key in newSchema.properties) {
			newSchema.properties[key] = cleanSchema(newSchema.properties[key]);
		}
	}
	if (newSchema.items) {
		newSchema.items = cleanSchema(newSchema.items);
	}
	return newSchema;
}

export function transformTools(req: any) {
	let tools, tool_config;
	if (req.tools) {
		const funcs = req.tools.filter((tool: any) => tool.type === 'function' && tool.function?.name !== 'googleSearch');
		if (funcs.length > 0) {
			tools = [
				{
					function_declarations: funcs.map((tool: any) => {
						const { strict, ...fnRest } = tool.function;
						return {
							...fnRest,
							parameters: fnRest.parameters ? cleanSchema(fnRest.parameters) : undefined,
						};
					}),
				},
			];
		}
	}
	if (req.tool_choice) {
		if (req.tool_choice === 'none') {
			tool_config = { function_calling_config: { mode: 'NONE' } };
		} else if (typeof req.tool_choice === 'object' && req.tool_choice.type === 'function') {
			tool_config = { function_calling_config: { mode: 'ANY', allowed_function_names: [req.tool_choice.function.name] } };
		}
	}
	return { tools, tool_config };
}

export async function transformOpenAIToGeminiRequest(req: any) {
	const harmCategory = ['HARM_CATEGORY_HATE_SPEECH', 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'HARM_CATEGORY_DANGEROUS_CONTENT', 'HARM_CATEGORY_HARASSMENT', 'HARM_CATEGORY_CIVIC_INTEGRITY'];
	const safetySettings = harmCategory.map((category) => ({ category, threshold: 'BLOCK_NONE' }));
	return { ...(await transformOpenAIMessagesToGeminiContents(req.messages)), safetySettings, generationConfig: transformConfig(req), ...transformTools(req) };
}

export function processCompletionsResponse(data: any, model: string, id: string) {
	const reasonsMap: Record<string, string> = { STOP: 'stop', MAX_TOKENS: 'length', SAFETY: 'content_filter', RECITATION: 'content_filter' };
	const transformCandidatesMessage = (cand: any) => {
		const message = { role: 'assistant', content: [] as string[], reasoning_content: '' as string };
		for (const part of cand.content?.parts ?? []) {
			if (part.text) {
				if (
					(part as any).thought === true ||
					((part as any).thought && typeof (part as any).thought === 'string')
				) {
					const thoughtContent =
						(part as any).thought === true ? part.text : (part as any).thought;
					message.reasoning_content += thoughtContent || part.text;
				} else {
					message.content.push(part.text);
				}
			}

			// Capture all variations of thinking/reasoning parts
			if ((part as any).thought && typeof (part as any).thought === 'string') {
				message.reasoning_content += (part as any).thought;
			} else if ((part as any).thinking && typeof (part as any).thinking === 'string') {
				message.reasoning_content += (part as any).thinking;
			} else if ((part as any).reasoning && typeof (part as any).reasoning === 'string') {
				message.reasoning_content += (part as any).reasoning;
			} else if ((part as any).toolCode && typeof (part as any).toolCode === 'string') {
				message.reasoning_content += (part as any).toolCode;
			}
		}
		const finalMessage: any = {
			...message,
			content:
				message.content.length > 0
					? message.content.join('')
					: message.reasoning_content
					? null
					: '',
		};
		if (!finalMessage.reasoning_content) delete finalMessage.reasoning_content;
		return {
			index: cand.index || 0,
			message: finalMessage,
			logprobs: null,
			finish_reason: reasonsMap[cand.finishReason] || cand.finishReason,
		};
	};
	const obj = { id, choices: data.candidates.map(transformCandidatesMessage), created: Math.floor(Date.now() / 1000), model: data.modelVersion ?? model, object: 'chat.completion', usage: data.usageMetadata && { completion_tokens: data.usageMetadata.candidatesTokenCount, prompt_tokens: data.usageMetadata.promptTokenCount, total_tokens: data.usageMetadata.totalTokenCount } };
	return JSON.stringify(obj);
}

export function toOpenAIStream(this: any, line: any, controller: any) {
	const reasonsMap: Record<string, string> = { STOP: 'stop', MAX_TOKENS: 'length', SAFETY: 'content_filter', RECITATION: 'content_filter' };
	const { candidates, usageMetadata } = line;
	if (usageMetadata) this.shared.usage = { completion_tokens: usageMetadata.candidatesTokenCount, prompt_tokens: usageMetadata.promptTokenCount, total_tokens: usageMetadata.totalTokenCount };
	if (candidates) {
		for (const cand of candidates) {
			const { index, content, finishReason } = cand;
			const { parts } = content;
			let allContent = '';
			let accumulatedReasoning = '';
			for (const part of parts) {
				if (part.text) {
					if (
						(part as any).thought === true ||
						((part as any).thought && typeof (part as any).thought === 'string')
					) {
						const thoughtContent =
							(part as any).thought === true ? part.text : (part as any).thought;
						accumulatedReasoning += thoughtContent || part.text;
					} else {
						allContent += part.text;
					}
				}

				// Capture all variations of thinking/reasoning parts in stream
				if ((part as any).thought && typeof (part as any).thought === 'string') {
					accumulatedReasoning += (part as any).thought;
				} else if ((part as any).thinking && typeof (part as any).thinking === 'string') {
					accumulatedReasoning += (part as any).thinking;
				} else if ((part as any).reasoning && typeof (part as any).reasoning === 'string') {
					accumulatedReasoning += (part as any).reasoning;
				} else if ((part as any).toolCode && typeof (part as any).toolCode === 'string') {
					accumulatedReasoning += (part as any).toolCode;
				}
			}
			if (this.last[index] === undefined) this.last[index] = '';
			const lastText = this.last[index] || '';
			let delta = allContent.startsWith(lastText) ? allContent.substring(lastText.length) : allContent;
			this.last[index] = allContent;
			const deltaObj: any = { content: delta };
			if (accumulatedReasoning) deltaObj.reasoning_content = accumulatedReasoning;
			const obj = { id: this.id, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000), model: this.model, choices: [{ index, delta: deltaObj, finish_reason: reasonsMap[finishReason] || finishReason }] };
			controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
		}
	}
}

export function toOpenAIStreamFlush(this: any, controller: any) {
	if (this.streamIncludeUsage && this.shared.usage) {
		const obj = { id: this.id, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000), model: this.model, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }], usage: this.shared.usage };
		controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
	}
	controller.enqueue('data: [DONE]\n\n');
}

export async function handleOpenAI(
    reqBody: any, 
    pathname: string, 
    method: string, 
    apiKey: string, 
    model?: string,
    handleGemini?: (request: Request, apiKey: string, model?: string) => Promise<Response>,
    handleModels?: (apiKey: string, modelId: string | undefined, authMode: string, model?: string) => Promise<Response>,
    handleEmbeddings?: (req: any, apiKey: string, resolvedModel?: string) => Promise<Response>
): Promise<Response> {
    const id = 'chatcmpl-' + generateId();
    
    if (pathname.endsWith('/chat/completions')) {
        if (method !== 'POST') throw new HttpError('Method not allowed', 405);
        
        const DEFAULT_MODEL = 'gemini-flash-latest';
        let geminiModel = model || (typeof reqBody.model === 'string' ? getGeminiModelForOpenAI(reqBody.model) : DEFAULT_MODEL);
        
        if (reqBody.input && !reqBody.messages) reqBody.messages = [{ role: 'user', content: reqBody.input }];
        
        let body: any = await transformOpenAIToGeminiRequest(reqBody);
        const extra = reqBody.extra_body?.google;
        if (extra) {
            if (extra.safety_settings) body.safetySettings = extra.safety_settings;
            if (extra.cached_content) body.cachedContent = extra.cached_content;
            if (extra.thinking_config) body.generationConfig.thinkingConfig = extra.thinking_config;
        }
        if (reqBody.model.includes('search') || reqBody.tools?.some((tool: any) => tool.function?.name === 'googleSearch')) {
            body.tools = body.tools || [];
            if (!body.tools.some((t:any) => t.googleSearch)) (body.tools as any[]).push({ googleSearch: {} });
            if (body.tools.some((t:any) => t.function_declarations)) {
                body.tools.forEach((t:any) => {
                    if (t.function_declarations) t.function_declarations = t.function_declarations.filter((f:any) => f.name !== 'googleSearch');
                });
            }
        }
        
        const TASK = reqBody.stream ? 'streamGenerateContent' : 'generateContent';
        const geminiUrl = new URL(`https://localhost/${API_VERSION}/models/${geminiModel}:${TASK}`);
        const geminiRequest = new Request(geminiUrl.toString(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });

        const response = await handleGemini!(geminiRequest, apiKey);
        if (!response.ok) return response;

        if (reqBody.stream) {
            const stream = response.body!
                .pipeThrough(new TextDecoderStream())
                .pipeThrough(new TransformStream({ transform: parseStream, flush: parseStreamFlush, buffer: '', shared: {} } as any))
                .pipeThrough(new TransformStream({ 
                    transform: toOpenAIStream, 
                    flush: toOpenAIStreamFlush, 
                    streamIncludeUsage: reqBody.stream_options?.include_usage, 
                    model: geminiModel, 
                    id, 
                    last: [], 
                    shared: {} 
                } as any))
                .pipeThrough(new TextEncoderStream());
                
            return new Response(stream, {
                headers: {
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                }
            });
        } else {
            const bodyText = await response.text();
            const bodyJson = JSON.parse(bodyText);
            return new Response(processCompletionsResponse(bodyJson, geminiModel, id), {
                status: response.status,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    
    if (pathname.endsWith('/embeddings')) {
        if (method !== 'POST') throw new HttpError('Method not allowed', 405);
        return handleEmbeddings!(reqBody, apiKey, model);
    }
    
    const modelsMatch = pathname.match(/models\/([^/]+)$/);
    const isModelsList = pathname.endsWith('/models') || pathname.endsWith('/oauth/models');
    if (modelsMatch || isModelsList) {
        if (method !== 'GET') throw new HttpError('Method not allowed', 405);
        const modelId = modelsMatch ? modelsMatch[1] : undefined;
        return handleModels!(apiKey, modelId, "openai", model);
    }
    
	throw new HttpError('Not Found', 404);
}

export async function handleEmbeddings(
	req: any,
	apiKey: string,
	handleGemini: (request: Request, apiKey: string, model?: string) => Promise<Response>,
	resolvedModel?: string
) {
	const DEFAULT_EMBEDDINGS_MODEL = 'gemini-embedding-001';
	let modelName =
		resolvedModel ||
		(typeof req.model === 'string' ? getGeminiModelForOpenAI(req.model) : DEFAULT_EMBEDDINGS_MODEL);
	if (
		!modelName.startsWith('text-embedding-') &&
		!modelName.startsWith('embedding-') &&
		!modelName.startsWith('gemini-embedding-')
	) {
		modelName = DEFAULT_EMBEDDINGS_MODEL;
	}
	if (modelName.startsWith('models/')) modelName = modelName.substring(7);
	const model = `models/${modelName}`;
	if (!Array.isArray(req.input)) req.input = [req.input];

	const geminiUrl = new URL(`https://localhost/${API_VERSION}/${model}:batchEmbedContents`);
	const geminiRequest = new Request(geminiUrl.toString(), {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			requests: req.input.map((text: string) => ({
				model,
				content: { parts: [{ text }] },
				outputDimensionality: req.dimensions,
			})),
		}),
	});

	const response = await handleGemini(geminiRequest, apiKey, resolvedModel);
	if (!response.ok) return response;

	let responseBody: BodyInit | null = response.body;
	if (response.ok) {
		const { embeddings } = JSON.parse(await response.text());
		responseBody = JSON.stringify({
			object: 'list',
			data: embeddings.map(({ values }: any, index: number) => ({
				object: 'embedding',
				index,
				embedding: values,
			})),
			model: modelName,
		});
	}
	return new Response(responseBody, response);
}
