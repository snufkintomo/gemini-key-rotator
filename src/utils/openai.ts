import type { ChatCompletionCreateParams } from 'openai/resources/chat/completions';
import { fetchAndEncodeMedia } from './media';
import { getGeminiModelForOpenAI } from './models';
import { parseStream, parseStreamFlush } from './streams';
import { stripMetaSchema } from './schema';

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

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = '';
	const len = bytes.byteLength;
	// Process in chunks of 8000 to avoid stack overflow in String.fromCharCode
	const chunk = 8000;
	for (let i = 0; i < len; i += chunk) {
		const subarr = bytes.subarray(i, i + chunk);
		// Convert to standard array to ensure String.fromCharCode.apply works reliably on all engines
		const normalArr = Array.from(subarr);
		binary += String.fromCharCode.apply(null, normalArr);
	}
	return btoa(binary);
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
					cfg.responseSchema = stripMetaSchema(req.response_format.json_schema.schema);
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
	const { content, tool_calls, tool_call_id, reasoning_content } = message;

	if (reasoning_content) {
		parts.push({ thought: true, text: reasoning_content });
	}

	if (tool_calls && Array.isArray(tool_calls)) {
		for (const tool_call of tool_calls) {
			if (tool_call.type === 'function') {
				const functionCall: any = {
					name: tool_call.function.name,
					args: JSON.parse(tool_call.function.arguments),
				};
				// We do not pass thought_signature to Google Gemini's standard API as it results in a 400 Bad Request
				parts.push({ functionCall });
			}
		}
	}

	if (tool_call_id) {
		let name = message.name || tool_call_id;

		// If tool_call_id contains encoded signature, extract the original name
		if (tool_call_id && tool_call_id.includes('_TSIG_')) {
			const idParts = tool_call_id.split('_TSIG_');
			// If name wasn't provided or was the encoded ID, use the part before TSIG
			if (!message.name || message.name === tool_call_id) {
				name = idParts[0];
			}
		}

		parts.push({
			functionResponse: {
				name: name,
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
			case 'tool':
				roleToUse = 'user';
				break;
			case 'assistant':
				roleToUse = 'model';
				break;
			default:
				throw new HttpError(`Unknown message role: "${item.role}"`, 400);
		}
		// Gemini requires functionResponse parts to be in a user role message.
		if (parts.some((p: any) => p.functionResponse)) {
			roleToUse = 'user';
		}
		contents.push({ role: roleToUse, parts });
	}

	// Merge consecutive same-role messages
	const mergedContents: any[] = [];
	for (const content of contents) {
		if (mergedContents.length > 0 && mergedContents[mergedContents.length - 1].role === content.role) {
			mergedContents[mergedContents.length - 1].parts.push(...content.parts);
		} else {
			mergedContents.push(content);
		}
	}

	// Ensure conversation starts with a user message
	if (mergedContents.length > 0 && mergedContents[0].role === 'model') {
		mergedContents.unshift({
			role: 'user',
			parts: [{ text: '...' }]
		});
	}

	return {
		system_instruction: system_instruction_parts.length > 0 ? { parts: system_instruction_parts } : undefined,
		contents: mergedContents,
	};
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
							parameters: fnRest.parameters ? stripMetaSchema(fnRest.parameters) : undefined,
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
		const message: any = { role: 'assistant', content: [] as string[], reasoning_content: '' as string };
		const tool_calls: any[] = [];
		let currentThoughtSignature: string | undefined;

		for (const part of cand.content?.parts ?? []) {
			// Capture thought signature if available in any part
			if (part.thoughtSignature) currentThoughtSignature = part.thoughtSignature;
			if (part.functionCall?.thought_signature) currentThoughtSignature = part.functionCall.thought_signature;

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

			if (part.functionCall) {
				let callId = `call_${generateId()}`;
				if (currentThoughtSignature) {
					// Encode signature in ID: call_ID_TSIG_signature
					callId += `_TSIG_${currentThoughtSignature}`;
				}
				tool_calls.push({
					id: callId,
					type: 'function',
					function: {
						name: part.functionCall.name,
						arguments: JSON.stringify(part.functionCall.args),
					},
				});
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
		if (tool_calls.length > 0) finalMessage.tool_calls = tool_calls;
		if (!finalMessage.reasoning_content) delete finalMessage.reasoning_content;
		return {
			index: cand.index || 0,
			message: finalMessage,
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
			completion_tokens: (data.usageMetadata.candidatesTokenCount || 0) + (data.usageMetadata.thoughtsTokenCount || 0), 
			prompt_tokens: data.usageMetadata.promptTokenCount, 
			total_tokens: data.usageMetadata.totalTokenCount 
		} 
	};
	return JSON.stringify(obj);
}

export function toOpenAIStream(this: any, line: any, controller: any) {
	const reasonsMap: Record<string, string> = { 
		STOP: 'stop', 
		MAX_TOKENS: 'length', 
		SAFETY: 'content_filter', 
		RECITATION: 'content_filter',
		OTHER: 'stop'
	};
	const { candidates, usageMetadata } = line;
	
	if (usageMetadata) {
		this.shared.usage = { 
			completion_tokens: (usageMetadata.candidatesTokenCount || 0) + (usageMetadata.thoughtsTokenCount || 0), 
			prompt_tokens: usageMetadata.promptTokenCount, 
			total_tokens: usageMetadata.totalTokenCount 
		};
	}

	if (candidates) {
		for (const cand of candidates) {
			const { index, content, finishReason } = cand;
			const parts = content?.parts || [];
			let currentFullText = '';
			let currentFullReasoning = '';
			let toolCalls: any[] = [];

			// Track thought signature in this candidate's parts
			if (!this.shared.thoughtSignatures) this.shared.thoughtSignatures = {};
			let currentThoughtSignature = this.shared.thoughtSignatures[index];

			for (const part of parts) {
				if ((part as any).thoughtSignature) {
					currentThoughtSignature = (part as any).thoughtSignature;
					this.shared.thoughtSignatures[index] = currentThoughtSignature;
				}
				if (part.functionCall?.thought_signature) {
					currentThoughtSignature = part.functionCall.thought_signature;
					this.shared.thoughtSignatures[index] = currentThoughtSignature;
				}

				// Handle thinking/reasoning parts
				let thinkingChunk = '';
				if ((part as any).thought === true || ((part as any).thought && typeof (part as any).thought === 'string')) {
					thinkingChunk = (part as any).thought === true ? (part.text || '') : (part as any).thought;
				} else if ((part as any).thinking && typeof (part as any).thinking === 'string') {
					thinkingChunk = (part as any).thinking;
				} else if ((part as any).reasoning && typeof (part as any).reasoning === 'string') {
					thinkingChunk = (part as any).reasoning;
				}

				if (thinkingChunk) {
					currentFullReasoning += thinkingChunk;
				} else if (part.text) {
					currentFullText += part.text;
				} else if (part.functionCall) {
					let callId = `call_${generateId()}`;
					if (currentThoughtSignature) {
						callId += `_TSIG_${currentThoughtSignature}`;
					}
					toolCalls.push({
						index: toolCalls.length,
						id: callId,
						type: 'function',
						function: {
							name: part.functionCall.name,
							arguments: JSON.stringify(part.functionCall.args || {}),
						},
					});
				}
			}

			// Initialize state for this candidate index if needed
			if (!this.shared.lastText) this.shared.lastText = {};
			if (!this.shared.lastReasoning) this.shared.lastReasoning = {};
			
			const lastText = this.shared.lastText[index] || '';
			const lastReasoning = this.shared.lastReasoning[index] || '';

			// Calculate deltas
			const textDelta = currentFullText.startsWith(lastText) 
				? currentFullText.substring(lastText.length) 
				: currentFullText;
			
			const reasoningDelta = currentFullReasoning.startsWith(lastReasoning)
				? currentFullReasoning.substring(lastReasoning.length)
				: currentFullReasoning;

			// Update state
			this.shared.lastText[index] = currentFullText;
			this.shared.lastReasoning[index] = currentFullReasoning;

			// Only send a chunk if there's new content or a finish reason
			if (textDelta || reasoningDelta || toolCalls.length > 0 || finishReason) {
				const deltaObj: any = {};
				if (textDelta) deltaObj.content = textDelta;
				if (reasoningDelta) deltaObj.reasoning_content = reasoningDelta;
				if (toolCalls.length > 0) deltaObj.tool_calls = toolCalls;

				const obj = { 
					id: this.id, 
					object: 'chat.completion.chunk', 
					created: Math.floor(Date.now() / 1000), 
					model: this.model, 
					choices: [{ 
						index, 
						delta: deltaObj, 
						finish_reason: finishReason ? (reasonsMap[finishReason] || finishReason.toLowerCase()) : null 
					}] 
				};
				controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
			}
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
    handleEmbeddings?: (req: any, apiKey: string, resolvedModel?: string) => Promise<Response>,
    request?: Request,
    storeImage?: (id: string, base64Bytes: string) => Promise<void>
): Promise<Response> {
    const id = 'chatcmpl-' + generateId();

	if (pathname.endsWith('/audio/transcriptions')) {
		if (method !== 'POST') throw new HttpError('Method not allowed', 405);
		if (!request) throw new HttpError('Original request is required for form-data parsing', 400);

		try {
			const formData = await request.clone().formData();
			const file = formData.get('file') as File;
			if (!file) throw new HttpError('Missing "file" parameter in audio transcription request', 400);

			const modelName = 'gemini-1.5-flash'; // High-efficiency model for audio transcriptions

			// Read file to ArrayBuffer and convert to Base64 safely
			const arrayBuffer = await file.arrayBuffer();
			const base64Data = arrayBufferToBase64(arrayBuffer);
			const mimeType = file.type || 'audio/mp3';

			// Construct Gemini payload
			const geminiPayload = {
				contents: [
					{
						parts: [
							{
								inlineData: {
									mimeType: mimeType,
									data: base64Data
								}
							},
							{
								text: 'Transcribe this audio file accurately. Return only the transcription text, nothing else.'
							}
						]
					}
				],
				systemInstruction: {
					parts: [
						{
							text: 'You are an expert audio transcriber. Your task is to transcribe the provided audio accurately. Output ONLY the verbatim transcription of the speech in the audio. Do not include any introductory remarks, descriptions of sounds, explanations, commentary, or markdown formatting.'
						}
					]
				}
			};

			const geminiUrl = new URL(`https://localhost/${API_VERSION}/models/${modelName}:generateContent`);
			const geminiRequest = new Request(geminiUrl.toString(), {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(geminiPayload),
			});

			const response = await handleGemini!(geminiRequest, apiKey);
			if (!response.ok) return response;

			const resJson: any = await response.json();
			const transcriptionText = resJson.candidates?.[0]?.content?.parts?.[0]?.text || '';

			return new Response(JSON.stringify({
				text: transcriptionText.trim()
			}), {
				status: response.status,
				headers: { 'Content-Type': 'application/json' }
			});

		} catch (e: any) {
			throw new HttpError(`Audio transcription failed: ${e.message}`, 500);
		}
	}

	if (pathname.endsWith('/images/generations')) {
		if (method !== 'POST') throw new HttpError('Method not allowed', 405);
		
		const geminiModel = 'imagen-3.0-generate-002'; // Stable Imagen model

		// Map OpenAI size to Gemini's aspectRatio
		let aspectRatio = '1:1';
		const size = reqBody.size || '1024x1024';
		if (size === '1792x1024' || size === '16:9') {
			aspectRatio = '16:9';
		} else if (size === '1024x1792' || size === '9:16') {
			aspectRatio = '9:16';
		} else if (size === '4:3' || size === '1024x768') {
			aspectRatio = '4:3';
		} else if (size === '3:4' || size === '768x1024') {
			aspectRatio = '3:4';
		}

		// Construct Gemini Imagen request payload
		const imagenPayload = {
			prompt: reqBody.prompt,
			numberOfImages: reqBody.n || 1,
			outputMimeType: 'image/jpeg',
			aspectRatio: aspectRatio,
			personGeneration: 'ALLOW_ADULT'
		};

		// For Imagen, we call generateImages
		const geminiUrl = new URL(`https://localhost/${API_VERSION}/models/${geminiModel}:generateImages`);
		const geminiRequest = new Request(geminiUrl.toString(), {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(imagenPayload),
		});

		const response = await handleGemini!(geminiRequest, apiKey);
		if (!response.ok) return response;

		const resJson: any = await response.json();
		
		// Translate back to OpenAI DALL-E format
		const openAIData = (resJson.generatedImages || []).map((imgObj: any) => {
			if (reqBody.response_format === 'b64_json') {
				return {
					b64_json: imgObj.image?.imageBytes || ''
				};
			} else {
				if (storeImage && request && imgObj.image?.imageBytes) {
					const imageId = generateId();
					const requestUrl = new URL(request.url);
					const token = request.headers.get('X-Access-Token') || '';
					
					// Store image asynchronously
					storeImage(imageId, imgObj.image.imageBytes);
					
					return {
						url: `${requestUrl.origin}/api/images/retrieve?id=${imageId}&token=${encodeURIComponent(token)}`
					};
				}
				return {
					url: imgObj.image?.imageBytes ? `data:image/jpeg;base64,${imgObj.image.imageBytes}` : ''
				};
			}
		});

		return new Response(JSON.stringify({
			created: Math.floor(Date.now() / 1000),
			data: openAIData
		}), {
			status: response.status,
			headers: { 'Content-Type': 'application/json' }
		});
	}

	if (pathname.endsWith('/responses')) {
		if (method !== 'POST') throw new HttpError('Method not allowed', 405);
		
		const DEFAULT_MODEL = 'gemini-2.0-flash'; // High-performance model that natively supports audio
		let geminiModel = model || (typeof reqBody.model === 'string' ? getGeminiModelForOpenAI(reqBody.model) : DEFAULT_MODEL);
		
		const contents = await transformOpenAIResponsesInputToGeminiContents(reqBody.input || []);
		
		const harmCategory = ['HARM_CATEGORY_HATE_SPEECH', 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'HARM_CATEGORY_DANGEROUS_CONTENT', 'HARM_CATEGORY_HARASSMENT', 'HARM_CATEGORY_CIVIC_INTEGRITY'];
		const safetySettings = harmCategory.map((category) => ({ category, threshold: 'BLOCK_NONE' }));

		const generationConfig: any = transformConfig(reqBody);

		// If client requested audio modality, instruct Gemini to output WAV audio
		const isAudioRequested = Array.isArray(reqBody.modalities) && reqBody.modalities.includes('audio');
		if (isAudioRequested) {
			generationConfig.responseMimeType = 'audio/wav';
		}

		const body = {
			contents,
			safetySettings,
			generationConfig
		};

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
					start(controller: any) {
						this.shared.keepAliveTimer = setInterval(() => {
							controller.enqueue(': keep-alive\n\n');
						}, 10000);
					},
					transform(chunk: any, controller: any) {
						if (this.shared.keepAliveTimer) {
							clearInterval(this.shared.keepAliveTimer);
							this.shared.keepAliveTimer = null;
						}
						toOpenAIResponsesStream.call(this, chunk, controller);
					},
					flush(controller: any) {
						if (this.shared.keepAliveTimer) {
							clearInterval(this.shared.keepAliveTimer);
						}
						toOpenAIResponsesStreamFlush.call(this, controller);
					},
					model: geminiModel, 
					id, 
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
			return new Response(processResponsesResponse(bodyJson, geminiModel, id), {
				status: response.status,
				headers: { 'Content-Type': 'application/json' }
			});
		}
	}
    
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
                    start(controller: any) {
                        this.shared.keepAliveTimer = setInterval(() => {
                            controller.enqueue(': keep-alive\n\n');
                        }, 10000);
                    },
                    transform(chunk: any, controller: any) {
                        if (this.shared.keepAliveTimer) {
                            clearInterval(this.shared.keepAliveTimer);
                            this.shared.keepAliveTimer = null;
                        }
                        toOpenAIStream.call(this, chunk, controller);
					},
                    flush(controller: any) {
                        if (this.shared.keepAliveTimer) {
                            clearInterval(this.shared.keepAliveTimer);
                        }
                        toOpenAIStreamFlush.call(this, controller);
                    },
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

export async function transformOpenAIResponsesInputToGeminiContents(input: any[]) {
	const contents: any[] = [];
	for (const item of input) {
		if (item.type !== 'message') continue;
		
		const parts: any[] = [];
		const roleToUse = item.role === 'assistant' ? 'model' : 'user';

		if (Array.isArray(item.content)) {
			for (const part of item.content) {
				if (part.type === 'text') {
					parts.push({ text: part.text });
				} else if (part.type === 'input_audio' && part.input_audio?.data) {
					const format = part.input_audio.format || 'mp3';
					parts.push({
						inlineData: {
							mimeType: format === 'mp3' ? 'audio/mpeg' : `audio/${format}`,
							data: part.input_audio.data,
						},
					});
				} else if (part.type === 'image' && part.image?.data) {
					parts.push({
						inlineData: {
							mimeType: part.image.mimeType || 'image/jpeg',
							data: part.image.data,
						},
					});
				}
			}
		} else if (typeof item.content === 'string') {
			parts.push({ text: item.content });
		}

		if (parts.length > 0) {
			contents.push({ role: roleToUse, parts });
		}
	}

	// Merge consecutive same-role messages
	const mergedContents: any[] = [];
	for (const content of contents) {
		if (mergedContents.length > 0 && mergedContents[mergedContents.length - 1].role === content.role) {
			mergedContents[mergedContents.length - 1].parts.push(...content.parts);
		} else {
			mergedContents.push(content);
		}
	}

	// Ensure conversation starts with user role
	if (mergedContents.length > 0 && mergedContents[0].role === 'model') {
		mergedContents.unshift({
			role: 'user',
			parts: [{ text: '...' }]
		});
	}

	return mergedContents;
}

export function processResponsesResponse(data: any, model: string, id: string): string {
	const candidate = data.candidates?.[0];
	const parts = candidate?.content?.parts || [];
	const contentItems: any[] = [];

	let textContent = '';
	let audioData = '';

	for (const part of parts) {
		if (part.text) {
			textContent += part.text;
		}
		if (part.inlineData && part.inlineData.mimeType?.startsWith('audio/')) {
			audioData = part.inlineData.data;
		}
	}

	if (textContent) {
		contentItems.push({
			type: 'text',
			text: textContent
		});
	}

	if (audioData) {
		contentItems.push({
			type: 'audio',
			audio: {
				id: 'aud_' + generateId(),
				data: audioData,
				expires_at: Math.floor(Date.now() / 1000) + 3600,
				transcript: textContent
			}
		});
	}

	const obj = {
		id: 'resp_' + generateId(),
		object: 'response',
		model: model,
		status: 'completed',
		output: [
			{
				id: 'msg_' + generateId(),
				object: 'response.message',
				role: 'assistant',
				content: contentItems
			}
		],
		usage: data.usageMetadata && {
			total_tokens: data.usageMetadata.totalTokenCount,
			input_tokens: data.usageMetadata.promptTokenCount,
			output_tokens: (data.usageMetadata.candidatesTokenCount || 0) + (data.usageMetadata.thoughtsTokenCount || 0)
		}
	};

	return JSON.stringify(obj);
}

export function toOpenAIResponsesStream(this: any, line: any, controller: any) {
	const { candidates, usageMetadata } = line;
	const respId = 'resp_' + this.id;
	const msgId = 'msg_' + this.id;

	if (usageMetadata) {
		this.shared.usage = { 
			total_tokens: usageMetadata.totalTokenCount,
			input_tokens: usageMetadata.promptTokenCount,
			output_tokens: (usageMetadata.candidatesTokenCount || 0) + (usageMetadata.thoughtsTokenCount || 0)
		};
	}

	// First time initialization
	if (!this.shared.initialized) {
		// 1. response.created
		controller.enqueue(`event: response.created\ndata: ${JSON.stringify({
			response: { id: respId, object: 'response', status: 'in_progress', model: this.model }
		})}\n\n`);

		// 2. response.output_item.added
		controller.enqueue(`event: response.output_item.added\ndata: ${JSON.stringify({
			response_id: respId,
			output_item: { id: msgId, object: 'response.message', role: 'assistant', content: [] }
		})}\n\n`);

		// 3. response.content_part.added
		controller.enqueue(`event: response.content_part.added\ndata: ${JSON.stringify({
			response_id: respId,
			output_item_id: msgId,
			content_part: { type: 'text', text: '' }
		})}\n\n`);

		this.shared.initialized = true;
	}

	if (candidates && candidates.length > 0) {
		const parts = candidates[0].content?.parts || [];
		let currentFullText = '';

		for (const part of parts) {
			if (part.text) {
				currentFullText += part.text;
			}
		}

		if (!this.shared.lastText) this.shared.lastText = '';
		const lastText = this.shared.lastText;

		const textDelta = currentFullText.startsWith(lastText) 
			? currentFullText.substring(lastText.length) 
			: currentFullText;

		this.shared.lastText = currentFullText;

		if (textDelta) {
			// 4. response.content_part.delta
			controller.enqueue(`event: response.content_part.delta\ndata: ${JSON.stringify({
				response_id: respId,
				output_item_id: msgId,
				content_part_index: 0,
				delta: { text: textDelta }
			})}\n\n`);
		}
	}
}

export function toOpenAIResponsesStreamFlush(this: any, controller: any) {
	const respId = 'resp_' + this.id;
	const msgId = 'msg_' + this.id;
	const finalText = this.shared.lastText || '';

	// 5. response.content_part.done
	controller.enqueue(`event: response.content_part.done\ndata: ${JSON.stringify({
		response_id: respId,
		output_item_id: msgId,
		content_part_index: 0,
		content_part: { type: 'text', text: finalText }
	})}\n\n`);

	// 6. response.output_item.done
	controller.enqueue(`event: response.output_item.done\ndata: ${JSON.stringify({
		response_id: respId,
		output_item: {
			id: msgId,
			object: 'response.message',
			status: 'completed',
			role: 'assistant',
			content: [
				{ type: 'text', text: finalText }
			]
		}
	})}\n\n`);

	// 7. response.done
	controller.enqueue(`event: response.done\ndata: ${JSON.stringify({
		response: {
			id: respId,
			object: 'response',
			status: 'completed',
			model: this.model,
			usage: this.shared.usage || { total_tokens: 0, input_tokens: 0, output_tokens: 0 }
		}
	})}\n\n`);
}
