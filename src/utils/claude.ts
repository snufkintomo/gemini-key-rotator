import { getGeminiModelForClaude } from './models';
import { parseStream, parseStreamFlush } from './streams';
import { generateId } from './openai';
import type { ClaudeCompletionRequest, GeminiResponse, ClaudeMessage, ClaudeTool, ClaudeMessagePart } from '../types';

const API_VERSION = 'v1beta';

class HttpError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = this.constructor.name;
		this.status = status;
	}
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

export async function transformClaudeMessagesToGeminiContents(messages: ClaudeMessage[]): Promise<{ contents: any[]; system_instruction?: any }> {
	const contents: any[] = [];
	let system_instruction: any;
	for (const item of messages) {
		if (item.role === 'user' || item.role === 'assistant') {
			const parts: any[] = [];
			if (typeof item.content === 'string') {
				parts.push({ text: item.content });
			} else if (Array.isArray(item.content)) {
				for (const part of item.content) {
					switch (part.type) {
						case 'text':
							if (part.text) parts.push({ text: part.text });
							break;
						case 'image':
							if (part.source?.type === 'base64') {
								parts.push({
									inlineData: {
										mimeType: part.source.media_type,
										data: part.source.data,
									},
								});
							}
							break;
						case 'audio':
						case 'document':
							if (part.source?.type === 'base64') {
								parts.push({
									inlineData: {
										mimeType: part.source.media_type,
										data: part.source.data,
									},
								});
							}
							break;
						case 'tool_use':
							parts.push({
								functionCall: {
									name: part.name || part.input?.name,
									args: part.input,
								},
							});
							break;
						case 'tool_result':
							parts.push({
								functionResponse: {
									name: part.tool_use_id,
									response: { content: part.content },
								},
							});
							break;
					}
				}
			}
			contents.push({ role: item.role === 'assistant' ? 'model' : 'user', parts: parts });
		} else if (item.role === 'system') {
			if (typeof item.content === 'string') {
				system_instruction = { parts: [{ text: item.content }] };
			} else if (Array.isArray(item.content)) {
				const textParts = (item.content as any[])
					.filter((p) => p.type === 'text')
					.map((p) => ({ text: p.text || '' }));
				if (textParts.length > 0) {
					system_instruction = { parts: textParts };
				}
			}
		}
	}
	return { contents, system_instruction };
}

export function transformClaudeToolsToGeminiTools(claudeTools?: ClaudeTool[], claudeToolChoice?: ClaudeCompletionRequest['tool_choice']): { tools?: any[]; tool_config?: any } {
	const geminiTools: any[] = [];
	if (claudeTools && claudeTools.length > 0) {
		geminiTools.push({
			function_declarations: claudeTools.map((tool) => {
				const parameters = JSON.parse(JSON.stringify(tool.input_schema));
				if (parameters.type !== 'object') {
					console.warn(`Tool ${tool.name} has non-object parameters, wrapping it.`);
					return {
						name: tool.name,
						description: tool.description,
						parameters: {
							type: 'object',
							properties: {
								input: parameters
							}
						}
					};
				}
				return {
					name: tool.name,
					description: tool.description,
					parameters: cleanSchema(parameters)
				};
			})
		});
	}
	let tool_config: any;
	if (claudeToolChoice) {
		if (claudeToolChoice.type === 'auto') {
			tool_config = { function_calling_config: { mode: 'AUTO' } };
		} else if ((claudeToolChoice as any).type === 'any') {
			tool_config = { function_calling_config: { mode: 'ANY' } };
		} else if (claudeToolChoice.type === 'tool' && claudeToolChoice.tool?.name) {
			tool_config = {
				function_calling_config: {
					mode: 'ANY',
					allowed_function_names: [claudeToolChoice.tool.name]
				}
			};
		} else if (claudeToolChoice.type === 'none') {
			tool_config = { function_calling_config: { mode: 'NONE' } };
		}
	}
	return { tools: geminiTools.length > 0 ? geminiTools : undefined, tool_config };
}

export async function transformClaudeToGeminiRequest(claudeReq: ClaudeCompletionRequest): Promise<any> {
	let { contents, system_instruction } = await transformClaudeMessagesToGeminiContents(claudeReq.messages);
	if (claudeReq.system && !system_instruction) {
		if (typeof claudeReq.system === 'string') {
			system_instruction = { parts: [{ text: claudeReq.system }] };
		} else if (Array.isArray(claudeReq.system)) {
			const textParts = (claudeReq.system as any[])
				.filter((p) => p.type === 'text')
				.map((p) => ({ text: p.text || '' }));
			if (textParts.length > 0) {
				system_instruction = { parts: textParts };
			}
		}
	}
	const { tools, tool_config } = transformClaudeToolsToGeminiTools(claudeReq.tools, claudeReq.tool_choice);
	let generationConfig: any = {};
	if (claudeReq.max_tokens) generationConfig.maxOutputTokens = claudeReq.max_tokens;
	if (claudeReq.temperature !== undefined && claudeReq.temperature !== null) generationConfig.temperature = claudeReq.temperature === 0 ? 0.6 : claudeReq.temperature;
	if (claudeReq.top_p) generationConfig.topP = claudeReq.top_p;
	if (claudeReq.top_k) generationConfig.topK = claudeReq.top_k;
	if (claudeReq.stop_sequences && claudeReq.stop_sequences.length > 0) generationConfig.stopSequences = claudeReq.stop_sequences;
	if (claudeReq.thinking && claudeReq.thinking.type === 'enabled') generationConfig.thinkingConfig = { thinkingBudget: claudeReq.thinking.budget_tokens || 1024, includeThoughts: true };
	const harmCategory = ['HARM_CATEGORY_HATE_SPEECH', 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'HARM_CATEGORY_DANGEROUS_CONTENT', 'HARM_CATEGORY_HARASSMENT', 'HARM_CATEGORY_CIVIC_INTEGRITY'];
	let safetySettings = harmCategory.map((category) => ({ category, threshold: 'BLOCK_NONE' }));
	return { contents, system_instruction, generationConfig: Object.keys(generationConfig).length > 0 ? generationConfig : undefined, safetySettings, tools, tool_config };
}

export function transformGeminiToClaudeResponse(geminiRes: GeminiResponse, model: string, id: string, thinking?: string): Response {
	const claudeContent: ClaudeMessagePart[] = [];
	let stopReason: string | null = null;
	let accumulatedThinking = thinking || '';
	let signature = '';
	if (geminiRes.candidates && geminiRes.candidates.length > 0) {
		const candidate = geminiRes.candidates[0];
		if (candidate.content?.parts) {
			for (const part of candidate.content.parts) {
				if (part.text) {
					if ((part as any).thought === true || ((part as any).thought && typeof (part as any).thought === 'string')) {
						const thoughtContent = (part as any).thought === true ? part.text : (part as any).thought;
						accumulatedThinking += thoughtContent || part.text;
						if ((part as any).thoughtSignature) signature = (part as any).thoughtSignature;
					} else claudeContent.push({ type: 'text', text: part.text });
				} else if (part.functionCall) {
					claudeContent.push({
						type: 'tool_use',
						id: `toolu_${generateId()}`,
						name: part.functionCall.name,
						input: part.functionCall.args,
					});
					stopReason = 'tool_use';
				}

				// Capture all variations of thinking/reasoning parts
				if ((part as any).thought && typeof (part as any).thought === 'string') {
					accumulatedThinking += (part as any).thought;
					if ((part as any).thoughtSignature) signature = (part as any).thoughtSignature;
				} else if ((part as any).thinking && typeof (part as any).thinking === 'string') {
					accumulatedThinking += (part as any).thinking;
				} else if ((part as any).reasoning && typeof (part as any).reasoning === 'string') {
					accumulatedThinking += (part as any).reasoning;
				} else if ((part as any).toolCode && typeof (part as any).toolCode === 'string') {
					accumulatedThinking += (part as any).toolCode;
				}
			}
		}
		if (!stopReason) {
			switch (candidate.finishReason) {
				case 'STOP': stopReason = 'end_turn'; break;
				case 'MAX_TOKENS': stopReason = 'max_tokens'; break;
				case 'SAFETY':
				case 'RECITATION': stopReason = 'stop_sequence'; if (claudeContent.length === 0) claudeContent.push({ type: 'text', text: `[Content blocked due to safety concerns: ${candidate.finishReason}]` }); break;
				default: stopReason = 'end_turn'; break;
			}
		}
	}
	if (accumulatedThinking) {
		claudeContent.unshift({ 
			type: 'thinking', 
			thinking: accumulatedThinking,
			signature: signature || 'placeholder' 
		} as any);
	}
	const usage = { 
		input_tokens: geminiRes.usageMetadata?.promptTokenCount || 0, 
		output_tokens: (geminiRes.usageMetadata?.candidatesTokenCount || 0) + (geminiRes.usageMetadata?.thoughtsTokenCount || 0) 
	};
	const claudeResponse = { id, type: 'message', role: 'assistant', model, content: claudeContent, stop_reason: stopReason, stop_sequence: null, usage };
	return new Response(JSON.stringify(claudeResponse), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

export function transformGeminiToClaudeStreamStart(this: any, controller: any) {
	controller.enqueue(`event: message_start\ndata: ${JSON.stringify({ type: 'message_start', message: { id: this.id, type: 'message', role: 'assistant', model: this.model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } })}\n\n`);
	controller.enqueue(`event: ping\ndata: ${JSON.stringify({ type: 'ping' })}\n\n`);
}

export function transformGeminiToClaudeStream(this: any, geminiChunk: any, controller: any) {
	const reasonsMap: Record<string, string> = { STOP: 'end_turn', MAX_TOKENS: 'max_tokens', SAFETY: 'stop_sequence', RECITATION: 'stop_sequence', OTHER: 'end_turn' };
	const { candidates, usageMetadata } = geminiChunk;
	if (candidates && candidates.length > 0) {
		const candidate = candidates[0];
		const { content, finishReason } = candidate;
		if (content?.parts) {
			for (const part of content.parts) {
				let thinkingContent = '';
				if (
					(part as any).thought === true ||
					((part as any).thought && typeof (part as any).thought === 'string')
				) {
					const thoughtContent = (part as any).thought === true ? part.text : (part as any).thought;
					thinkingContent = thoughtContent || part.text || '';
				} else if ((part as any).thinking && typeof (part as any).thinking === 'string') {
					thinkingContent = (part as any).thinking;
				} else if ((part as any).reasoning && typeof (part as any).reasoning === 'string') {
					thinkingContent = (part as any).reasoning;
				} else if ((part as any).toolCode && typeof (part as any).toolCode === 'string') {
					thinkingContent = (part as any).toolCode;
				}

				if (thinkingContent) {
					if (!this.shared.sentThinkingBlock) {
						controller.enqueue(
							`event: content_block_start\ndata: ${JSON.stringify({
								type: 'content_block_start',
								index: this.shared.contentIndex || 0,
								content_block: { type: 'thinking', thinking: '' },
							})}\n\n`
						);
						this.shared.sentThinkingBlock = true;
					}
					controller.enqueue(
						`event: content_block_delta\ndata: ${JSON.stringify({
							type: 'content_block_delta',
							index: this.shared.contentIndex || 0,
							delta: { type: 'thinking_delta', thinking: thinkingContent },
						})}\n\n`
					);
					this.shared.thinking = (this.shared.thinking || '') + thinkingContent;
					continue;
				}

				if (part.text) {
					if (this.shared.sentThinkingBlock && !this.shared.stoppedThinkingBlock) {
						controller.enqueue(
							`event: content_block_stop\ndata: ${JSON.stringify({
								type: 'content_block_stop',
								index: this.shared.contentIndex || 0,
							})}\n\n`
						);
						this.shared.contentIndex = (this.shared.contentIndex || 0) + 1;
						this.shared.stoppedThinkingBlock = true;
					}
					if (!this.shared.sentTextBlock) {
						controller.enqueue(
							`event: content_block_start\ndata: ${JSON.stringify({
								type: 'content_block_start',
								index: this.shared.contentIndex || 0,
								content_block: { type: 'text', text: '' },
							})}\n\n`
						);
						this.shared.sentTextBlock = true;
					}
					controller.enqueue(
						`event: content_block_delta\ndata: ${JSON.stringify({
							type: 'content_block_delta',
							index: this.shared.contentIndex || 0,
							delta: { type: 'text_delta', text: part.text },
						})}\n\n`
					);
				} else if (part.functionCall) {
					if (this.shared.sentThinkingBlock && !this.shared.stoppedThinkingBlock) {
						controller.enqueue(
							`event: content_block_stop\ndata: ${JSON.stringify({
								type: 'content_block_stop',
								index: this.shared.contentIndex || 0,
							})}\n\n`
						);
						this.shared.contentIndex = (this.shared.contentIndex || 0) + 1;
						this.shared.stoppedThinkingBlock = true;
					}
					if (this.shared.sentTextBlock && !this.shared.stoppedTextBlock) {
						controller.enqueue(
							`event: content_block_stop\ndata: ${JSON.stringify({
								type: 'content_block_stop',
								index: this.shared.contentIndex || 0,
							})}\n\n`
						);
						this.shared.contentIndex = (this.shared.contentIndex || 0) + 1;
						this.shared.stoppedTextBlock = true;
					}
					const toolIndex = this.shared.contentIndex || 0;
					controller.enqueue(
						`event: content_block_start\ndata: ${JSON.stringify({
							type: 'content_block_start',
							index: toolIndex,
							content_block: {
								type: 'tool_use',
								id: `toolu_${generateId()}`,
								name: part.functionCall.name,
								input: part.functionCall.args,
							},
						})}\n\n`
					);
					controller.enqueue(
						`event: content_block_stop\ndata: ${JSON.stringify({
							type: 'content_block_stop',
							index: toolIndex,
						})}\n\n`
					);
					this.shared.contentIndex = (this.shared.contentIndex || 0) + 1;
					this.shared.stopReason = 'tool_use';
				}
			}
		}
		if (finishReason) {
			const mappedReason = reasonsMap[finishReason] || finishReason.toLowerCase();
			if (this.shared.stopReason !== 'tool_use' || mappedReason !== 'end_turn') {
				this.shared.stopReason = mappedReason;
			}
		}
	}
	if (usageMetadata) this.shared.usage = { output_tokens: usageMetadata.candidatesTokenCount || 0 };
}

export function transformGeminiToClaudeStreamFlush(this: any, controller: any) {
	if (this.shared.sentThinkingBlock && !this.shared.stoppedThinkingBlock) {
		controller.enqueue(`event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: this.shared.contentIndex || 0 })}\n\n`);
	} else if (this.shared.sentTextBlock && !this.shared.stoppedTextBlock) {
		controller.enqueue(`event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: this.shared.contentIndex || 0 })}\n\n`);
	}
	controller.enqueue(`event: message_delta\ndata: ${JSON.stringify({ type: 'message_delta', delta: { stop_reason: this.shared.stopReason || 'end_turn' }, usage: this.shared.usage || { output_tokens: 0 } })}\n\n`);
	controller.enqueue(`event: message_stop\ndata: ${JSON.stringify({ type: 'message_stop' })}\n\n`);
}

export async function handleClaude(
    reqBody: ClaudeCompletionRequest, 
    pathname: string, 
    method: string, 
    apiKey: string, 
    model?: string,
    handleGemini?: (request: Request, apiKey: string, model?: string) => Promise<Response>,
    handleModels?: (apiKey: string, modelId: string | undefined, authMode: string, model?: string) => Promise<Response>
): Promise<Response> {
    const id = 'msg_' + generateId();
    
    if (pathname.endsWith('/messages')) {
        if (method !== 'POST') throw new HttpError('Method not allowed', 405);
        
        const geminiReqBody = await transformClaudeToGeminiRequest(reqBody);
        const geminiModel = model || getGeminiModelForClaude(reqBody.model);
        const TASK = reqBody.stream ? 'streamGenerateContent' : 'generateContent';

        const geminiUrl = new URL(`https://localhost/${API_VERSION}/models/${geminiModel}:${TASK}`);
        const geminiRequest = new Request(geminiUrl.toString(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(geminiReqBody),
        });

        const geminiResponse = await handleGemini!(geminiRequest, apiKey, model);
        if (!geminiResponse.ok) return geminiResponse;

        if (reqBody.stream) {
            const { readable, writable } = new TransformStream();
            geminiResponse.body!
                .pipeThrough(new TextDecoderStream())
                .pipeThrough(new TransformStream({ transform: parseStream, flush: parseStreamFlush, buffer: '', shared: {} } as any))
                .pipeThrough(
                    new TransformStream({
                        start: transformGeminiToClaudeStreamStart,
                        transform: transformGeminiToClaudeStream,
                        flush: transformGeminiToClaudeStreamFlush,
                        model: reqBody.model,
                        id,
                        shared: {},
                    } as any)
                )
                .pipeThrough(new TextEncoderStream())
                .pipeTo(writable);
            return new Response(readable, { status: 200, headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' } });
        } else {
            return transformGeminiToClaudeResponse(await geminiResponse.json(), reqBody.model, id);
        }
    }
    
    const modelsMatch = pathname.match(/models\/([^/]+)$/);
    const isModelsList = pathname.endsWith('/models') || pathname.endsWith('/oauth/models');
    if (modelsMatch || isModelsList) {
        if (method !== 'GET') throw new HttpError('Method not allowed', 405);
        const modelId = modelsMatch ? modelsMatch[1] : undefined;
        return handleModels!(apiKey, modelId, "claude", model);
    }
    
    throw new HttpError('Not Found', 404);
}
