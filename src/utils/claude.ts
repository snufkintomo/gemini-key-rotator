import { getGeminiModelForClaude } from './models';
import { parseStream, parseStreamFlush } from './streams';
import { generateId } from './openai';
import { stripMetaSchema } from './schema';
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


export async function transformClaudeMessagesToGeminiContents(messages: ClaudeMessage[]): Promise<{ contents: any[]; system_instruction?: any }> {
	const contents: any[] = [];
	let system_instruction: any;
	for (const item of messages) {
		if (item.role === 'user' || item.role === 'assistant') {
			const parts: any[] = [];
			let currentSignature: string | undefined;

			if (typeof item.content === 'string') {
				if (item.content && item.content.trim().length > 0) {
					parts.push({ text: item.content });
				}
			} else if (Array.isArray(item.content)) {
				for (const part of item.content) {
					switch (part.type) {
						case 'thinking':
							if ((part as any).signature) currentSignature = (part as any).signature;
							if (part.thinking && part.thinking.trim().length > 0) {
								parts.push({
									thought: true,
									text: part.thinking,
									thoughtSignature: (part as any).signature,
								});
							}
							break;
						case 'text':
							if (part.text && part.text.trim().length > 0) {
								parts.push({ text: part.text });
							}
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
							let toolName = part.tool_use_id;
							if (part.tool_use_id && part.tool_use_id.includes('_TSIG_')) {
								const parts = part.tool_use_id.split('_TSIG_');
								toolName = parts[0];
							}
							parts.push({
								functionResponse: {
									name: toolName,
									response: { content: part.content },
								},
							});
							break;
					}
				}
			}
			if (parts.length > 0) {
				contents.push({ role: item.role === 'assistant' ? 'model' : 'user', parts: parts });
			}
		} else if (item.role === 'system') {
			if (typeof item.content === 'string') {
				if (item.content && item.content.trim().length > 0) {
					system_instruction = { parts: [{ text: item.content }] };
				}
			} else if (Array.isArray(item.content)) {
				const textParts = (item.content as any[])
					.filter((p) => p.type === 'text' && p.text && p.text.trim().length > 0)
					.map((p) => ({ text: p.text }));
				if (textParts.length > 0) {
					system_instruction = { parts: textParts };
				}
			}
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

	// Ensure conversation starts with a user message
	if (mergedContents.length > 0 && mergedContents[0].role === 'model') {
		mergedContents.unshift({
			role: 'user',
			parts: [{ text: '...' }]
		});
	}

	return { contents: mergedContents, system_instruction };
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
					parameters: stripMetaSchema(parameters)
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

async function sha256Hex(plain: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(plain);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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

	// Detect Claude prompt caching (ephemeral cache control)
	let cacheControlMeta = null;
	let cacheIndex = -1;

	// Check messages for cache control
	if (claudeReq.messages && claudeReq.messages.length > 0) {
		for (let i = 0; i < claudeReq.messages.length; i++) {
			const msg = claudeReq.messages[i];
			let hasCache = false;
			if ((msg as any).cache_control?.type === 'ephemeral') {
				hasCache = true;
			} else if (Array.isArray(msg.content)) {
				for (const part of msg.content) {
					if ((part as any).cache_control?.type === 'ephemeral') {
						hasCache = true;
						break;
					}
				}
			}
			if (hasCache) {
				cacheIndex = i;
			}
		}
	}

	// Also check system prompt for cache control
	let systemHasCache = false;
	if (claudeReq.system) {
		if (Array.isArray(claudeReq.system)) {
			for (const p of claudeReq.system) {
				if ((p as any).cache_control?.type === 'ephemeral') {
					systemHasCache = true;
					break;
				}
			}
		} else if (typeof claudeReq.system === 'object' && (claudeReq.system as any).cache_control?.type === 'ephemeral') {
			systemHasCache = true;
		}
	}

	if (cacheIndex !== -1 || systemHasCache) {
		// Calculate cacheable prefix payload
		const cacheableMessages = cacheIndex !== -1 ? claudeReq.messages.slice(0, cacheIndex + 1) : [];
		const { contents: cacheableContents } = await transformClaudeMessagesToGeminiContents(cacheableMessages);
		
		const cacheablePayload = {
			contents: cacheableContents,
			system_instruction: system_instruction || null
		};

		const payloadStr = JSON.stringify(cacheablePayload);
		const prefixHash = await sha256Hex(payloadStr);

		cacheControlMeta = {
			hash: prefixHash,
			cacheable_payload: cacheablePayload,
			remaining_contents_index: cacheableContents.length
		};
	}

	const result: any = { 
		contents, 
		system_instruction, 
		generationConfig: Object.keys(generationConfig).length > 0 ? generationConfig : undefined, 
		safetySettings, 
		tools, 
		tool_config 
	};

	if (cacheControlMeta) {
		result.__claude_cache_control__ = cacheControlMeta;
	}

	return result;
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
				// Capture signature from thinking parts or functionCall
				if ((part as any).thoughtSignature) signature = (part as any).thoughtSignature;
				if (part.functionCall?.thought_signature) signature = part.functionCall.thought_signature;

				if (part.text) {
					if ((part as any).thought === true || ((part as any).thought && typeof (part as any).thought === 'string')) {
						const thoughtContent = (part as any).thought === true ? part.text : (part as any).thought;
						accumulatedThinking += thoughtContent || part.text;
					} else claudeContent.push({ type: 'text', text: part.text });
				} else if (part.functionCall) {
					let toolId = `toolu_${generateId()}`;
					// Encode signature in tool ID for later recovery
					if (signature) {
						toolId += `_TSIG_${signature}`;
					}
					claudeContent.push({
						type: 'tool_use',
						id: toolId,
						name: part.functionCall.name,
						input: part.functionCall.args,
					});
					stopReason = 'tool_use';
				}

				// Capture all variations of thinking/reasoning parts
				if ((part as any).thought && typeof (part as any).thought === 'string') {
					accumulatedThinking += (part as any).thought;
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
		output_tokens: (geminiRes.usageMetadata?.candidatesTokenCount || 0) + (geminiRes.usageMetadata?.thoughtsTokenCount || 0),
		cache_read_tokens: geminiRes.usageMetadata?.cachedContentTokenCount || 0
	};
	const claudeResponse = { id, type: 'message', role: 'assistant', model, content: claudeContent, stop_reason: stopReason, stop_sequence: null, usage };
	return new Response(JSON.stringify(claudeResponse), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

export function transformGeminiToClaudeStreamStart(this: any, controller: any) {
	controller.enqueue(`event: message_start\ndata: ${JSON.stringify({ type: 'message_start', message: { id: this.id, type: 'message', role: 'assistant', model: this.model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } })}\n\n`);
	controller.enqueue(`event: ping\ndata: ${JSON.stringify({ type: 'ping' })}\n\n`);

	// Start keep-alive interval
	this.shared.keepAliveTimer = setInterval(() => {
		controller.enqueue(': keep-alive\n\n');
	}, 10000);
}

export function transformGeminiToClaudeStream(this: any, geminiChunk: any, controller: any) {
	if (this.shared.keepAliveTimer) {
		clearInterval(this.shared.keepAliveTimer);
		this.shared.keepAliveTimer = null;
	}

	const reasonsMap: Record<string, string> = { 
		STOP: 'end_turn', 
		MAX_TOKENS: 'max_tokens', 
		SAFETY: 'stop_sequence', 
		RECITATION: 'stop_sequence', 
		OTHER: 'end_turn' 
	};
	const { candidates, usageMetadata } = geminiChunk;
	
	if (usageMetadata) {
		this.shared.usage = { 
			input_tokens: usageMetadata.promptTokenCount || 0,
			output_tokens: (usageMetadata.candidatesTokenCount || 0) + (usageMetadata.thoughtsTokenCount || 0),
			cache_read_tokens: usageMetadata.cachedContentTokenCount || 0
		};
	}

	if (candidates && candidates.length > 0) {
		const candidate = candidates[0];
		const { content, finishReason } = candidate;
		
		if (content?.parts) {
			for (const part of content.parts) {
				// Capture thought signature if available
				if ((part as any).thoughtSignature) this.shared.currentSignature = (part as any).thoughtSignature;
				if (part.functionCall?.thought_signature) this.shared.currentSignature = part.functionCall.thought_signature;

				// 1. Detect Thinking
				let thinkingContent = '';
				if ((part as any).thought === true || ((part as any).thought && typeof (part as any).thought === 'string')) {
					thinkingContent = (part as any).thought === true ? (part.text || '') : (part as any).thought;
				} else if ((part as any).thinking && typeof (part as any).thinking === 'string') {
					thinkingContent = (part as any).thinking;
				} else if ((part as any).reasoning && typeof (part as any).reasoning === 'string') {
					thinkingContent = (part as any).reasoning;
				}

				if (thinkingContent) {
					// Start thinking block if not already started
					if (!this.shared.currentBlockType) {
						controller.enqueue(`event: content_block_start\ndata: ${JSON.stringify({
							type: 'content_block_start',
							index: this.shared.contentIndex || 0,
							content_block: { 
								type: 'thinking', 
								thinking: '',
								signature: this.shared.currentSignature || 'placeholder'
							}
						})}\n\n`);
						this.shared.currentBlockType = 'thinking';
						this.shared.contentIndex = (this.shared.contentIndex || 0);
					}
					
					// If we were in a text block, we can't switch back to thinking in Claude protocol usually,
					// but Gemini might interleaved. We'll stick to the current block if it's thinking.
					if (this.shared.currentBlockType === 'thinking') {
						const delta: any = { type: 'thinking_delta', thinking: thinkingContent };
						if (this.shared.currentSignature) delta.signature = this.shared.currentSignature;
						
						controller.enqueue(`event: content_block_delta\ndata: ${JSON.stringify({
							type: 'content_block_delta',
							index: this.shared.contentIndex || 0,
							delta: delta
						})}\n\n`);
					}
					continue;
				}

				// 2. Handle Text
				if (part.text) {
					// Transition from thinking to text if needed
					if (this.shared.currentBlockType === 'thinking') {
						controller.enqueue(`event: content_block_stop\ndata: ${JSON.stringify({
							type: 'content_block_stop',
							index: this.shared.contentIndex || 0
						})}\n\n`);
						this.shared.contentIndex = (this.shared.contentIndex || 0) + 1;
						this.shared.currentBlockType = null;
					}

					// Start text block if not started
					if (!this.shared.currentBlockType) {
						controller.enqueue(`event: content_block_start\ndata: ${JSON.stringify({
							type: 'content_block_start',
							index: this.shared.contentIndex || 0,
							content_block: { type: 'text', text: '' }
						})}\n\n`);
						this.shared.currentBlockType = 'text';
					}

					if (this.shared.currentBlockType === 'text') {
						controller.enqueue(`event: content_block_delta\ndata: ${JSON.stringify({
							type: 'content_block_delta',
							index: this.shared.contentIndex || 0,
							delta: { type: 'text_delta', text: part.text }
						})}\n\n`);
					}
				} 
				
				// 3. Handle Tool Calls
				else if (part.functionCall) {
					// Stop any open text/thinking blocks
					if (this.shared.currentBlockType) {
						controller.enqueue(`event: content_block_stop\ndata: ${JSON.stringify({
							type: 'content_block_stop',
							index: this.shared.contentIndex || 0
						})}\n\n`);
						this.shared.contentIndex = (this.shared.contentIndex || 0) + 1;
						this.shared.currentBlockType = null;
					}

					const toolIndex = this.shared.contentIndex || 0;
					let toolId = `toolu_${generateId()}`;
					if (this.shared.currentSignature) {
						toolId += `_TSIG_${this.shared.currentSignature}`;
					}
					controller.enqueue(`event: content_block_start\ndata: ${JSON.stringify({
						type: 'content_block_start',
						index: toolIndex,
						content_block: {
							type: 'tool_use',
							id: toolId,
							name: part.functionCall.name,
							input: part.functionCall.args || {}
						}
					})}\n\n`);
					
					controller.enqueue(`event: content_block_stop\ndata: ${JSON.stringify({
						type: 'content_block_stop',
						index: toolIndex
					})}\n\n`);
					
					this.shared.contentIndex = toolIndex + 1;
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
}

export function transformGeminiToClaudeStreamFlush(this: any, controller: any) {
	if (this.shared.keepAliveTimer) {
		clearInterval(this.shared.keepAliveTimer);
	}

	// 1. Close any remaining open content block
	if (this.shared.currentBlockType) {
		controller.enqueue(`event: content_block_stop\ndata: ${JSON.stringify({ 
			type: 'content_block_stop', 
			index: this.shared.contentIndex || 0 
		})}\n\n`);
	}

	// 2. Send final message delta with stop reason and usage
	controller.enqueue(`event: message_delta\ndata: ${JSON.stringify({ 
		type: 'message_delta', 
		delta: { 
			stop_reason: this.shared.stopReason || 'end_turn',
			stop_sequence: null
		}, 
		usage: this.shared.usage || { output_tokens: 0 } 
	})}\n\n`);

	// 3. Final stop event
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
