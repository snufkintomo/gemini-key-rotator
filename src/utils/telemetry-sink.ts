/**
 * Deep Module: TelemetrySink
 * Consolidates credential sanitization, usage token extraction,
 * FIFO in-memory buffering, and non-blocking Cloudflare D1 batch persistence.
 */

import { sanitizeLogBody } from './sanitize';

export interface TelemetryEvent {
	rawKey?: string;
	keyType?: 'api_key' | 'oauth' | 'antigravity';
	userToken?: string;
	success: boolean;
	is429?: boolean;
	mode?: string;
	model?: string;
	promptTokens?: number;
	completionTokens?: number;
	cachedTokens?: number;
	savedTokens?: number;
	requestPath?: string;
	method?: string;
	requestHeaders?: Record<string, string>;
	requestBody?: string;
	responseStatus?: number;
	responseHeaders?: Record<string, string>;
	responseBody?: string;
	durationMs?: number;
	timestamp?: number;
}

export class TelemetrySink {
	private buffer: TelemetryEvent[] = [];
	private maxBufferSize: number;

	constructor(maxBufferSize = 100) {
		this.maxBufferSize = maxBufferSize;
	}

	/**
	 * Redacts sensitive credentials (Authorization headers, API keys, OAuth secrets).
	 */
	static sanitizeText(text: string): string {
		if (!text) return '';
		let cleaned = text;
		// Redact Bearer tokens / X-Access-Token / API keys
		cleaned = cleaned.replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, '$1[REDACTED]');
		cleaned = cleaned.replace(/(x-access-token:\s*)[^\s,"']+/gi, '$1[REDACTED]');
		cleaned = cleaned.replace(/(key=)[A-Za-z0-9_-]{20,}/gi, '$1[REDACTED]');
		return sanitizeLogBody(cleaned);
	}

	/**
	 * Extracts usage tokens (promptTokens, completionTokens, cachedTokens) from an HTTP Response.
	 */
	static async extractUsage(response: Response, mode: string): Promise<{ promptTokens: number; completionTokens: number; cachedTokens: number }> {
		let promptTokens = 0;
		let completionTokens = 0;
		let cachedTokens = 0;

		try {
			const cloned = response.clone();
			if (cloned.headers.get('content-type')?.includes('text/event-stream')) {
				const reader = cloned.body?.getReader();
				if (!reader) return { promptTokens, completionTokens, cachedTokens };

				const decoder = new TextDecoder();
				let buffer = '';
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value) {
						buffer += decoder.decode(value, { stream: true });
					}
				}

				// 1. Gemini usageMetadata
				const usageMetadataMatch = buffer.match(/"usageMetadata"\s*:\s*\{([^}]+)\}/);
				if (usageMetadataMatch) {
					const inner = usageMetadataMatch[1];
					const promptMatch = inner.match(/"promptTokenCount"\s*:\s*(\d+)/);
					const candidatesMatch = inner.match(/"candidatesTokenCount"\s*:\s*(\d+)/);
					const cachedMatch = inner.match(/"cachedContentTokenCount"\s*:\s*(\d+)/);
					if (promptMatch) promptTokens = parseInt(promptMatch[1], 10);
					if (candidatesMatch) completionTokens = parseInt(candidatesMatch[1], 10);
					if (cachedMatch) cachedTokens = parseInt(cachedMatch[1], 10);
					return { promptTokens, completionTokens, cachedTokens };
				}

				// 2. Claude / OpenAI SSE tokens
				const promptTokensMatch = buffer.match(/"(?:input_tokens|prompt_tokens)"\s*:\s*(\d+)/);
				if (promptTokensMatch) {
					promptTokens = parseInt(promptTokensMatch[1], 10);
				}

				const completionRegex = /"(?:output_tokens|completion_tokens)"\s*:\s*(\d+)/g;
				let match;
				let maxCompletion = 0;
				while ((match = completionRegex.exec(buffer)) !== null) {
					const val = parseInt(match[1], 10);
					if (val > maxCompletion) {
						maxCompletion = val;
					}
				}
				completionTokens = maxCompletion;
			} else {
				const text = await cloned.text();
				try {
					const data = JSON.parse(text);
					if (mode === 'openai') {
						if (data.usage) {
							promptTokens = data.usage.prompt_tokens || 0;
							completionTokens = data.usage.completion_tokens || 0;
						}
					} else if (mode === 'claude') {
						if (data.usage) {
							promptTokens = data.usage.input_tokens || 0;
							completionTokens = data.usage.output_tokens || 0;
						}
					} else {
						let usage = null;
						if (Array.isArray(data) && data.length > 0 && data[0].usageMetadata) {
							usage = data[0].usageMetadata;
						} else if (data.usageMetadata) {
							usage = data.usageMetadata;
						}
						if (usage) {
							promptTokens = usage.promptTokenCount || 0;
							completionTokens = usage.candidatesTokenCount || 0;
							cachedTokens = usage.cachedContentTokenCount || 0;
						}
					}
				} catch {
					// Ignore JSON parse error on non-JSON response body
				}
			}
		} catch {
			// Ignore stream reading errors on aborted responses
		}

		return { promptTokens, completionTokens, cachedTokens };
	}

	/**
	 * Record a telemetry event into the FIFO buffer with automatic sanitization.
	 */
	recordEvent(event: TelemetryEvent): void {
		const sanitizedEvent: TelemetryEvent = {
			...event,
			timestamp: event.timestamp || Date.now(),
			requestBody: event.requestBody ? TelemetrySink.sanitizeText(event.requestBody) : undefined,
			responseBody: event.responseBody ? TelemetrySink.sanitizeText(event.responseBody) : undefined
		};

		if (this.buffer.length >= this.maxBufferSize) {
			this.buffer.shift(); // FIFO eviction when capacity is reached
		}
		this.buffer.push(sanitizedEvent);
	}

	/**
	 * Get current buffered events.
	 */
	getBufferedEvents(): TelemetryEvent[] {
		return [...this.buffer];
	}

	/**
	 * Flush buffered events to D1 database batch.
	 */
	async flush(db?: any): Promise<number> {
		if (this.buffer.length === 0) return 0;
		const eventsToFlush = [...this.buffer];
		this.buffer = [];

		if (db && typeof db.prepare === 'function') {
			try {
				const stmt = db.prepare(
					'INSERT INTO api_logs (timestamp, access_token, request_method, request_url, request_headers, request_body, response_status, response_headers, response_body, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
				);
				const batch = eventsToFlush.map((evt) =>
					stmt.bind(
						new Date(evt.timestamp || Date.now()).toISOString(),
						evt.userToken || null,
						evt.method || 'POST',
						evt.requestPath || '/v1/chat/completions',
						JSON.stringify(evt.requestHeaders || {}),
						evt.requestBody || '',
						evt.responseStatus || 200,
						JSON.stringify(evt.responseHeaders || {}),
						evt.responseBody || '',
						evt.durationMs || 0
					)
				);
				if (typeof db.batch === 'function') {
					await db.batch(batch);
				}
			} catch {
				// Prevent telemetry flush failures from affecting client request flow
			}
		}

		return eventsToFlush.length;
	}
}
