import { describe, it, expect } from 'vitest';
import { getProtocolAdapter, OpenAIAdapter, ClaudeAdapter, GeminiAdapter, AntigravityAdapter } from './protocol-adapter';
import { transformOpenAIMessagesToGeminiContents } from './openai';

describe('ProtocolAdapter Seam', () => {
	it('should return correct adapter instance for given mode string', () => {
		expect(getProtocolAdapter('openai')).toBeInstanceOf(OpenAIAdapter);
		expect(getProtocolAdapter('claude')).toBeInstanceOf(ClaudeAdapter);
		expect(getProtocolAdapter('gemini')).toBeInstanceOf(GeminiAdapter);
		expect(getProtocolAdapter('google')).toBeInstanceOf(GeminiAdapter);
		expect(getProtocolAdapter('antigravity')).toBeInstanceOf(AntigravityAdapter);
	});

	it('should translate OpenAI request into normalized payload', async () => {
		const adapter = new OpenAIAdapter();
		const request = new Request('https://proxy/v1/chat/completions', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				model: 'gpt-4o',
				messages: [{ role: 'user', content: 'Hello OpenAI' }]
			})
		});

		const payload = await adapter.translateRequest(request);
		expect(payload.contents.length).toBe(1);
		expect(payload.model).toBeDefined();
	});

	it('should translate Claude request into normalized payload with system prompt', async () => {
		const adapter = new ClaudeAdapter();
		const request = new Request('https://proxy/v1/messages', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				model: 'claude-3-7-sonnet',
				system: 'You are a helpful assistant',
				messages: [{ role: 'user', content: 'Hello Claude' }]
			})
		});

		const payload = await adapter.translateRequest(request);
		expect(payload.contents.length).toBe(1);
		expect(payload.systemInstruction).toBe('You are a helpful assistant');
	});

	it('should attach thought_signature to Gemini functionCall when translating OpenAI tool_calls', async () => {
		const result: any = await transformOpenAIMessagesToGeminiContents([
			{ role: 'user', content: 'Read files' },
			{
				role: 'assistant',
				tool_calls: [
					{
						id: 'call_123_TSIG_SIG_TEST_456',
						type: 'function',
						function: { name: 'default_api:read', arguments: '{}' }
					},
					{
						id: 'call_789',
						type: 'function',
						function: { name: 'default_api:bash', arguments: '{}' }
					}
				]
			}
		]);

		const modelContent = result.contents.find((c: any) => c.role === 'model');
		expect(modelContent).toBeDefined();
		const parts = modelContent.parts;
		expect(parts[0].functionCall.thought_signature).toBe('SIG_TEST_456');
		expect(parts[1].functionCall.thought_signature).toBe('skip');
	});
});
