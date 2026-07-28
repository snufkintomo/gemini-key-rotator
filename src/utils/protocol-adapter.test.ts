import { describe, it, expect } from 'vitest';
import { getProtocolAdapter, OpenAIAdapter, ClaudeAdapter, GeminiAdapter, AntigravityAdapter } from './protocol-adapter';

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

	it('should translate Gemini request into normalized payload', async () => {
		const adapter = new GeminiAdapter();
		const request = new Request('https://proxy/v1/models/gemini-2.5-flash:generateContent', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				contents: [{ role: 'user', parts: [{ text: 'Hello Gemini' }] }]
			})
		});

		const payload = await adapter.translateRequest(request);
		expect(payload.contents.length).toBe(1);
	});
});
