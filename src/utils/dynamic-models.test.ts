import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { findDynamicModel, fetchAvailableRuntimeModel } from './dynamic-models';

describe('Dynamic Model Matching', () => {
	it('should recursively find matching model ID in complex nested objects', () => {
		const mockResponse = {
			availableModels: [
				{
					modelId: 'gemini-3.5-flash-low-001',
					displayName: 'Gemini 3.5 Flash (low)',
					modelProvider: 'GOOGLE'
				},
				{
					modelId: 'gemini-3-flash-agent-v3',
					displayName: 'Gemini 3 Flash Agent',
					modelProvider: 'GOOGLE'
				},
				{
					model: 'claude-sonnet-4-6-thinking',
					label: 'Claude 3.5 Sonnet 4.6',
					modelProvider: 'ANTHROPIC'
				},
				{
					id: 'MODEL_GOOGLE_GEMINI_2_5_FLASH',
					name: 'Gemini 2.5 Flash',
					modelProvider: 'GOOGLE'
				}
			]
		};

		// 1. Test gemini-3.5-flash-low ➔ gemini-3.5-flash-low-001
		expect(findDynamicModel(mockResponse, 'gemini-3.5-flash-low')).toBe('gemini-3.5-flash-low-001');

		// 2. Test gemini-3.5-flash-high ➔ gemini-3-flash-agent-v3
		expect(findDynamicModel(mockResponse, 'gemini-3.5-flash-high')).toBe('gemini-3-flash-agent-v3');
		expect(findDynamicModel(mockResponse, 'gemini-3-flash-agent')).toBe('gemini-3-flash-agent-v3');

		// 3. Test claude-sonnet-4-6 ➔ claude-sonnet-4-6-thinking
		expect(findDynamicModel(mockResponse, 'claude-sonnet-4-6')).toBe('claude-sonnet-4-6-thinking');

		// 4. Test gemini-2.5-flash ➔ MODEL_GOOGLE_GEMINI_2_5_FLASH
		expect(findDynamicModel(mockResponse, 'gemini-2.5-flash')).toBe('MODEL_GOOGLE_GEMINI_2_5_FLASH');
	});

	it('should fallback to regex search if no explicit model requestedId match exists', () => {
		const mockResponse = {
			id: 'gemini-1.5-pro-experimental',
			displayName: 'Gemini 1.5 Pro Exp'
		};
		expect(findDynamicModel(mockResponse, 'gemini-1.5-pro')).toBe('gemini-1.5-pro-experimental');
	});
});

describe('fetchAvailableRuntimeModel API integration', () => {
	let originalFetch: typeof fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it('should fetch available models and return matching ID', async () => {
		const mockApiResult = {
			models: [
				{
					id: 'gemini-3.1-pro-low-test',
					displayName: 'Gemini 3.1 Pro (low)'
				}
			]
		};

		const fetchSpy = vi.fn().mockResolvedValue(new Response(JSON.stringify(mockApiResult), { status: 200 }));
		globalThis.fetch = fetchSpy;

		const result = await fetchAvailableRuntimeModel('token', 'project', 'gemini-3.1-pro-low');
		expect(result).toBe('gemini-3.1-pro-low-test');
		expect(fetchSpy).toHaveBeenCalled();
	});
});
