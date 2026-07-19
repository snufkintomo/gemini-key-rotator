import { describe, it, expect } from 'vitest';
import { sanitizeLogBody } from './sanitize';

describe('Log Sanitization Utility', () => {
	it('should return empty string or small string unmodified', () => {
		expect(sanitizeLogBody('')).toBe('');
		expect(sanitizeLogBody('Hello world')).toBe('Hello world');
	});

	it('should sanitize base64 data URLs in JSON', () => {
		const original = {
			model: 'gpt-4o',
			messages: [
				{
					role: 'user',
					content: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA' + 'A'.repeat(1000)
				}
			]
		};

		const sanitizedStr = sanitizeLogBody(JSON.stringify(original));
		const sanitized = JSON.parse(sanitizedStr);

		expect(sanitized.messages[0].content).toContain('data:image/png;base64,[Truncated Base64 Data:');
		expect(sanitized.messages[0].content).not.toContain('AAAA');
	});

	it('should sanitize nested "data" fields with base64 data', () => {
		const original = {
			contents: [
				{
					parts: [
						{
							inlineData: {
								mimeType: 'image/jpeg',
								data: '/9j/4AAQSkZJRgABAQEASABIAAD/' + 'A'.repeat(6000)
							}
						}
					]
				}
			]
		};

		const sanitizedStr = sanitizeLogBody(JSON.stringify(original));
		const sanitized = JSON.parse(sanitizedStr);

		expect(sanitized.contents[0].parts[0].inlineData.data).toContain('[Truncated Base64 Data: 6028 characters]');
	});

	it('should sanitize plain string with base64 data URLs using regex fallback', () => {
		const plainText = 'Here is the data: data:image/jpeg;base64,' + 'A'.repeat(500);
		const sanitized = sanitizeLogBody(plainText, 100);

		expect(sanitized).toContain('data:image/jpeg;base64,[Truncated Base64 Data: 500 characters]');
	});

	it('should truncate extremely long text values in JSON', () => {
		const original = {
			prompt: 'A'.repeat(60000)
		};

		const sanitizedStr = sanitizeLogBody(JSON.stringify(original), 10000);
		const sanitized = JSON.parse(sanitizedStr);

		expect(sanitized.prompt).toHaveLength(10050); // 10000 + 50 characters for suffix
		expect(sanitized.prompt).toContain('... [Truncated, original length: 60000 characters]');
	});
});
