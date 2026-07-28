import { describe, it, expect } from 'vitest';
import { TelemetrySink } from './telemetry-sink';

describe('TelemetrySink', () => {
	it('should redact sensitive tokens and credentials from request/response bodies', () => {
		const rawInput = JSON.stringify({
			key: 'AIzaSyKey12345678901234567890',
			auth: 'Bearer secret_token_xyz_123456789'
		});

		const sanitized = TelemetrySink.sanitizeText(rawInput);
		expect(sanitized).toContain('[REDACTED]');
		expect(sanitized).not.toContain('secret_token_xyz_123456789');
	});

	it('should extract token usage metrics from OpenAI format response', async () => {
		const body = JSON.stringify({
			usage: {
				prompt_tokens: 150,
				completion_tokens: 42
			}
		});
		const response = new Response(body, {
			headers: { 'content-type': 'application/json' }
		});

		const usage = await TelemetrySink.extractUsage(response, 'openai');
		expect(usage.promptTokens).toBe(150);
		expect(usage.completionTokens).toBe(42);
	});

	it('should extract token usage metrics from Claude format response', async () => {
		const body = JSON.stringify({
			usage: {
				input_tokens: 200,
				output_tokens: 88
			}
		});
		const response = new Response(body, {
			headers: { 'content-type': 'application/json' }
		});

		const usage = await TelemetrySink.extractUsage(response, 'claude');
		expect(usage.promptTokens).toBe(200);
		expect(usage.completionTokens).toBe(88);
	});

	it('should buffer recorded events with FIFO eviction', () => {
		const sink = new TelemetrySink(2);
		sink.recordEvent({ success: true, promptTokens: 10 });
		sink.recordEvent({ success: true, promptTokens: 20 });
		sink.recordEvent({ success: true, promptTokens: 30 });

		const events = sink.getBufferedEvents();
		expect(events.length).toBe(2);
		expect(events[0].promptTokens).toBe(20);
		expect(events[1].promptTokens).toBe(30);
	});

	it('should flush buffered events cleanly', async () => {
		const sink = new TelemetrySink(10);
		sink.recordEvent({ success: true, promptTokens: 100 });
		sink.recordEvent({ success: true, promptTokens: 200 });

		const flushedCount = await sink.flush();
		expect(flushedCount).toBe(2);
		expect(sink.getBufferedEvents().length).toBe(0);
	});
});
