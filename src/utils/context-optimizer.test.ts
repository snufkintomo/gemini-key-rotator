import { describe, it, expect } from 'vitest';
import { ContextOptimizer } from './context-optimizer';

describe('ContextOptimizer', () => {
	it('should correctly estimate token counts for text and tool parts', () => {
		const contents = [
			{
				role: 'user',
				parts: [{ text: 'Hello world! This is a test prompt.' }]
			}
		];
		const tokens = ContextOptimizer.estimateTokens(contents);
		expect(tokens).toBeGreaterThan(0);
		expect(tokens).toBe(Math.ceil('Hello world! This is a test prompt.'.length / 4));
	});

	it('should strip ANSI escape sequences from strings', () => {
		const rawText = '\u001b[31mError:\u001b[0m Something failed\u001b[1m!';
		const clean = ContextOptimizer.stripAnsi(rawText);
		expect(clean).toBe('Error: Something failed!');
	});

	it('should fold unchanged context in git diffs', () => {
		const lines = [
			'diff --git a/file.ts b/file.ts',
			'index 123456..7890ab 100644',
			'--- a/file.ts',
			'+++ b/file.ts',
			'@@ -1,15 +1,15 @@',
			...Array(20).fill(' const unchanged = true;'),
			'+const changed = true;',
			...Array(20).fill(' const unchanged = true;')
		].join('\n');

		const compacted = ContextOptimizer.compactGitDiff(lines);
		expect(compacted).toContain('lines of unchanged context folded to save tokens');
		expect(compacted).toContain('+const changed = true;');
	});

	it('should prune expired tool call pairs when superseded by a newer call for same resource', () => {
		const contents = [
			{
				role: 'user',
				parts: [{ functionCall: { name: 'read', args: { path: 'config.json' } } }]
			},
			{
				role: 'user',
				parts: [{ functionResponse: { name: 'read', response: { content: 'v1' } } }]
			},
			{
				role: 'user',
				parts: [{ functionCall: { name: 'read', args: { path: 'config.json' } } }]
			},
			{
				role: 'user',
				parts: [{ functionResponse: { name: 'read', response: { content: 'v2' } } }]
			}
		];

		const res = ContextOptimizer.optimizePayload(contents);
		expect(res.stats.expiredRemoved).toBe(2);
		// Adjacent user turns are merged into 1 turn containing surviving parts
		expect(res.prunedContents.length).toBe(1);
		expect(res.prunedContents[0].parts.length).toBe(2);
	});

	it('should tombstone error outputs when older error call is restored by dependency', () => {
		const contents = [
			{
				role: 'user',
				parts: [{ functionCall: { name: 'bash', args: { command: 'build app.ts' } } }]
			},
			{
				role: 'user',
				parts: [{ functionResponse: { name: 'bash', response: { exitCode: 1, error: 'Build failed app.ts' } } }]
			},
			{
				role: 'user',
				parts: [{ functionCall: { name: 'bash', args: { command: 'build app.ts' } } }]
			},
			{
				role: 'user',
				parts: [{ functionResponse: { name: 'bash', response: { exitCode: 0, output: 'Success' } } }]
			},
			{
				role: 'user',
				parts: [{ text: 'We modified app.ts and executed build app.ts successfully.' }]
			}
		];

		const res = ContextOptimizer.optimizePayload(contents);
		expect(res.stats.restoredCount).toBe(2);
		expect(res.stats.errorsTombstoned).toBe(1);
	});

	it('TDD Ticket 01: should collapse framework stacktrace frames while preserving app frames and error message', () => {
		const longStacktrace = [
			'Error: Connection timeout at Database.connect',
			'    at Database.connect (D:/CloudflareWorkers/gemini-key-rotator/src/utils/admin-controller.ts:88:15)',
			'    at Layer.handle [as handle_request] (D:/CloudflareWorkers/gemini-key-rotator/node_modules/express/lib/router/layer.js:95:5)',
			'    at trim_prefix (D:/CloudflareWorkers/gemini-key-rotator/node_modules/express/lib/router/index.js:317:13)',
			'    at c (D:/CloudflareWorkers/gemini-key-rotator/node_modules/express/lib/router/index.js:284:7)',
			'    at Function.process_params (D:/CloudflareWorkers/gemini-key-rotator/node_modules/express/lib/router/index.js:335:12)',
			'    at next (D:/CloudflareWorkers/gemini-key-rotator/node_modules/express/lib/router/index.js:275:10)',
			'    at send_file (D:/CloudflareWorkers/gemini-key-rotator/node_modules/express/lib/router/index.js:621:5)',
			'    at c (D:/CloudflareWorkers/gemini-key-rotator/node_modules/express/lib/router/index.js:284:7)',
			'    at processTicksAndRejections (node:internal/process/task_queues:95:5)',
			'    at async handleRequest (D:/CloudflareWorkers/gemini-key-rotator/src/index.ts:120:10)',
			'    at async Server.emit (node:events:513:28)',
			'    at async Socket.onData (node:net:312:9)',
			'    at async TCP.onStreamRead (node:internal/stream_base_commons:217:20)',
			'    at async Pipe.onread (node:net:612:12)',
			'    at async Socket.write (node:net:710:14)',
			'    at async HTTPParser.onIncoming (node:internal/http:412:8)',
			'    at async Stream.pipe (node:internal/stream:110:5)',
			'    at async Module._compile (node:internal/modules/cjs/loader:1159:14)',
			'    at async Module._load (node:internal/modules/cjs/loader:981:12)'
		].join('\n');

		const pruned = ContextOptimizer.pruneStacktraces(longStacktrace);
		expect(pruned).toContain('Error: Connection timeout at Database.connect');
		expect(pruned).toContain('src/utils/admin-controller.ts:88:15');
		expect(pruned).toContain('src/index.ts:120:10');
		expect(pruned).toContain('internal stack frames hidden');
		expect(pruned.split('\n').length).toBeLessThan(longStacktrace.split('\n').length);
	});

	it('TDD Ticket 02: should replace duplicate large code blocks (> 300 chars) across turns with pointer token', () => {
		const largeBlock = `
			function processLargeDataPayload(inputPayload: string): Record<string, any> {
				const sanitized = inputPayload.trim().toLowerCase();
				const result = { timestamp: Date.now(), status: 'success', data: sanitized };
				if (sanitized.length > 500) {
					console.log('Processing large input payload in background worker queue...');
					result.status = 'queued';
				}
				return result;
			}
		`.repeat(3); // > 300 chars

		const contents = [
			{ role: 'user', parts: [{ text: `Here is the code in Turn 1:\n${largeBlock}` }] },
			{ role: 'model', parts: [{ text: 'I understand.' }] },
			{ role: 'user', parts: [{ text: `Here is the identical code again in Turn 3:\n${largeBlock}` }] }
		];

		const res = ContextOptimizer.optimizePayload(contents, { forceTier: 1 });
		expect(res.stats.duplicatesRemoved).toBeGreaterThan(0);
		expect(res.prunedContents[2].parts[0].text).toContain('Duplicate text removed');
	});

	it('TDD Ticket 03: should route to Tier 0 (<16k), Tier 1 (16k-32k), Tier 2 (>32k) with middle-turn compaction', () => {
		// Create a small payload (< 16k)
		const smallContents = [
			{ role: 'user', parts: [{ text: 'Small query' }] },
			{ role: 'model', parts: [{ text: 'Small response' }] }
		];
		const res0 = ContextOptimizer.optimizePayload(smallContents);
		expect(res0.stats.tier).toBe(0);
		expect(res0.prunedContents.length).toBe(2);

		// Create a massive payload (> 32k tokens) with 15 turns
		const hugeTurnText = 'A'.repeat(10000); // ~2,500 tokens per turn
		const hugeContents = Array.from({ length: 15 }, (_, i) => ({
			role: i % 2 === 0 ? 'user' : 'model',
			parts: [{ text: `Turn ${i} content: ${hugeTurnText}` }]
		}));

		const res2 = ContextOptimizer.optimizePayload(hugeContents);
		expect(res2.stats.tier).toBe(2);
		expect(res2.stats.middleCompacted).toBe(true);
		// Turn 0 (User Task) and Turn 1 (First response) preserved, last 8 turns preserved
		expect(res2.prunedContents[0].parts[0].text).toContain('Turn 0');
		expect(res2.prunedContents.some((c: any) => c.parts.some((p: any) => p.text && p.text.includes('Session Milestone Summary')))).toBe(true);
	});
});
