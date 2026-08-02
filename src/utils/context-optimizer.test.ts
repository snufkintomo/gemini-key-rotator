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
});
