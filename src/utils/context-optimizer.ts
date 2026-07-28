/**
 * Deep Module: ContextOptimizer
 * Consolidates git diff folding, ANSI escape code stripping,
 * 3-pass tool-call dependency pruning, error log tombstoning,
 * and token estimation behind a single optimizePayload interface.
 */

export interface OptimizationStats {
	originalParts: number;
	finalParts: number;
	expiredRemoved: number;
	duplicatesRemoved: number;
	restoredCount: number;
	savedTokens: number;
	errorsTombstoned: number;
}

export interface OptimizationResult {
	prunedContents: any[];
	stats: OptimizationStats;
	tokensEstimated: number;
}

export class ContextOptimizer {
	/**
	 * Estimates token count for Gemini contents array (approx. 4 characters per token).
	 */
	static estimateTokens(contents: any[]): number {
		let chars = 0;
		if (!contents || !Array.isArray(contents)) return 0;
		for (const turn of contents) {
			if (turn && Array.isArray(turn.parts)) {
				for (const part of turn.parts) {
					if (part.text) {
						chars += part.text.length;
					} else if (part.functionCall) {
						chars += JSON.stringify(part.functionCall).length;
					} else if (part.functionResponse) {
						chars += JSON.stringify(part.functionResponse).length;
					}
				}
			}
		}
		return Math.ceil(chars / 4);
	}

	/**
	 * Strips ANSI terminal escape sequences.
	 */
	static stripAnsi(text: string): string {
		if (!text || typeof text !== 'string') return text;
		return text.replace(/[\u001b\x1b]\[[0-9;]*[a-zA-Z]/g, '');
	}

	/**
	 * Folds unchanged context lines in large `diff --git` outputs to conserve tokens.
	 */
	static compactGitDiff(text: string): string {
		if (!text || typeof text !== 'string') return text;
		if (!text.includes('diff --git')) return text;

		const lines = text.split('\n');
		const outputLines: string[] = [];
		let inDiff = false;
		let diffBuffer: string[] = [];

		const processDiffBuffer = (buf: string[]) => {
			if (buf.length === 0) return [];
			const processed: string[] = [];
			let chunkLines: string[] = [];

			const flushChunk = (linesInChunk: string[]) => {
				if (linesInChunk.length === 0) return;
				const isModified = linesInChunk.map(
					(line) => line.startsWith('+') || line.startsWith('-')
				);

				const keep = new Array(linesInChunk.length).fill(false);
				for (let i = 0; i < linesInChunk.length; i++) {
					if (isModified[i]) {
						for (
							let k = Math.max(0, i - 6);
							k <= Math.min(linesInChunk.length - 1, i + 6);
							k++
						) {
							keep[k] = true;
						}
					}
				}

				for (let i = 0; i < linesInChunk.length; i++) {
					const line = linesInChunk[i];
					if (
						line.startsWith('@@') ||
						line.startsWith('diff --git') ||
						line.startsWith('index ') ||
						line.startsWith('---') ||
						line.startsWith('+++')
					) {
						keep[i] = true;
					}
				}

				let foldedCount = 0;
				for (let i = 0; i < linesInChunk.length; i++) {
					if (keep[i]) {
						if (foldedCount > 0) {
							processed.push(
								`... [${foldedCount} lines of unchanged context folded to save tokens] ...`
							);
							foldedCount = 0;
						}
						processed.push(linesInChunk[i]);
					} else {
						foldedCount++;
					}
				}
				if (foldedCount > 0) {
					processed.push(
						`... [${foldedCount} lines of unchanged context folded to save tokens] ...`
					);
				}
			};

			for (const line of buf) {
				if (line.startsWith('@@')) {
					flushChunk(chunkLines);
					chunkLines = [line];
				} else if (line.startsWith('diff --git')) {
					flushChunk(chunkLines);
					chunkLines = [line];
				} else {
					chunkLines.push(line);
				}
			}
			flushChunk(chunkLines);
			return processed;
		};

		for (const line of lines) {
			if (line.startsWith('diff --git')) {
				if (inDiff) {
					outputLines.push(...processDiffBuffer(diffBuffer));
					diffBuffer = [];
				}
				inDiff = true;
				diffBuffer.push(line);
			} else if (inDiff) {
				diffBuffer.push(line);
			} else {
				outputLines.push(line);
			}
		}
		if (inDiff) {
			outputLines.push(...processDiffBuffer(diffBuffer));
		}

		return outputLines.join('\n');
	}

	/**
	 * Determines if a tool response object represents an execution failure.
	 */
	static isFailureResponse(responseObj: any, responseStr: string): boolean {
		if (responseObj && (responseObj.error || responseObj.failed || (responseObj.exitCode !== undefined && responseObj.exitCode !== 0))) {
			return true;
		}
		const lowerStr = responseStr.toLowerCase();
		if (responseStr.length > 300 && (
			lowerStr.includes('error') ||
			lowerStr.includes('failed') ||
			lowerStr.includes('exception') ||
			lowerStr.includes('npm err!') ||
			lowerStr.includes('module not found') ||
			lowerStr.includes('typescript error') ||
			lowerStr.includes('stderr')
		)) {
			return true;
		}
		return false;
	}
	static compactPart(part: any): any {
		if (!part) return part;
		let updated = { ...part };
		if (updated.text && typeof updated.text === 'string') {
			updated.text = this.stripAnsi(updated.text);
			updated.text = this.compactGitDiff(updated.text);
		}
		if (updated.functionResponse && updated.functionResponse.response) {
			const res = updated.functionResponse.response;
			if (typeof res === 'object') {
				let updatedRes = { ...res };
				if (updatedRes.stdout && typeof updatedRes.stdout === 'string') {
					updatedRes.stdout = this.stripAnsi(updatedRes.stdout);
					updatedRes.stdout = this.compactGitDiff(updatedRes.stdout);
				}
				if (updatedRes.output && typeof updatedRes.output === 'string') {
					updatedRes.output = this.stripAnsi(updatedRes.output);
					updatedRes.output = this.compactGitDiff(updatedRes.output);
				}
				if (updatedRes.response && typeof updatedRes.response === 'string') {
					updatedRes.response = this.stripAnsi(updatedRes.response);
					updatedRes.response = this.compactGitDiff(updatedRes.response);
				}
				updated = {
					...updated,
					functionResponse: {
						...updated.functionResponse,
						response: updatedRes
					}
				};
			}
		}
		return updated;
	}

	/**
	 * Optimizes the input Gemini contents payload by running multi-pass dependency analysis,
	 * expired tool-call elimination, duplicate text folding, error tombstoning, and token estimation.
	 */
	static optimizePayload(contents: any[]): OptimizationResult {
		if (!contents || !Array.isArray(contents) || contents.length === 0) {
			return {
				prunedContents: contents || [],
				stats: {
					originalParts: 0,
					finalParts: 0,
					expiredRemoved: 0,
					duplicatesRemoved: 0,
					restoredCount: 0,
					savedTokens: 0,
					errorsTombstoned: 0
				},
				tokensEstimated: 0
			};
		}

		const originalTokens = this.estimateTokens(contents);

		let originalPartsCount = 0;
		for (const turn of contents) {
			if (turn && Array.isArray(turn.parts)) {
				originalPartsCount += turn.parts.length;
			}
		}

		const removedParts = new Set<string>();

		interface ToolCallPair {
			callTurnIdx: number;
			callPartIdx: number;
			resTurnIdx: number;
			resPartIdx: number;
			name: string;
			args: any;
			resourceKey: string;
		}
		const pairs: ToolCallPair[] = [];

		for (let i = 0; i < contents.length; i++) {
			const turn = contents[i];
			if (!turn || !Array.isArray(turn.parts)) continue;

			for (let j = 0; j < turn.parts.length; j++) {
				const part = turn.parts[j];
				if (part && part.functionCall) {
					const name = part.functionCall.name;
					const args = part.functionCall.args || {};

					let matchFound = false;
					for (let k = i + 1; k < contents.length; k++) {
						const resTurn = contents[k];
						if (!resTurn || !Array.isArray(resTurn.parts)) continue;

						for (let l = 0; l < resTurn.parts.length; l++) {
							const resPart = resTurn.parts[l];
							if (resPart && resPart.functionResponse && resPart.functionResponse.name === name) {
								let resourceKey = name;
								const keyProp = args.path || args.filename || args.command || args.query || args.id;
								if (keyProp) {
									resourceKey = `${name}::${keyProp}`;
								} else {
									resourceKey = `${name}::${JSON.stringify(args)}`;
								}

								pairs.push({
									callTurnIdx: i,
									callPartIdx: j,
									resTurnIdx: k,
									resPartIdx: l,
									name,
									args,
									resourceKey
								});
								matchFound = true;
								break;
							}
						}
						if (matchFound) break;
					}
				}
			}
		}

		// Pass 1: Expired Context Elimination
		const latestPairIdx = new Map<string, number>();
		for (let i = 0; i < pairs.length; i++) {
			latestPairIdx.set(pairs[i].resourceKey, i);
		}

		let expiredRemoved = 0;
		for (let i = 0; i < pairs.length; i++) {
			const pair = pairs[i];
			if (latestPairIdx.get(pair.resourceKey) !== i) {
				removedParts.add(`${pair.callTurnIdx}:${pair.callPartIdx}`);
				removedParts.add(`${pair.resTurnIdx}:${pair.resPartIdx}`);
				expiredRemoved += 2;
			}
		}

		// Pass 2: Duplicate Context Elimination
		const seenText = new Set<string>();
		const duplicateParts = new Map<string, string>();
		let duplicatesRemoved = 0;

		for (let i = 0; i < contents.length; i++) {
			const turn = contents[i];
			if (!turn || !Array.isArray(turn.parts)) continue;

			for (let j = 0; j < turn.parts.length; j++) {
				const part = turn.parts[j];
				if (part && part.text && typeof part.text === 'string') {
					if (part.text.length > 200) {
						const norm = part.text.toLowerCase().replace(/\s+/g, ' ').trim();
						if (seenText.has(norm)) {
							duplicateParts.set(`${i}:${j}`, "[System Pruner: Duplicate text removed. Use 'read' offset/limit to re-inspect if needed.]");
							duplicatesRemoved++;
						} else {
							seenText.add(norm);
						}
					}
				}
			}
		}

		// Pass 3: Dependency Restoration
		let survivingTextConcat = '';
		for (let i = 0; i < contents.length; i++) {
			const turn = contents[i];
			if (!turn || !Array.isArray(turn.parts)) continue;

			for (let j = 0; j < turn.parts.length; j++) {
				if (!removedParts.has(`${i}:${j}`)) {
					const part = turn.parts[j];
					if (part && part.text) {
						survivingTextConcat += ' ' + part.text;
					}
				}
			}
		}

		let restoredCount = 0;
		for (const pair of pairs) {
			const callKey = `${pair.callTurnIdx}:${pair.callPartIdx}`;
			if (removedParts.has(callKey)) {
				let shouldRestore = false;
				if (pair.args && typeof pair.args === 'object') {
					const pathValue = pair.args.path || pair.args.filename;
					if (pathValue && typeof pathValue === 'string') {
						const basename = pathValue.split('/').pop() || pathValue;
						if (survivingTextConcat.includes(pathValue) || survivingTextConcat.includes(basename)) {
							shouldRestore = true;
						}
					}
					if (pair.args.command && typeof pair.args.command === 'string') {
						if (survivingTextConcat.includes(pair.args.command)) {
							shouldRestore = true;
						}
					}
				}

				if (shouldRestore) {
					removedParts.delete(`${pair.callTurnIdx}:${pair.callPartIdx}`);
					removedParts.delete(`${pair.resTurnIdx}:${pair.resPartIdx}`);
					restoredCount += 2;
				}
			}
		}

		// Pass 4: Error Log Tombstoning
		const tombstonedResponses = new Map<string, any>();
		let errorsTombstoned = 0;

		const latestSuccessPairIdx = new Map<string, number>();
		for (let k = 0; k < pairs.length; k++) {
			const pair = pairs[k];
			const resPart = contents[pair.resTurnIdx].parts[pair.resPartIdx];
			if (resPart && resPart.functionResponse) {
				const responseObj = resPart.functionResponse.response;
				const responseStr = JSON.stringify(responseObj || {});

				const isFailure = ContextOptimizer.isFailureResponse(responseObj, responseStr);

				if (!isFailure) {
					latestSuccessPairIdx.set(pair.resourceKey, k);
				}
			}
		}

		for (let k = 0; k < pairs.length; k++) {
			const pair = pairs[k];
			const resKey = `${pair.resTurnIdx}:${pair.resPartIdx}`;

			if (removedParts.has(resKey)) continue;

			const resPart = contents[pair.resTurnIdx].parts[pair.resPartIdx];
			if (resPart && resPart.functionResponse) {
				const responseObj = resPart.functionResponse.response;
				const responseStr = JSON.stringify(responseObj || {});

				const isFailure = ContextOptimizer.isFailureResponse(responseObj, responseStr);

				if (isFailure) {
					let shouldTombstone = false;

					const successIdx = latestSuccessPairIdx.get(pair.resourceKey);
					if (successIdx !== undefined && successIdx > k) {
						shouldTombstone = true;
					}

					if (!shouldTombstone && originalTokens > 20000 && (contents.length - pair.resTurnIdx > 8)) {
						shouldTombstone = true;
					}

					if (shouldTombstone) {
						tombstonedResponses.set(resKey, {
							output: "[System Pruner: Old build/runtime error log removed. Subsequent run of this command succeeded.]",
							error: null,
							failed: false,
							exitCode: 0
						});
						errorsTombstoned++;
					}
				}
			}
		}

		// Build final pruned contents with merged adjacent roles
		const prunedContents: any[] = [];
		let finalPartsCount = 0;

		for (let i = 0; i < contents.length; i++) {
			const turn = contents[i];
			if (!turn || !Array.isArray(turn.parts)) continue;

			const survivingParts: any[] = [];
			for (let j = 0; j < turn.parts.length; j++) {
				if (!removedParts.has(`${i}:${j}`)) {
					let part = turn.parts[j];
					const key = `${i}:${j}`;
					if (duplicateParts.has(key)) {
						part = { ...part, text: duplicateParts.get(key) };
					} else if (tombstonedResponses.has(key)) {
						part = {
							...part,
							functionResponse: {
								...part.functionResponse,
								response: tombstonedResponses.get(key)
							}
						};
					}
					part = this.compactPart(part);
					survivingParts.push(part);
				}
			}

			if (survivingParts.length > 0) {
				finalPartsCount += survivingParts.length;
				const role = turn.role || 'user';
				if (prunedContents.length > 0 && prunedContents[prunedContents.length - 1].role === role) {
					prunedContents[prunedContents.length - 1].parts.push(...survivingParts);
				} else {
					prunedContents.push({
						role,
						parts: survivingParts
					});
				}
			}
		}

		const prunedTokens = this.estimateTokens(prunedContents);
		const savedTokens = Math.max(0, originalTokens - prunedTokens);

		return {
			prunedContents,
			stats: {
				originalParts: originalPartsCount,
				finalParts: finalPartsCount,
				expiredRemoved: Math.max(0, expiredRemoved - restoredCount),
				duplicatesRemoved,
				restoredCount,
				savedTokens,
				errorsTombstoned
			},
			tokensEstimated: prunedTokens
		};
	}
}
