/**
 * Deep Module: ContextOptimizer
 * Consolidates git diff folding, ANSI escape code stripping,
 * 3-pass tool-call dependency pruning, error log tombstoning,
 * AST stacktrace frame pruning, cross-turn hash deduplication,
 * and 3-tier threshold routing behind a single optimizePayload interface.
 */

export interface OptimizationStats {
	originalParts: number;
	finalParts: number;
	expiredRemoved: number;
	duplicatesRemoved: number;
	restoredCount: number;
	savedTokens: number;
	errorsTombstoned: number;
	tier?: number;
	middleCompacted?: boolean;
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
	 * Collapses internal framework stacktrace frames (node_modules, node:internal) in error outputs > 15 lines.
	 */
	static pruneStacktraces(text: string): string {
		if (!text || typeof text !== 'string') return text;
		const lines = text.split('\n');
		if (lines.length <= 15) return text;

		const isStackLine = (line: string) => /^\s*at\s+/.test(line);
		const isInternalFrame = (line: string) =>
			isStackLine(line) &&
			(line.includes('node_modules') ||
				line.includes('node:internal') ||
				line.includes('node:net') ||
				line.includes('node:events'));

		const outputLines: string[] = [];
		let hiddenCount = 0;

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (isInternalFrame(line)) {
				hiddenCount++;
			} else {
				if (hiddenCount > 0) {
					outputLines.push(`    ... [${hiddenCount} internal stack frames hidden for context efficiency] ...`);
					hiddenCount = 0;
				}
				outputLines.push(line);
			}
		}
		if (hiddenCount > 0) {
			outputLines.push(`    ... [${hiddenCount} internal stack frames hidden for context efficiency] ...`);
		}

		return outputLines.join('\n');
	}

	/**
	 * Hashes large text/code blocks (> 200 chars) and replaces duplicate occurrences in later turns with a pointer token.
	 */
	static deduplicateHashes(contents: any[]): { contents: any[]; duplicatesRemoved: number } {
		if (!contents || !Array.isArray(contents)) return { contents: contents || [], duplicatesRemoved: 0 };

		const seenHashes = new Map<string, number>();
		let duplicatesRemoved = 0;

		const fastHash = (str: string) => {
			let hash = 0;
			const norm = str.trim().replace(/\s+/g, ' ');
			for (let i = 0; i < norm.length; i++) {
				hash = (hash << 5) - hash + norm.charCodeAt(i);
				hash |= 0;
			}
			return `h_${Math.abs(hash).toString(16)}`;
		};

		const pruned = contents.map((turn, turnIdx) => {
			if (!turn || !Array.isArray(turn.parts)) return turn;
			const newParts = turn.parts.map((part: any) => {
				if (part && part.text && typeof part.text === 'string') {
					let text = part.text;
					const blocks = text.split(/\n\s*\n/);
					if (blocks.length > 1) {
						const updatedBlocks = blocks.map((block: string) => {
							const trimmed = block.trim();
							if (trimmed.length >= 200) {
								const h = fastHash(trimmed);
								if (seenHashes.has(h)) {
									const prevTurnIdx = seenHashes.get(h)!;
									duplicatesRemoved++;
									return `[System Pruner: Duplicate text removed. Identical to block in Turn ${prevTurnIdx + 1} (Hash: #${h})]`;
								} else {
									seenHashes.set(h, turnIdx);
								}
							}
							return block;
						});
						return { ...part, text: updatedBlocks.join('\n\n') };
					} else if (text.trim().length >= 200) {
						const trimmed = text.trim();
						const h = fastHash(trimmed);
						if (seenHashes.has(h)) {
							const prevTurnIdx = seenHashes.get(h)!;
							duplicatesRemoved++;
							return {
								...part,
								text: `[System Pruner: Duplicate text removed. Identical to block in Turn ${prevTurnIdx + 1} (Hash: #${h})]`
							};
						} else {
							seenHashes.set(h, turnIdx);
						}
					}
				}
				return part;
			});
			return { ...turn, parts: newParts };
		});

		return { contents: pruned, duplicatesRemoved };
	}

	/**
	 * Compacts middle turns for Tier 2 (> 32k tokens), keeping Turn 0, Turn 1, and the last 8 turns intact.
	 */
	static compactMiddleTurns(contents: any[]): { contents: any[]; middleCompacted: boolean } {
		if (!contents || contents.length <= 10) {
			return { contents: contents || [], middleCompacted: false };
		}

		const head = contents.slice(0, 2);
		const tail = contents.slice(-8);

		const summaryTurn = {
			role: 'model',
			parts: [
				{
					text: `[Session Milestone Summary (Middle Turns 2-${contents.length - 8} Compacted for Token Efficiency): Active working state and recent conversation history preserved in turns below.]`
				}
			]
		};

		return {
			contents: [...head, summaryTurn, ...tail],
			middleCompacted: true
		};
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
				if (line.startsWith('@@') && chunkLines.length > 0) {
					flushChunk(chunkLines);
					chunkLines = [];
				}
				chunkLines.push(line);
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
			}
			if (inDiff) {
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
	 * Compacts a single part (text, functionCall, or functionResponse).
	 */
	static compactPart(part: any): any {
		if (!part) return part;

		if (part.text && typeof part.text === 'string') {
			let text = this.stripAnsi(part.text);
			text = this.compactGitDiff(text);
			text = this.pruneStacktraces(text);
			return { ...part, text };
		}

		if (part.functionResponse && part.functionResponse.response) {
			const res = part.functionResponse.response;
			if (res.output && typeof res.output === 'string') {
				let output = this.stripAnsi(res.output);
				output = this.compactGitDiff(output);
				output = this.pruneStacktraces(output);
				return {
					...part,
					functionResponse: {
						...part.functionResponse,
						response: { ...res, output }
					}
				};
			}
		}

		return part;
	}

	/**
	 * Checks if a function response indicates execution failure.
	 */
	static isFailureResponse(responseObj: any, responseStr: string): boolean {
		if (!responseObj) return false;
		if (responseObj.failed === true) return true;
		if (typeof responseObj.exitCode === 'number' && responseObj.exitCode !== 0) return true;
		if (responseObj.error) return true;

		const lower = responseStr.toLowerCase();
		if (
			lower.includes('error:') ||
			lower.includes('command failed') ||
			lower.includes('no such file') ||
			lower.includes('failed with status')
		) {
			return true;
		}

		return false;
	}

	/**
	 * Main entry point: optimizes conversation history using 3-tier dynamic routing.
	 */
	static optimizePayload(contents: any[], options?: { forceTier?: number }): OptimizationResult {
		if (!contents || !Array.isArray(contents)) {
			return {
				prunedContents: contents || [],
				stats: {
					originalParts: 0,
					finalParts: 0,
					expiredRemoved: 0,
					duplicatesRemoved: 0,
					restoredCount: 0,
					savedTokens: 0,
					errorsTombstoned: 0,
					tier: 0,
					middleCompacted: false
				},
				tokensEstimated: 0
			};
		}

		const originalTokens = this.estimateTokens(contents);
		let targetTier = 0;
		if (options?.forceTier !== undefined) {
			targetTier = options.forceTier;
		} else if (originalTokens >= 32000) {
			targetTier = 2;
		} else if (originalTokens >= 16000) {
			targetTier = 1;
		}

		let workingContents = contents;

		// Apply Tier 2 Middle-Turn Compaction if >= 32k
		let middleCompacted = false;
		if (targetTier === 2) {
			const compactRes = this.compactMiddleTurns(workingContents);
			workingContents = compactRes.contents;
			middleCompacted = compactRes.middleCompacted;
		}

		let originalPartsCount = 0;
		for (const turn of workingContents) {
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

		for (let i = 0; i < workingContents.length; i++) {
			const turn = workingContents[i];
			if (!turn || !Array.isArray(turn.parts)) continue;

			for (let j = 0; j < turn.parts.length; j++) {
				const part = turn.parts[j];
				if (part && part.functionCall) {
					const name = part.functionCall.name;
					const args = part.functionCall.args || {};

					let matchFound = false;
					for (let k = i + 1; k < workingContents.length; k++) {
						const resTurn = workingContents[k];
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

		// Pass 2: Duplicate Text Removal
		const seenText = new Set<string>();
		const duplicateParts = new Map<string, string>();
		let duplicateTextCount = 0;

		for (let i = 0; i < workingContents.length; i++) {
			const turn = workingContents[i];
			if (!turn || !Array.isArray(turn.parts)) continue;

			for (let j = 0; j < turn.parts.length; j++) {
				const part = turn.parts[j];
				if (part && part.text && typeof part.text === 'string') {
					if (part.text.length > 200) {
						const norm = part.text.toLowerCase().replace(/\s+/g, ' ').trim();
						if (seenText.has(norm)) {
							duplicateParts.set(`${i}:${j}`, "[System Pruner: Duplicate text removed. Use 'read' offset/limit to re-inspect if needed.]");
							duplicateTextCount++;
						} else {
							seenText.add(norm);
						}
					}
				}
			}
		}

		// Pass 3: Dependency Restoration
		let survivingTextConcat = '';
		for (let i = 0; i < workingContents.length; i++) {
			const turn = workingContents[i];
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
		for (let i = 0; i < pairs.length; i++) {
			const pair = pairs[i];
			if (removedParts.has(`${pair.callTurnIdx}:${pair.callPartIdx}`)) {
				let shouldRestore = false;
				const pathKey = pair.args?.path || pair.args?.filename || pair.args?.command || pair.args?.query;
				if (pathKey) {
					const baseName = pathKey.includes('/') ? pathKey.split('/').pop() : pathKey;
					if (
						survivingTextConcat.includes(pathKey) ||
						(baseName && baseName.length > 3 && survivingTextConcat.includes(baseName))
					) {
						shouldRestore = true;
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
			const resPart = workingContents[pair.resTurnIdx].parts[pair.resPartIdx];
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

			const resPart = workingContents[pair.resTurnIdx].parts[pair.resPartIdx];
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

					if (!shouldTombstone && originalTokens > 20000 && (workingContents.length - pair.resTurnIdx > 8)) {
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

		// Build final pruned contents
		const prunedContents: any[] = [];
		let finalPartsCount = 0;

		for (let i = 0; i < workingContents.length; i++) {
			const turn = workingContents[i];
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

		// Apply Hash Deduplication on final pruned contents
		const dedupRes = this.deduplicateHashes(prunedContents);
		const finalPrunedContents = dedupRes.contents;
		const duplicatesRemoved = duplicateTextCount + dedupRes.duplicatesRemoved;

		return {
			prunedContents: finalPrunedContents,
			stats: {
				originalParts: originalPartsCount,
				finalParts: finalPartsCount,
				expiredRemoved: Math.max(0, expiredRemoved - restoredCount),
				duplicatesRemoved,
				restoredCount,
				savedTokens,
				errorsTombstoned,
				tier: targetTier,
				middleCompacted
			},
			tokensEstimated: prunedTokens
		};
	}
}
