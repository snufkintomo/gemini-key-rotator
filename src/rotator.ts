import { ApiCredentials, KeyState } from './types';
import {
	handleModels,
	parseRequestModel,
	resolveModelAndAuthMode,
} from './utils/models';
import { handleOpenAI, handleEmbeddings } from './utils/openai';
import { handleClaude } from './utils/claude';
import { handleGemini } from './utils/gemini';
import { proxyRequest } from './utils/proxy';
import { SystemContext } from './utils/context';
import { createErrorResponse, Protocol, JSON_HEADERS } from './utils/errors';
import { StorageHelper } from './utils/storage';
import { getStandardRotationIndex, parseCredentials, parseCsvList } from './utils/credentials';
import { sendInvalidTokenEmail, sendExhaustedEmail } from './utils/email';
import { getOAuthAccessToken, parseOAuthCredentials, discoverProjectId, saveDiscoveredProjectId, fetchAvailableModelsForToken } from './utils/oauth';
import { writeCombinedLog } from './utils/logger';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// --- Types ---
export interface Env {
	DB: D1Database;
	GEMINI_API_BASE_URL?: string;
	OAUTH_CLIENT_ID?: string;
	OAUTH_CLIENT_SECRET?: string;
	CLOUDFLARE_AI_GATEWAY_ID: string;
	CLOUDFLARE_AI_GATEWAY_NAME: string;
	ENABLE_API_LOGGING?: string;
	ENABLE_CLOUDFLARE_AI_GATEWAY?: string;
	ENABLE_ORG_GEMINI_API_BASE_URL?: string;
	ENABLE_USAGE_STATISTICS?: string;
	NOTIFICATION_EMAIL?: string;
	RESEND_API_KEY?: string;
	UPSTREAM_TIMEOUT_MS?: string;
}

export class KeyRotator {
	ctx: SystemContext;
	storage: StorageHelper;
	requestCountSinceSync = 0;
	lastCleanupTime = 0;

	// Caching properties
	private cachedCredentials: ApiCredentials | null = null;
	private cacheTimestamp = 0;
	private readonly CACHE_TTL = 3600000; // 1 hour Cache TTL
	private isPrefetching = false; // Lock flag to prevent redundant prefetching
	private readonly PREFETCH_THRESHOLD = 300000; // 5 minutes (in ms) to prefetch before expiration
	private sessionKeyMap = new Map<string, string>();
	private inMemoryStats: any[] = [];

	private setSessionKey(sessionId: string, apiKey: string) {
		if (this.sessionKeyMap.size >= 2000) {
			const oldestKey = this.sessionKeyMap.keys().next().value;
			if (oldestKey !== undefined) {
				this.sessionKeyMap.delete(oldestKey);
			}
		}
		this.sessionKeyMap.set(sessionId, apiKey);
	}

	// In-memory index tracking for perfect round-robin under high load
	private cachedGeminiApiBaseUrls: string[] | null = null;
	private currentKeyIndex: number | undefined = undefined;
	private currentOauthIndex: number | undefined = undefined;
	private currentAntigravityIndex: number | undefined = undefined;
	private initPromise: Promise<void> | null = null;

	private async ensureInitialized(userAccessToken: string, dbKeyIndex: number, dbOauthIndex: number, dbAntigravityIndex: number = 0) {
		if (!this.ctx.env.DB) {
			throw new Error("D1 Database binding 'DB' is missing in wrangler config or environment.");
		}
		if (this.currentKeyIndex !== undefined && this.currentOauthIndex !== undefined && this.currentAntigravityIndex !== undefined) {
			return;
		}
		if (!this.initPromise) {
			this.initPromise = (async () => {
				let keyIndex = await this.storage.getUserKeyIndex(userAccessToken);
				if (keyIndex === undefined) {
					keyIndex = dbKeyIndex;
					await this.storage.setUserKeyIndex(userAccessToken, keyIndex);
				}
				this.currentKeyIndex = keyIndex;

				let oauthIndex = await this.storage.getUserOauthIndex(userAccessToken);
				if (oauthIndex === undefined) {
					oauthIndex = dbOauthIndex;
					await this.storage.setUserOauthIndex(userAccessToken, oauthIndex);
				}
				this.currentOauthIndex = oauthIndex;

				let antigravityIndex = await this.storage.get<number>(`antigravity_index_${userAccessToken}`);
				if (antigravityIndex === undefined) {
					antigravityIndex = dbAntigravityIndex;
					await this.storage.put(`antigravity_index_${userAccessToken}`, antigravityIndex);
				}
				this.currentAntigravityIndex = antigravityIndex;

				let syncCount = await this.storage.get<number>(`sync_count_${userAccessToken}`);
				this.requestCountSinceSync = syncCount || 0;
			})();
		}
		await this.initPromise;
	}

	constructor(state: DurableObjectState, env: Env) {
		this.ctx = new SystemContext(state, env);
		this.storage = new StorageHelper(state.storage);
		this.initDatabase();
	}

	private initDatabase() {
		try {
			const db = this.ctx.state.storage.sql;
			if (!db) {
				console.warn("Durable Object Local SQLite not supported or not mocked in this environment.");
				return;
			}
			db.exec(`
				CREATE TABLE IF NOT EXISTS exact_match_cache (
					hash TEXT PRIMARY KEY,
					response TEXT,
					expires_at INTEGER
				)
			`);
			db.exec(`
				CREATE TABLE IF NOT EXISTS gemini_context_caches (
					hash TEXT PRIMARY KEY,
					gemini_cache_id TEXT,
					api_key TEXT,
					model TEXT,
					expires_at INTEGER
				)
			`);
			// Create indexes for fast lookup
			db.exec(`CREATE INDEX IF NOT EXISTS idx_exact_match_expires ON exact_match_cache(expires_at)`);
			db.exec(`CREATE INDEX IF NOT EXISTS idx_gemini_context_expires ON gemini_context_caches(expires_at)`);
		} catch (e) {
			console.error("Failed to initialize Durable Object Local SQLite database:", e);
		}
	}

	getExactMatchCache(hash: string): any | null {
		try {
			const db = this.ctx.state.storage.sql;
			if (!db) return null;
			const cursor = db.exec(`SELECT response, expires_at FROM exact_match_cache WHERE hash = ?`, hash);
			const row = cursor.next().value;
			if (row) {
				const expiresAt = row.expires_at as number;
				const responseStr = row.response as string;
				if (expiresAt && Date.now() < expiresAt) {
					return JSON.parse(responseStr);
				} else {
					// Expired: delete it asynchronously
					this.ctx.state.waitUntil((async () => {
						try {
							db.exec(`DELETE FROM exact_match_cache WHERE hash = ?`, hash);
						} catch (e) {}
					})());
				}
			}
		} catch (e) {
			console.error("Error reading exact match cache from DO SQLite:", e);
		}
		return null;
	}

	setExactMatchCache(hash: string, responseObj: any, ttlMs: number) {
		try {
			const db = this.ctx.state.storage.sql;
			if (!db) return;
			const expiresAt = Date.now() + ttlMs;
			db.exec(
				`INSERT OR REPLACE INTO exact_match_cache (hash, response, expires_at) VALUES (?, ?, ?)`,
				hash,
				JSON.stringify(responseObj),
				expiresAt
			);
		} catch (e) {
			console.error("Error writing exact match cache to DO SQLite:", e);
		}
	}

	getGeminiContextCache(hash: string, model: string): { gemini_cache_id: string; api_key: string } | null {
		try {
			const db = this.ctx.state.storage.sql;
			if (!db) return null;
			const cursor = db.exec(
				`SELECT gemini_cache_id, api_key, expires_at FROM gemini_context_caches WHERE hash = ? AND model = ?`,
				hash,
				model
			);
			const row = cursor.next().value;
			if (row) {
				const expiresAt = row.expires_at as number;
				const geminiCacheId = row.gemini_cache_id as string;
				const apiKey = row.api_key as string;
				if (expiresAt && Date.now() < expiresAt) {
					return { gemini_cache_id: geminiCacheId, api_key: apiKey };
				} else {
					// Expired: delete it
					this.ctx.state.waitUntil((async () => {
						try {
							db.exec(`DELETE FROM gemini_context_caches WHERE hash = ? AND model = ?`, hash, model);
						} catch (e) {}
					})());
				}
			}
		} catch (e) {
			console.error("Error reading Gemini context cache from DO SQLite:", e);
		}
		return null;
	}

	setGeminiContextCache(hash: string, model: string, geminiCacheId: string, apiKey: string, ttlMs: number) {
		try {
			const db = this.ctx.state.storage.sql;
			if (!db) return;
			const expiresAt = Date.now() + ttlMs;
			db.exec(
				`INSERT OR REPLACE INTO gemini_context_caches (hash, gemini_cache_id, api_key, model, expires_at) VALUES (?, ?, ?, ?, ?)`,
				hash,
				geminiCacheId,
				apiKey,
				model,
				expiresAt
			);
		} catch (e) {
			console.error("Error writing Gemini context cache to DO SQLite:", e);
		}
	}

	estimateGeminiTokens(contents: any[]): number {
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
		return Math.ceil(chars / 4); // 4 chars per token average
	}

	compactGitDiff(text: string): string {
		if (!text || typeof text !== "string") return text;
		if (!text.includes("diff --git")) return text;

		const lines = text.split("\n");
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
					(line) => line.startsWith("+") || line.startsWith("-")
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
						line.startsWith("@@") ||
						line.startsWith("diff --git") ||
						line.startsWith("index ") ||
						line.startsWith("---") ||
						line.startsWith("+++")
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
				if (line.startsWith("@@")) {
					flushChunk(chunkLines);
					chunkLines = [line];
				} else if (line.startsWith("diff --git")) {
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
			if (line.startsWith("diff --git")) {
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

		return outputLines.join("\n");
	}

	stripAnsi(text: string): string {
		if (!text || typeof text !== "string") return text;
		return text.replace(/[\u001b\x1b]\[[0-9;]*[a-zA-Z]/g, "");
	}

	compactPart(part: any): any {
		if (!part) return part;
		let updated = { ...part };
		if (updated.text && typeof updated.text === "string") {
			updated.text = this.stripAnsi(updated.text);
			updated.text = this.compactGitDiff(updated.text);
		}
		if (updated.functionResponse && updated.functionResponse.response) {
			const res = updated.functionResponse.response;
			if (typeof res === "object") {
				let updatedRes = { ...res };
				if (updatedRes.stdout && typeof updatedRes.stdout === "string") {
					updatedRes.stdout = this.stripAnsi(updatedRes.stdout);
					updatedRes.stdout = this.compactGitDiff(updatedRes.stdout);
				}
				if (updatedRes.output && typeof updatedRes.output === "string") {
					updatedRes.output = this.stripAnsi(updatedRes.output);
					updatedRes.output = this.compactGitDiff(updatedRes.output);
				}
				if (updatedRes.response && typeof updatedRes.response === "string") {
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

	pruneGeminiContents(contents: any[]): {
		prunedContents: any[];
		stats: {
			originalParts: number;
			finalParts: number;
			expiredRemoved: number;
			duplicatesRemoved: number;
			restoredCount: number;
			savedTokens: number;
			errorsTombstoned: number;
		};
	} {
		if (!contents || !Array.isArray(contents) || contents.length === 0) {
			return {
				prunedContents: contents,
				stats: { originalParts: 0, finalParts: 0, expiredRemoved: 0, duplicatesRemoved: 0, restoredCount: 0, savedTokens: 0, errorsTombstoned: 0 }
			};
		}

		const originalTokens = this.estimateGeminiTokens(contents);

		let originalPartsCount = 0;
		for (const turn of contents) {
			if (turn && Array.isArray(turn.parts)) {
				originalPartsCount += turn.parts.length;
			}
		}

		// Set to keep track of turnIndex:partIndex marked for removal
		const removedParts = new Set<string>();

		// Let's identify functionCall / functionResponse pairs (Pass 1)
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

					// Look for matching response in subsequent turns
					let matchFound = false;
					for (let k = i + 1; k < contents.length; k++) {
						const resTurn = contents[k];
						if (!resTurn || !Array.isArray(resTurn.parts)) continue;

						for (let l = 0; l < resTurn.parts.length; l++) {
							const resPart = resTurn.parts[l];
							if (resPart && resPart.functionResponse && resPart.functionResponse.name === name) {
								// Found pair!
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
		// Map resourceKey -> latest pair index in the pairs list
		const latestPairIdx = new Map<string, number>();
		for (let i = 0; i < pairs.length; i++) {
			latestPairIdx.set(pairs[i].resourceKey, i);
		}

		let expiredRemoved = 0;
		for (let i = 0; i < pairs.length; i++) {
			const pair = pairs[i];
			if (latestPairIdx.get(pair.resourceKey) !== i) {
				// This is an older, expired pair! Mark for removal
				removedParts.add(`${pair.callTurnIdx}:${pair.callPartIdx}`);
				removedParts.add(`${pair.resTurnIdx}:${pair.resPartIdx}`);
				expiredRemoved += 2;
			}
		}

		// Pass 2: Duplicate Context Elimination (RAG docs or text duplication)
		const seenText = new Set<string>();
		const duplicateParts = new Map<string, string>();
		let duplicatesRemoved = 0;

		for (let i = 0; i < contents.length; i++) {
			const turn = contents[i];
			if (!turn || !Array.isArray(turn.parts)) continue;

			for (let j = 0; j < turn.parts.length; j++) {
				const part = turn.parts[j];
				if (part && part.text && typeof part.text === 'string') {
					// We only collapse larger blocks (e.g., >200 characters)
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
		// First, compile all text from surviving parts (including duplicates that have tombstone strings)
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
		// Check expired pairs to see if they are referenced
		for (const pair of pairs) {
			const callKey = `${pair.callTurnIdx}:${pair.callPartIdx}`;
			if (removedParts.has(callKey)) {
				let shouldRestore = false;
				if (pair.args && typeof pair.args === 'object') {
					const pathValue = pair.args.path || pair.args.filename;
					if (pathValue && typeof pathValue === 'string') {
						const basename = pathValue.split('/').pop() || pathValue;
						// If user explicitly mentions the path or file name in surviving messages, restore it!
						if (survivingTextConcat.includes(pathValue) || survivingTextConcat.includes(basename)) {
							shouldRestore = true;
						}
					}
					// Also restore if command is referenced
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

		// Pass 4: Error Log Tombstoning (Tombstone old/superseded build & runtime failures)
		const tombstonedResponses = new Map<string, any>();
		let errorsTombstoned = 0;

		// 1. Identify which resource keys have a successful tool output later in history
		const latestSuccessPairIdx = new Map<string, number>();
		for (let k = 0; k < pairs.length; k++) {
			const pair = pairs[k];
			const resPart = contents[pair.resTurnIdx].parts[pair.resPartIdx];
			if (resPart && resPart.functionResponse) {
				const responseObj = resPart.functionResponse.response;
				const responseStr = JSON.stringify(responseObj || {});
				
				let isFailure = false;
				if (responseObj && (responseObj.error || responseObj.failed || (responseObj.exitCode !== undefined && responseObj.exitCode !== 0))) {
					isFailure = true;
				} else {
					const lowerStr = responseStr.toLowerCase();
					if (responseStr.length > 300 && (
						lowerStr.includes("error") || 
						lowerStr.includes("failed") || 
						lowerStr.includes("exception") || 
						lowerStr.includes("npm err!") || 
						lowerStr.includes("module not found") || 
						lowerStr.includes("typescript error") || 
						lowerStr.includes("stderr")
					)) {
						isFailure = true;
					}
				}

				if (!isFailure) {
					latestSuccessPairIdx.set(pair.resourceKey, k);
				}
			}
		}

		// 2. Scan pairs for failed executions and apply tombstoning rules
		for (let k = 0; k < pairs.length; k++) {
			const pair = pairs[k];
			const resKey = `${pair.resTurnIdx}:${pair.resPartIdx}`;
			
			// If already removed by Pass 1, skip
			if (removedParts.has(resKey)) continue;

			const resPart = contents[pair.resTurnIdx].parts[pair.resPartIdx];
			if (resPart && resPart.functionResponse) {
				const responseObj = resPart.functionResponse.response;
				const responseStr = JSON.stringify(responseObj || {});
				
				let isFailure = false;
				if (responseObj && (responseObj.error || responseObj.failed || (responseObj.exitCode !== undefined && responseObj.exitCode !== 0))) {
					isFailure = true;
				} else {
					const lowerStr = responseStr.toLowerCase();
					if (responseStr.length > 300 && (
						lowerStr.includes("error") || 
						lowerStr.includes("failed") || 
						lowerStr.includes("exception") || 
						lowerStr.includes("npm err!") || 
						lowerStr.includes("module not found") || 
						lowerStr.includes("typescript error") || 
						lowerStr.includes("stderr")
					)) {
						isFailure = true;
					}
				}

				if (isFailure) {
					let shouldTombstone = false;
					
					// Rule 1: Same-Command Success Detection (100% deterministic, no turn count required!)
					const successIdx = latestSuccessPairIdx.get(pair.resourceKey);
					if (successIdx !== undefined && successIdx > k) {
						shouldTombstone = true;
					}
					
					// Rule 2 & 3: Time-based safety margin (8 turns) AND Token Pressure (>20,000 tokens)
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

		let finalPartsCount = 0;
		for (const turn of prunedContents) {
			finalPartsCount += turn.parts.length;
		}

		const prunedTokens = this.estimateGeminiTokens(prunedContents);
		const savedTokens = Math.max(0, originalTokens - prunedTokens);

		return {
			prunedContents,
			stats: {
				originalParts: originalPartsCount,
				finalParts: finalPartsCount,
				expiredRemoved: expiredRemoved - restoredCount,
				duplicatesRemoved,
				restoredCount,
				savedTokens,
				errorsTombstoned
			}
		};
	}

	async getNextApiBaseUrl(isStreaming: boolean, isOAuth = false): Promise<string> {
		if (!isStreaming && !isOAuth && this.ctx.isCloudflareAIGatewayEnabled) {
			return `${this.ctx.cloudflareAIGatewayBase}/google-ai-studio`;
		}

		const endpoints: string[] = [];
		if (this.ctx.isOrgGeminiApiEnabled) {
			endpoints.push(this.ctx.orgGeminiApiBaseUrl);
		}
		if (this.ctx.env.GEMINI_API_BASE_URL) {
			if (!this.cachedGeminiApiBaseUrls) {
				this.cachedGeminiApiBaseUrls = this.ctx.env.GEMINI_API_BASE_URL.split(',')
					.map(url => url.trim())
					.filter(Boolean);
			}
			endpoints.push(...this.cachedGeminiApiBaseUrls);
		}

		if (endpoints.length === 0) {
			return 'https://generativelanguage.googleapis.com';
		}

		let currentIndex = await this.storage.getApiBaseUrlIndex();
		const nextIndex = (currentIndex + 1) % endpoints.length;
		this.ctx.waitUntil(this.storage.setApiBaseUrlIndex(nextIndex));

		const indexToUse = currentIndex < endpoints.length ? currentIndex : 0;
		return endpoints[indexToUse];
	}

	wrapResponseWithSpyStream(
		response: Response,
		apiKey: string,
		effectivelyOAuth: boolean,
		userAccessToken: string,
		authMode: string | null,
		model: string | null,
		savedTokensCount: number,
		isMetadataRequest: boolean
	): Response {
		if (isMetadataRequest) return response;

		let usageRecorded = false;
		const recordUsageStats = async (p: number, c: number, ca: number) => {
			if (response.status === 404) return; // Scheme 2: Skip recording 404 responses (bad routes/models) to keep statistics pristine
			if (usageRecorded) return;
			usageRecorded = true;
			await this.recordUsage(
				apiKey,
				effectivelyOAuth ? "oauth" : "api_key",
				userAccessToken || '',
				response.ok,
				response.status === 429,
				authMode || "google",
				model || "unknown",
				p,
				c,
				ca,
				savedTokensCount
			);
		};

		if (response.ok && response.body) {
			const decoder = new TextDecoder();
			let slidingBuffer = "";
			const self = this;

			const spyStream = new TransformStream({
				transform(chunk, controller) {
					controller.enqueue(chunk);
					if (chunk) {
						const text = decoder.decode(chunk, { stream: true });
						slidingBuffer += text;
					}
					if (slidingBuffer.length > 4000) {
						slidingBuffer = slidingBuffer.slice(slidingBuffer.length - 4000);
					}
				},
				async flush() {
					slidingBuffer += decoder.decode();
					let p = 0;
					let c = 0;
					let ca = 0;
					try {
						const usageMetadataMatch = slidingBuffer.match(/"usageMetadata"\s*:\s*\{([^}]+)\}/);
						if (usageMetadataMatch) {
							const inner = usageMetadataMatch[1];
							const promptMatch = inner.match(/"promptTokenCount"\s*:\s*(\d+)/);
							const candidatesMatch = inner.match(/"candidatesTokenCount"\s*:\s*(\d+)/);
							const cachedMatch = inner.match(/"cachedContentTokenCount"\s*:\s*(\d+)/);
							if (promptMatch) p = parseInt(promptMatch[1], 10);
							if (candidatesMatch) c = parseInt(candidatesMatch[1], 10);
							if (cachedMatch) ca = parseInt(cachedMatch[1], 10);
						} else {
							const promptMatch = slidingBuffer.match(/"(?:input_tokens|prompt_tokens)"\s*:\s*(\d+)/);
							if (promptMatch) p = parseInt(promptMatch[1], 10);

							const completionRegex = /"(?:output_tokens|completion_tokens)"\s*:\s*(\d+)/g;
							let match;
							let maxCompletion = 0;
							while ((match = completionRegex.exec(slidingBuffer)) !== null) {
								const val = parseInt(match[1], 10);
								if (val > maxCompletion) {
									maxCompletion = val;
								}
							}
							c = maxCompletion;

							const cachedMatch = slidingBuffer.match(/"cache_read_tokens"\s*:\s*(\d+)/);
							if (cachedMatch) ca = parseInt(cachedMatch[1], 10);
						}
					} catch (e) {}

					// Record stats synchronously when the stream completes successfully
					self.ctx.waitUntil(recordUsageStats(p, c, ca));
				}
			});

			return new Response(response.body.pipeThrough(spyStream), response);
		} else {
			// For non-ok (failed) requests or responses without body
			this.ctx.waitUntil(recordUsageStats(0, 0, 0));
			return response;
		}
	}

	async recordUsage(
		rawKey: string,
		keyType: 'api_key' | 'oauth',
		userToken: string,
		success: boolean,
		is429: boolean,
		mode: string,
		model: string,
		promptTokens = 0,
		completionTokens = 0,
		cachedTokens = 0,
		savedTokens = 0
	) {
		if (!this.ctx.isUsageStatisticsEnabled) return;

		// 1. Thread-safe, non-blocking synchronous append to in-memory stats
		const actualPromptTokens = success ? promptTokens : 0;
		const actualCompletionTokens = success ? completionTokens : 0;
		const actualCachedTokens = success ? cachedTokens : 0;
		const actualSavedTokens = success ? savedTokens : 0;

		this.inMemoryStats.push({
			rawKey,
			keyType,
			userToken,
			success,
			is429,
			mode: mode || 'unknown',
			model: model || 'unknown',
			promptTokens: actualPromptTokens,
			completionTokens: actualCompletionTokens,
			cachedTokens: actualCachedTokens,
			savedTokens: actualSavedTokens
		});

		// 2. Persistent save to DO storage asynchronously in the background (no read-modify-write race!)
		this.ctx.waitUntil((async () => {
			try {
				await this.storage.put("pending_stats", this.inMemoryStats);
			} catch (e) {
				console.error('Error writing usage stats to DO storage:', e);
			}
		})());

		// Schedule alarm for 1 minute from now if not already scheduled
		try {
			const existingAlarm = await this.storage.getAlarm();
			if (!existingAlarm) {
				await this.storage.setAlarm(Date.now() + 60000); // 1 minute delay
			}
		} catch (e) {
			console.error('Error setting Durable Object alarm for usage stats flush:', e);
			// Fallback: Flush immediately on error to prevent data loss
			await this.alarm();
		}
	}

	async alarm() {
		// 1. Read pending stats from in-memory and persistent DO storage and flush them
		let statsToFlush = [...this.inMemoryStats];
		let statsFlushed = false;

		if (statsToFlush.length === 0) {
			try {
				statsToFlush = (await this.storage.get<any[]>("pending_stats")) || [];
			} catch (e) {
				console.error('Error reading pending stats from DO storage:', e);
			}
		}

		// Clear memory and delete storage entry to prevent double-processing
		this.inMemoryStats = [];
		try {
			await this.storage.delete("pending_stats");
			statsFlushed = statsToFlush.length > 0;
		} catch (e) {
			console.error('Error deleting pending stats from DO storage:', e);
		}

		if (statsFlushed && statsToFlush.length > 0) {
			// Aggregate stats by composite key to minimize DB operations
			const aggregated: { [key: string]: {
				rawKey: string;
				keyType: 'api_key' | 'oauth';
				userToken: string;
				mode: string;
				model: string;
				requestCount: number;
				successCount: number;
				error429Count: number;
				promptTokens: number;
				completionTokens: number;
				cachedTokens: number;
				savedTokens: number;
			}} = {};

			const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Hong_Kong' });

			for (const s of statsToFlush) {
				const compositeKey = `${s.rawKey}|${s.userToken}|${s.mode}|${s.model}`;
				if (!aggregated[compositeKey]) {
					aggregated[compositeKey] = {
						rawKey: s.rawKey,
						keyType: s.keyType,
						userToken: s.userToken,
						mode: s.mode,
						model: s.model,
						requestCount: 0,
						successCount: 0,
						error429Count: 0,
						promptTokens: 0,
						completionTokens: 0,
						cachedTokens: 0,
						savedTokens: 0
					};
				}

				const agg = aggregated[compositeKey];
				agg.requestCount += 1;
				agg.successCount += (s.success ? 1 : 0);
				agg.error429Count += (s.is429 ? 1 : 0);
				agg.promptTokens += s.promptTokens;
				agg.completionTokens += s.completionTokens;
				agg.cachedTokens += s.cachedTokens;
				agg.savedTokens += s.savedTokens || 0;
			}

			// Perform batch updates to D1
			const statements: any[] = [];
			const query = `
				INSERT INTO api_key_usage (
					raw_key, key_type, usage_date, user_access_token, mode, model, 
					request_count, success_count, error_429_count, 
					prompt_tokens, completion_tokens, cached_tokens, saved_tokens
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(raw_key, usage_date, user_access_token, mode, model) DO UPDATE SET
					request_count = request_count + ?,
					success_count = success_count + ?,
					error_429_count = error_429_count + ?,
					prompt_tokens = prompt_tokens + ?,
					completion_tokens = completion_tokens + ?,
					cached_tokens = cached_tokens + ?,
					saved_tokens = saved_tokens + ?
			`;

			for (const compositeKey in aggregated) {
				const agg = aggregated[compositeKey];
				statements.push(
					this.ctx.env.DB.prepare(query).bind(
						agg.rawKey,
						agg.keyType,
						today,
						agg.userToken,
						agg.mode,
						agg.model,
						agg.requestCount,
						agg.successCount,
						agg.error429Count,
						agg.promptTokens,
						agg.completionTokens,
						agg.cachedTokens,
						agg.savedTokens,
						agg.requestCount,
						agg.successCount,
						agg.error429Count,
						agg.promptTokens,
						agg.completionTokens,
						agg.cachedTokens,
						agg.savedTokens
					)
				);
			}

			if (statements.length > 0) {
				try {
					await this.ctx.env.DB.batch(statements);
					console.log(`Durable Object Alarm: Successfully flushed ${statsToFlush.length} usage records (aggregated into ${statements.length} DB statements) to D1.`);
				} catch (e) {
					console.error('Error flushing aggregated usage statistics to D1:', e);
					// Restore records on failure to DO storage so we don't lose them
					try {
						const currentPending = (await this.storage.get<any[]>("pending_stats")) || [];
						await this.storage.put("pending_stats", [...statsToFlush, ...currentPending]);
						this.inMemoryStats = [...statsToFlush, ...this.inMemoryStats];
					} catch (storeError) {
						console.error('Fatal: Failed to restore statistics to DO storage:', storeError);
					}
				}
			}
		}

		// 2. Proactive Model Sync Check (Level 1)
		try {
			const now = Date.now();
			const lastSyncTime = (await this.storage.get<number>("last_model_sync_time")) || 0;
			const twelveHoursInMs = 12 * 60 * 60 * 1000;
			
			if (now - lastSyncTime > twelveHoursInMs) {
				await this.syncAvailableModelsForAllCredentials();
				await this.storage.put("last_model_sync_time", now);
			}
		} catch (err) {
			console.error('Error in alarm proactive model sync check:', err);
		}
	}

	async syncAvailableModelsForAllCredentials() {
		try {
			const db = this.ctx.env.DB;
			if (!db) return;

			// Retrieve all active credentials rows (use access_token as key instead of non-existent id column)
			const allRows = await db.prepare('SELECT access_token, oauth_credentials, oauth_key_states FROM api_credentials').all<{ access_token: string, oauth_credentials: string, oauth_key_states: string }>();
			const results = allRows.results || [];

			for (const row of results) {
				const access_token = row.access_token as string || '';
				const oauth_credentials = row.oauth_credentials as string || '';
				const oauth_key_states = JSON.parse(row.oauth_key_states || '[]') as KeyState[];

				if (!oauth_credentials) continue;

				const oauthParts = parseCsvList(oauth_credentials);
				let updatedOauthKeyStates = [...oauth_key_states];
				
				// Pad updatedOauthKeyStates to match oauthParts length
				while (updatedOauthKeyStates.length < oauthParts.length) {
					updatedOauthKeyStates.push({});
				}

				let anyChange = false;

				const promises = oauthParts.map(async (part, i) => {
					try {
						const creds = parseOAuthCredentials(part, this.ctx.env.OAUTH_CLIENT_ID, this.ctx.env.OAUTH_CLIENT_SECRET);
						if (!creds.refresh_token) return;

						// 1. Get/Refresh OAuth Access Token
						const activeAccessToken = await getOAuthAccessToken(this.ctx.state, creds, this.ctx);
						if (!activeAccessToken) return;

						// 2. Discover project ID if not explicitly configured
						let projectId = creds.project_id;
						if (!projectId) {
							projectId = await discoverProjectId(activeAccessToken, creds.email);
						}
						if (!projectId) return;

						// 3. Fetch supported models list from Google
						const supportedModels = await fetchAvailableModelsForToken(activeAccessToken, projectId);
						if (supportedModels.length > 0) {
							// Update new dynamic availableModels
							const newAvailableModels = supportedModels.map(b => b.modelId).filter(Boolean);
							const oldAvailableModels = updatedOauthKeyStates[i].availableModels || [];
							const availableModelsChanged = JSON.stringify(newAvailableModels.sort()) !== JSON.stringify([...oldAvailableModels].sort());

							if (availableModelsChanged) {
								updatedOauthKeyStates[i] = {
									...updatedOauthKeyStates[i],
									availableModels: newAvailableModels,
									lastModelSyncTime: Date.now()
								};
								anyChange = true;
							}
						}
					} catch (err) {
						console.error(`Error syncing models for OAuth credential at index ${i} in row ${access_token}:`, err);
					}
				});

				await Promise.all(promises);

				if (anyChange) {
					await db.prepare('UPDATE api_credentials SET oauth_key_states = ? WHERE access_token = ?')
						.bind(JSON.stringify(updatedOauthKeyStates), access_token)
						.run();
				}
			}
		} catch (e) {
			console.error('Failed to sync available models for all credentials:', e);
		}
	}

	async notifyInvalidToken(userToken: string, tokenType: 'api_key' | 'oauth', rawToken: string, reason: string) {
		const resendKey = this.ctx.resendApiKey;
		const adminEmail = this.ctx.notificationEmail;

		if (!resendKey) return;

		let ownerEmail: string | undefined = undefined;
		try {
			if (userToken) {
				const ownerResult = await this.ctx.env.DB.prepare(
					`SELECT a.email FROM api_credentials c JOIN admins a ON c.owner_admin_id = a.id WHERE c.access_token = ?`
				).bind(userToken).first<{ email: string }>();
				ownerEmail = ownerResult?.email;
			}
		} catch (e) {
			console.error('Error fetching owner email for invalid token notification:', e);
		}

		const recipients = new Set<string>();
		if (adminEmail) {
			recipients.add(adminEmail.trim().toLowerCase());
		}
		if (ownerEmail) {
			recipients.add(ownerEmail.trim().toLowerCase());
		}

		const toEmails = Array.from(recipients);
		if (toEmails.length > 0) {
			this.ctx.waitUntil(sendInvalidTokenEmail(resendKey, toEmails, tokenType, rawToken, reason));
		}
	}

	async notifyExhausted(userToken: string, hasFallbackOAuth: boolean, model: string) {
		const resendKey = this.ctx.resendApiKey;
		const adminEmail = this.ctx.notificationEmail;

		if (!resendKey) return;

		// Cooldown: 1 hour (3600000 ms)
		const cooldown = 3600000;
		const now = Date.now();
		const lastSentKey = `last_exhausted_email_${userToken}`;
		const lastSent = await this.storage.get<number>(lastSentKey);

		if (!lastSent || now - lastSent > cooldown) {
			await this.storage.put(lastSentKey, now);

			let ownerEmail: string | undefined = undefined;
			try {
				if (userToken) {
					const ownerResult = await this.ctx.env.DB.prepare(
						`SELECT a.email FROM api_credentials c JOIN admins a ON c.owner_admin_id = a.id WHERE c.access_token = ?`
					).bind(userToken).first<{ email: string }>();
					ownerEmail = ownerResult?.email;
				}
			} catch (e) {
				console.error('Error fetching owner email for exhausted notification:', e);
			}

			const recipients = new Set<string>();
			if (adminEmail) {
				recipients.add(adminEmail.trim().toLowerCase());
			}
			if (ownerEmail) {
				recipients.add(ownerEmail.trim().toLowerCase());
			}

			const toEmails = Array.from(recipients);
			if (toEmails.length > 0) {
				this.ctx.waitUntil(sendExhaustedEmail(resendKey, toEmails, userToken, hasFallbackOAuth, model));
			}
		}
	}

	private async cleanupExpiredImages(): Promise<void> {
		try {
			if (!this.storage.storage || typeof this.storage.storage.list !== 'function') {
				return;
			}
			const expiries = await this.storage.storage.list({ prefix: 'img_expiry_' });
			const now = Date.now();
			for (const [key, expiry] of expiries) {
				if (expiry && now > (expiry as number)) {
					const id = key.replace('img_expiry_', '');
					await this.storage.delete(`img_data_${id}`);
					await this.storage.delete(`img_expiry_${id}`);
				}
			}
		} catch (e) {
			console.error('Failed to cleanup expired images in DO:', e);
		}
	}

	private async handleImageRetrieve(requestUrl: URL, protocol: Protocol): Promise<Response | null> {
		const imageId = requestUrl.searchParams.get('id');
		if (!imageId) return createErrorResponse('Missing image ID', 400, protocol);

		const expiry = await this.storage.get<number>(`img_expiry_${imageId}`);
		if (expiry && Date.now() > expiry) {
			// Expired: delete asynchronously
			this.ctx.state.waitUntil(this.storage.delete(`img_data_${imageId}`));
			this.ctx.state.waitUntil(this.storage.delete(`img_expiry_${imageId}`));
			return createErrorResponse('Image expired', 410, protocol);
		}

		const imgBase64 = await this.storage.get<string>(`img_data_${imageId}`);
		if (!imgBase64) return createErrorResponse('Image not found', 404, protocol);

		// Convert Base64 back to binary data safely
		const binaryString = atob(imgBase64);
		const len = binaryString.length;
		const bytes = new Uint8Array(len);
		for (let i = 0; i < len; i++) {
			bytes[i] = binaryString.charCodeAt(i);
		}

		return new Response(bytes.buffer, {
			headers: {
				'Content-Type': 'image/jpeg',
				'Cache-Control': 'public, max-age=3600'
			}
		});
	}

		private async handleAdminRequest(
		requestUrl: URL,
		request: Request,
		userAccessToken: string | null,
		protocol: Protocol
	): Promise<Response | null> {
		// Handle key diagnostic requests (Internal/Admin only)
		if (requestUrl.pathname === '/admin/key-diagnose' && request.method === 'POST') {
			if (!userAccessToken) return createErrorResponse('Unauthorized', 401, protocol);

			const { key, isOAuth, model } = (await request.json()) as { key: string; isOAuth: boolean; model?: string };
			if (!key) return createErrorResponse('Key is required', 400, protocol);

			const startTime = Date.now();
			let testUrl = '';
			const headersObj: { [key: string]: string } = { 'Content-Type': 'application/json' };

			// Clean and resolve the model name
			let modelToUse = model;
			if (!modelToUse) {
				modelToUse = isOAuth ? 'gemini-3.1-flash-lite' : 'gemini-3.1-flash-lite';
			}
			if (modelToUse.startsWith('models/')) {
				modelToUse = modelToUse.replace('models/', '');
			}

			if (modelToUse === 'unknown' || modelToUse === '_general_') {
				modelToUse = isOAuth ? 'gemini-3.1-flash-lite' : 'gemini-3.1-flash-lite';
			}

			try {
				if (isOAuth) {
					const defaultClientId = this.ctx.env.OAUTH_CLIENT_ID;
					const defaultClientSecret = this.ctx.env.OAUTH_CLIENT_SECRET;
					const credentials = parseOAuthCredentials(key, defaultClientId, defaultClientSecret);
					
					// This will refresh the OAuth token if necessary and return a valid access token
					const token = await getOAuthAccessToken(this.ctx.state, credentials, this.ctx);
					
					// OAuth Key test using the actual companion API
					testUrl = `https://cloudcode-pa.googleapis.com/v1internal:generateContent`;
					headersObj['Authorization'] = `Bearer ${token}`;
					headersObj['Content-Type'] = 'application/json';
					headersObj['User-Agent'] = 'google-api-nodejs-client/9.15.1';
					headersObj['X-Goog-Api-Client'] = 'google-api-nodejs-client/9.15.1';
					headersObj['Client-Metadata'] = 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI';
					
					let projectId = credentials.project_id;
					if (!projectId || projectId === 'default') {
						projectId = await discoverProjectId(token);
						await saveDiscoveredProjectId(credentials, projectId, this.ctx);
					}
					
					const companionBody = {
						project: projectId,
						model: modelToUse, // gemini-3-flash-preview
						user_prompt_id: 'diagnose-' + Math.random().toString(36).substring(2, 15),
						request: {
							contents: [{ role: 'user', parts: [{ text: 'Hi!' }] }]
						}
					};

					const response = await fetch(testUrl, {
						method: 'POST',
						headers: headersObj,
						body: JSON.stringify(companionBody)
					});
					
					const latency = Date.now() - startTime;
					if (response.ok) {
						let greeting = "";
						try {
							const resJson = await response.json() as any;
							const candidates = resJson.candidates || resJson.response?.candidates;
							if (candidates && candidates[0]?.content?.parts?.[0]?.text) {
								greeting = candidates[0].content.parts[0].text.trim();
							}
						} catch (e) {
							// Ignore
						}
						return new Response(JSON.stringify({ success: true, status: response.status, latency, greeting, model: modelToUse }), {
							headers: JSON_HEADERS
						});
					} else {
						const errorJson = await response.json<any>().catch(() => ({}));
						const errMsg = errorJson?.error?.message || 'Upstream returned error';
						return new Response(JSON.stringify({ success: false, status: response.status, latency, error: errMsg }), {
							status: response.status,
							headers: JSON_HEADERS
						});
					}
				} else {
					// API Key test using generateContent with the specific model
					testUrl = `https://generativelanguage.googleapis.com/v1beta/models/${modelToUse}:generateContent?key=${key}`;
					const response = await fetch(testUrl, {
						method: 'POST',
						headers: headersObj,
						body: JSON.stringify({
							contents: [{ parts: [{ text: 'Hi!' }] }]
						})
					});
					
					const latency = Date.now() - startTime;
					if (response.ok) {
						let greeting = "";
						try {
							const resJson = await response.clone().json() as any;
							const candidates = resJson.candidates || resJson.response?.candidates;
							if (candidates && candidates[0]?.content?.parts?.[0]?.text) {
								greeting = candidates[0].content.parts[0].text.trim();
							}
						} catch (e) {
							// Ignore
						}
						return new Response(JSON.stringify({ success: true, status: response.status, latency, greeting, model: modelToUse }), {
							headers: JSON_HEADERS
						});
					} else {
						const errorJson = await response.json<any>().catch(() => ({}));
						const errMsg = errorJson?.error?.message || 'Upstream returned error';
						return new Response(JSON.stringify({ success: false, status: response.status, latency, error: errMsg }), {
							status: response.status,
							headers: JSON_HEADERS
						});
					}
				}
			} catch (e: any) {
				const latency = Date.now() - startTime;
				return new Response(JSON.stringify({ success: false, status: 500, latency, error: e.message }), {
					status: 500,
					headers: JSON_HEADERS
				});
			}
		}

		// Handle clear cache requests (Internal/Admin only)
		if (requestUrl.pathname === '/admin/clear-cache' && request.method === 'POST') {
			if (!userAccessToken) return createErrorResponse('Unauthorized', 401, protocol);
			this.cachedCredentials = null;
			this.currentKeyIndex = undefined;
			this.currentOauthIndex = undefined;
			this.initPromise = null;
			this.requestCountSinceSync = 0;
			this.ctx.state.waitUntil((async () => {
				await this.storage.delete(`key_index_${userAccessToken}`);
				await this.storage.delete(`oauth_index_${userAccessToken}`);
				await this.storage.delete(`sync_count_${userAccessToken}`);
			})());
			return new Response(JSON.stringify({ success: true }), {
				headers: JSON_HEADERS,
			});
		}

		// Handle key health status requests (Internal/Admin only)
		if (requestUrl.pathname === '/admin/key-status' && request.method === 'GET') {
			if (!userAccessToken) return createErrorResponse('Unauthorized', 401, protocol);

			const stmt = this.ctx.env.DB.prepare(
				'SELECT api_keys, key_states, oauth_credentials, oauth_key_states, antigravity_credentials, antigravity_key_states FROM api_credentials WHERE access_token = ?'
			);
			const dbResult = await stmt.bind(userAccessToken).first<any>();
			if (!dbResult) return createErrorResponse('Not Found', 404, protocol);

			return new Response(
				JSON.stringify({
					api_keys: parseCsvList(dbResult.api_keys),
					key_states: JSON.parse(dbResult.key_states || '[]'),
					oauth_credentials: parseCsvList(dbResult.oauth_credentials),
					oauth_key_states: JSON.parse(dbResult.oauth_key_states || '[]'),
					antigravity_credentials: parseCsvList(dbResult.antigravity_credentials),
					antigravity_key_states: JSON.parse(dbResult.antigravity_key_states || '[]'),
				}),
				{ headers: JSON_HEADERS }
			);
		}

		// Handle model query requests (Internal/Admin only)
		if (requestUrl.pathname === '/admin/key-models' && request.method === 'POST') {
			if (!userAccessToken) return createErrorResponse('Unauthorized', 401, protocol);

			const { key, isOAuth, isAntigravity } = (await request.json()) as { key: string; isOAuth?: boolean; isAntigravity?: boolean };
			if (!key) return createErrorResponse('Key is required', 400, protocol);

			try {
				if (isAntigravity) {
					const creds = parseAntigravityCredentials(key);
					if (!creds.refresh_token) {
						return new Response(JSON.stringify({ error: 'Invalid Antigravity credentials format' }), { status: 400, headers: JSON_HEADERS });
					}
					const activeAccessToken = await getOAuthAccessToken(this.ctx.state, creds, this.ctx);
					if (!activeAccessToken) {
						return new Response(JSON.stringify({ error: 'Failed to refresh Antigravity token' }), { status: 400, headers: JSON_HEADERS });
					}
					let projectId = creds.project_id;
					if (!projectId) {
						projectId = await discoverProjectId(activeAccessToken, creds.email);
					}
					if (!projectId) {
						return new Response(JSON.stringify({ error: 'Failed to discover Google Cloud Project ID' }), { status: 400, headers: JSON_HEADERS });
					}

					const buckets = await fetchAvailableModelsForToken(activeAccessToken, projectId);

					if (buckets.length > 0) {
						const stmt = this.ctx.env.DB.prepare(
							'SELECT antigravity_credentials, antigravity_key_states FROM api_credentials WHERE access_token = ?'
						);
						const dbResult = await stmt.bind(userAccessToken).first<any>();
						if (dbResult) {
							const agy_credentials = dbResult.antigravity_credentials as string || '';
							const agy_key_states = JSON.parse(dbResult.antigravity_key_states || '[]') as KeyState[];
							const agyParts = parseCsvList(agy_credentials);
							
							const targetIndex = agyParts.indexOf(key.trim());
							if (targetIndex !== -1) {
								let updatedAgyKeyStates = [...agy_key_states];
								while (updatedAgyKeyStates.length <= targetIndex) {
									updatedAgyKeyStates.push({});
								}

								const newAvailableModels = buckets.map(b => b.modelId).filter(Boolean);
								const oldAvailableModels = updatedAgyKeyStates[targetIndex].availableModels || [];
								const availableModelsChanged = JSON.stringify(newAvailableModels.sort()) !== JSON.stringify([...oldAvailableModels].sort());

								if (availableModelsChanged) {
									updatedAgyKeyStates[targetIndex] = {
										...updatedAgyKeyStates[targetIndex],
										availableModels: newAvailableModels,
										lastModelSyncTime: Date.now()
									};

									await this.ctx.env.DB.prepare('UPDATE api_credentials SET antigravity_key_states = ? WHERE access_token = ?')
										.bind(JSON.stringify(updatedAgyKeyStates), userAccessToken)
										.run();

									this.cachedCredentials = null;
								}
							}
						}
					}

					const models = buckets
						.filter((b: any) => b.modelId)
						.map((b: any) => `${b.modelId} (Remaining: ${b.remainingAmount || 'unknown'})`);

					return new Response(JSON.stringify({ models }), { headers: JSON_HEADERS });
				} else if (isOAuth) {
					const creds = parseOAuthCredentials(key, this.ctx.env.OAUTH_CLIENT_ID, this.ctx.env.OAUTH_CLIENT_SECRET);
					if (!creds.refresh_token) {
						return new Response(JSON.stringify({ error: 'Invalid OAuth credentials format' }), { status: 400, headers: JSON_HEADERS });
					}
					const activeAccessToken = await getOAuthAccessToken(this.ctx.state, creds, this.ctx);
					if (!activeAccessToken) {
						return new Response(JSON.stringify({ error: 'Failed to refresh OAuth token' }), { status: 400, headers: JSON_HEADERS });
					}
					let projectId = creds.project_id;
					if (!projectId) {
						projectId = await discoverProjectId(activeAccessToken, creds.email);
					}
					if (!projectId) {
						return new Response(JSON.stringify({ error: 'Failed to discover Google Cloud Project ID' }), { status: 400, headers: JSON_HEADERS });
					}

					// Use the DRY-ed official helper to fetch model buckets
					const buckets = await fetchAvailableModelsForToken(activeAccessToken, projectId);

					// Force instant DB force-sync if buckets are successfully fetched
					if (buckets.length > 0) {
						const stmt = this.ctx.env.DB.prepare(
							'SELECT oauth_credentials, oauth_key_states FROM api_credentials WHERE access_token = ?'
						);
						const dbResult = await stmt.bind(userAccessToken).first<any>();
						if (dbResult) {
							const oauth_credentials = dbResult.oauth_credentials as string || '';
							const oauth_key_states = JSON.parse(dbResult.oauth_key_states || '[]') as KeyState[];
							const oauthParts = parseCsvList(oauth_credentials);
							
							const targetIndex = oauthParts.indexOf(key.trim());
							if (targetIndex !== -1) {
								let updatedOauthKeyStates = [...oauth_key_states];
								while (updatedOauthKeyStates.length <= targetIndex) {
									updatedOauthKeyStates.push({});
								}

								// Update new dynamic availableModels
								const newAvailableModels = buckets.map(b => b.modelId).filter(Boolean);
								const oldAvailableModels = updatedOauthKeyStates[targetIndex].availableModels || [];
								const availableModelsChanged = JSON.stringify(newAvailableModels.sort()) !== JSON.stringify([...oldAvailableModels].sort());

								if (availableModelsChanged) {
									updatedOauthKeyStates[targetIndex] = {
										...updatedOauthKeyStates[targetIndex],
										availableModels: newAvailableModels,
										lastModelSyncTime: Date.now()
									};

									await this.ctx.env.DB.prepare('UPDATE api_credentials SET oauth_key_states = ? WHERE access_token = ?')
										.bind(JSON.stringify(updatedOauthKeyStates), userAccessToken)
										.run();

									// Clear local Durable Object memory cache to instantly apply the new states
									this.cachedCredentials = null;
								}
							}
						}
					}

					// Return models with remaining amounts formatted nicely for UI
					const models = buckets
						.filter((b: any) => b.modelId)
						.map((b: any) => `${b.modelId} (Remaining: ${b.remainingAmount || 'unknown'})`);

					return new Response(JSON.stringify({ models }), { headers: JSON_HEADERS });
				} else {
					// Fetch standard API Key models
					const response = await fetch(`https://generativelanguage.googleapis.com/v1/models?key=${key}`);
					if (!response.ok) {
						return new Response(JSON.stringify({ error: `Google API Error: ${response.statusText}` }), { status: response.status, headers: JSON_HEADERS });
					}
					const data = await response.json() as { models?: { name: string }[] };
					const models = (data.models || []).map(m => m.name.replace('models/', ''));
					return new Response(JSON.stringify({ models }), { headers: JSON_HEADERS });
				}
			} catch (err: any) {
				return new Response(JSON.stringify({ error: err.message || 'Unknown error occurred' }), { status: 500, headers: JSON_HEADERS });
			}
		}

		// Handle key health reset requests (Internal/Admin only)
		if (requestUrl.pathname === '/admin/reset-key-health' && request.method === 'POST') {
			if (!userAccessToken) return createErrorResponse('Unauthorized', 401, protocol);

			const { key, isOAuth, isAntigravity } = (await request.json()) as { key: string; isOAuth?: boolean; isAntigravity?: boolean };
			if (!key) return createErrorResponse('Key is required', 400, protocol);

			const stmt = this.ctx.env.DB.prepare(
				'SELECT api_keys, key_states, oauth_credentials, oauth_key_states, antigravity_credentials, antigravity_key_states FROM api_credentials WHERE access_token = ?'
			);
			const dbResult = await stmt.bind(userAccessToken).first<any>();
			if (!dbResult) return createErrorResponse('Not Found', 404, protocol);

			const { apiKeys, keyStates, oauthCredentialsList, oauthKeyStates, antigravityCredentialsList, antigravityKeyStates } = parseCredentials(dbResult);

			if (isAntigravity) {
				const index = antigravityCredentialsList.indexOf(key);
				if (index !== -1 && antigravityKeyStates[index]) {
					const s = { ...antigravityKeyStates[index] };
					delete (s as any).invalid;
					delete (s as any).exhaustedUntil;
					delete (s as any).modelUnavailable;
					antigravityKeyStates[index] = s;
					await this.ctx.env.DB.prepare(
						'UPDATE api_credentials SET antigravity_key_states = ? WHERE access_token = ?'
					)
						.bind(JSON.stringify(antigravityKeyStates), userAccessToken)
						.run();
				}
			} else if (isOAuth) {
				const index = oauthCredentialsList.indexOf(key);
				if (index !== -1 && oauthKeyStates[index]) {
					const s = { ...oauthKeyStates[index] };
					delete (s as any).invalid;
					delete (s as any).exhaustedUntil;
					delete (s as any).modelUnavailable;
					oauthKeyStates[index] = s;
					await this.ctx.env.DB.prepare(
						'UPDATE api_credentials SET oauth_key_states = ? WHERE access_token = ?'
					)
						.bind(JSON.stringify(oauthKeyStates), userAccessToken)
						.run();
				}
			} else {
				const index = apiKeys.indexOf(key);
				if (index !== -1 && keyStates[index]) {
					const s = { ...keyStates[index] };
					delete (s as any).invalid;
					delete (s as any).exhaustedUntil;
					delete (s as any).modelUnavailable;
					keyStates[index] = s;
					await this.ctx.env.DB.prepare(
						'UPDATE api_credentials SET key_states = ? WHERE access_token = ?'
					)
						.bind(JSON.stringify(keyStates), userAccessToken)
						.run();
				}
			}

			// Clear cache
			this.cachedCredentials = null;

			return new Response(JSON.stringify({ success: true }), {
				headers: JSON_HEADERS,
			});
		}

		return null;
	}

async fetch(request: Request): Promise<Response> {
		const startTime = Date.now();
		let savedTokensCount = 0;
		const clonedRequest = request.clone();
		const requestUrl = new URL(request.url);
		const userAccessToken = request.headers.get('X-Access-Token');
		const authMode = request.headers.get('X-Auth-Mode');
		const protocol = authMode as Protocol;
		const enablePruningHeader = request.headers.get('X-Enable-Pruning');
		let enablePruning = true;

		let cacheId: string | undefined;
		let requestBodyJson: any = null;
		if (request.method === 'POST') {
			try {
				requestBodyJson = await clonedRequest.clone().json();
				if (requestBodyJson) {
					cacheId = requestBodyJson.cachedContent;
				}
			} catch (e) {
				// Ignore
			}
		}
		const sessionId = request.headers.get('X-Session-ID') || request.headers.get('X-Sticky-Session') || cacheId;

		// Check for Exact-Match Cache on non-streaming POST completions
		let cacheHash: string | null = null;
		if (request.method === 'POST' && requestBodyJson) {
			try {
				if (!requestBodyJson.stream) {
					const pathname = requestUrl.pathname;
					if (pathname.includes('/completions') || pathname.includes('/messages') || pathname.includes(':generateContent')) {
						const cacheKey = `${pathname}|${JSON.stringify(requestBodyJson)}`;
						cacheHash = await sha256Hex(cacheKey);
						
						const cached = this.getExactMatchCache(cacheHash);
						if (cached) {
							console.log(`Durable Object Exact-Match Cache Hit for hash ${cacheHash}!`);
							return new Response(cached.body, {
								status: cached.status,
								headers: cached.headers
							});
						}
					}
				}
			} catch (e) {
				// Ignore
			}
		}

		// Run background garbage collection for expired images every 30 minutes
		if (Date.now() - this.lastCleanupTime > 1800000) {
			this.lastCleanupTime = Date.now();
			this.ctx.state.waitUntil(this.cleanupExpiredImages());
		}

		// Handle image retrieve requests (Proxy endpoint for DALL-E Imagen)
		if (requestUrl.pathname === '/api/images/retrieve' && request.method === 'GET') {
			const imgRes = await this.handleImageRetrieve(requestUrl, protocol);
			if (imgRes) return imgRes;
		}

		  // Handle admin requests
		if (requestUrl.pathname.startsWith('/admin/')) {
			const adminRes = await this.handleAdminRequest(requestUrl, request, userAccessToken, protocol);
			if (adminRes) return adminRes;
		}

		if (!userAccessToken) {
			return createErrorResponse('Unauthorized: Access token is required.', 401, protocol);
		}

		const pathname = requestUrl.pathname;
		const isMetadataRequest =
			request.method === 'GET' &&
			(pathname.endsWith('/models') ||
				pathname.includes('/models/') ||
				pathname.includes('/v1/models') ||
				pathname.includes('/v1beta/models'));

		const rawModel = await parseRequestModel(clonedRequest.clone() as any);
		const resolved = resolveModelAndAuthMode(rawModel, authMode, userAccessToken);

		// Handle /oauth/models explicitly to force OAuth mode
		if (pathname.includes('/oauth/models')) {
			resolved.useOAuth = true;
		} else if (pathname.includes('/antigravity/models')) {
			resolved.useAntigravity = true;
		}
		const model = resolved.model;
		const isOAuthMode = resolved.useOAuth;
		const isAntigravityMode = resolved.useAntigravity;

		let dbResult: ApiCredentials | null = null;
		const now = Date.now();
		if (this.cachedCredentials && (now - this.cacheTimestamp < this.CACHE_TTL)) {
			dbResult = this.cachedCredentials;

			// Trigger background prefetch if within the prefetch window (55-60 mins) and not already prefetching
			if (now - this.cacheTimestamp >= this.CACHE_TTL - this.PREFETCH_THRESHOLD && !this.isPrefetching) {
				this.isPrefetching = true;
				this.ctx.state.waitUntil((async () => {
					try {
						const stmt = this.ctx.env.DB.prepare(
							'SELECT api_keys, current_key_index, key_states, oauth_credentials, current_oauth_index, oauth_key_states, antigravity_credentials, current_antigravity_index, antigravity_key_states, enable_logging, enable_pruning FROM api_credentials WHERE access_token = ?'
						);
						const freshResult = await stmt.bind(userAccessToken).first<ApiCredentials>();
						if (freshResult) {
							this.cachedCredentials = freshResult;
							this.cacheTimestamp = Date.now();
						}
					} catch (e) {
						console.error('Background prefetch failed:', e);
					} finally {
						this.isPrefetching = false;
					}
				})());
			}
		} else {
			const stmt = this.ctx.env.DB.prepare(
				'SELECT api_keys, current_key_index, key_states, oauth_credentials, current_oauth_index, oauth_key_states, antigravity_credentials, current_antigravity_index, antigravity_key_states, enable_logging, enable_pruning FROM api_credentials WHERE access_token = ?'
			);
			dbResult = await stmt.bind(userAccessToken).first<ApiCredentials>();
			if (dbResult) {
				this.cachedCredentials = dbResult;
				this.cacheTimestamp = now;
			}
		}

		if (!dbResult) {
			return createErrorResponse('Unauthorized: Invalid access token.', 401, protocol);
		}

		if (dbResult.enable_pruning !== undefined && dbResult.enable_pruning !== null) {
			enablePruning = dbResult.enable_pruning === 1;
		} else if (enablePruningHeader !== null) {
			enablePruning = enablePruningHeader !== 'false';
		}

		const {
			apiKeys,
			keyStates,
			oauthCredentialsList,
			oauthKeyStates,
			antigravityCredentialsList,
			antigravityKeyStates,
			currentKeyIndex: dbKeyIndex,
			currentOauthIndex: dbOauthIndex,
			currentAntigravityIndex: dbAntigravityIndex,
		} = parseCredentials(dbResult);

		// Initialize in-memory index tracking safely with no race conditions on first load
		await this.ensureInitialized(userAccessToken, dbKeyIndex, dbOauthIndex, dbAntigravityIndex);
		let currentKeyIndex = this.currentKeyIndex!;
		let currentOauthIndex = this.currentOauthIndex!;
		let currentAntigravityIndex = this.currentAntigravityIndex!;

		const modelForExhaustion = model || '_general_';

		let apiKey = '';
		let keyIndexToUse: number | null = null;
		let oauthIndexToUse: number | null = null;
		let antigravityIndexToUse: number | null = null;
		let effectivelyOAuth = isOAuthMode;
		let effectivelyAntigravity = isAntigravityMode;

		let isStickyUsed = false;
		if (sessionId && this.sessionKeyMap.has(sessionId)) {
			const stickyKey = this.sessionKeyMap.get(sessionId)!;
			const agyIdx = antigravityCredentialsList.indexOf(stickyKey);
			if (agyIdx !== -1) {
				const agyState = antigravityKeyStates[agyIdx];
				const isHealthy = !agyState?.invalid && (!agyState?.exhaustedUntil || !agyState.exhaustedUntil[modelForExhaustion] || Date.now() > (agyState.exhaustedUntil[modelForExhaustion] || 0)) && (!agyState?.exhaustedUntil || !agyState.exhaustedUntil['_general_'] || Date.now() > (agyState.exhaustedUntil['_general_'] || 0));
				if (isHealthy) {
					apiKey = stickyKey;
					antigravityIndexToUse = agyIdx;
					effectivelyAntigravity = true;
					effectivelyOAuth = false;
					isStickyUsed = true;
				}
			} else {
				const idx = apiKeys.indexOf(stickyKey);
				if (idx !== -1) {
					const keyState = keyStates[idx];
					const isHealthy = !keyState?.invalid && (!keyState?.exhaustedUntil || !keyState.exhaustedUntil[modelForExhaustion] || Date.now() > (keyState.exhaustedUntil[modelForExhaustion] || 0)) && (!keyState?.exhaustedUntil || !keyState.exhaustedUntil['_general_'] || Date.now() > (keyState.exhaustedUntil['_general_'] || 0));
					if (isHealthy) {
						apiKey = stickyKey;
						keyIndexToUse = idx;
						effectivelyOAuth = false;
						effectivelyAntigravity = false;
						isStickyUsed = true;
					}
				} else {
					const oauthIdx = oauthCredentialsList.indexOf(stickyKey);
					if (oauthIdx !== -1) {
						const oauthState = oauthKeyStates[oauthIdx];
						const isHealthy = !oauthState?.invalid && (!oauthState?.exhaustedUntil || !oauthState.exhaustedUntil[modelForExhaustion] || Date.now() > (oauthState.exhaustedUntil[modelForExhaustion] || 0)) && (!oauthState?.exhaustedUntil || !oauthState.exhaustedUntil['_general_'] || Date.now() > (oauthState.exhaustedUntil['_general_'] || 0));
						if (isHealthy) {
							apiKey = stickyKey;
							oauthIndexToUse = oauthIdx;
							effectivelyOAuth = true;
							effectivelyAntigravity = false;
							isStickyUsed = true;
						}
					}
				}
			}
		}

		if (!isStickyUsed) {
			if (isAntigravityMode) {
				antigravityIndexToUse = getStandardRotationIndex(
					antigravityCredentialsList,
					currentAntigravityIndex,
					antigravityKeyStates,
					modelForExhaustion,
					Date.now()
				);

				if (antigravityIndexToUse === null) {
					if (antigravityCredentialsList.length > 0) {
						return createErrorResponse(
							'All Antigravity OAuth credentials for your account are currently exhausted. Please try again later.',
							429,
							protocol
						);
					}
					return createErrorResponse('No Antigravity OAuth credentials configured for this account.', 401, protocol);
				}
				apiKey = antigravityCredentialsList[antigravityIndexToUse];
				effectivelyAntigravity = true;
				effectivelyOAuth = false;

				const nextAgyIndex = (antigravityIndexToUse + 1) % antigravityCredentialsList.length;
				this.currentAntigravityIndex = nextAgyIndex;
				this.ctx.state.waitUntil(this.storage.put(`antigravity_index_${userAccessToken}`, nextAgyIndex));
			} else if (isOAuthMode) {
				oauthIndexToUse = getStandardRotationIndex(
					oauthCredentialsList,
					currentOauthIndex,
					oauthKeyStates,
					modelForExhaustion,
					Date.now()
				);

				if (oauthIndexToUse === null) {
					if (oauthCredentialsList.length > 0) {
						return createErrorResponse(
							'All OAuth credentials for your account are currently exhausted. Please try again later.',
							429,
							protocol
						);
					}
					return createErrorResponse('No OAuth credentials configured for this account.', 401, protocol);
				}
				apiKey = oauthCredentialsList[oauthIndexToUse];

				// Update index in DO storage immediately after selection
				const nextOauthIndex = (oauthIndexToUse + 1) % oauthCredentialsList.length;
				this.currentOauthIndex = nextOauthIndex;
				this.ctx.state.waitUntil(this.storage.setUserOauthIndex(userAccessToken, nextOauthIndex));
			} else {
				keyIndexToUse = getStandardRotationIndex(
					apiKeys,
					currentKeyIndex,
					keyStates,
					modelForExhaustion,
					Date.now()
				);

				if (keyIndexToUse === null) {
					// Standard keys are exhausted, try fallback to OAuth
					let hasOAuthAvailable = oauthCredentialsList.length > 0;
					let oauthFallbacked = false;

					if (hasOAuthAvailable) {
						oauthIndexToUse = getStandardRotationIndex(
							oauthCredentialsList,
							currentOauthIndex,
							oauthKeyStates,
							modelForExhaustion,
							Date.now()
						);
						if (oauthIndexToUse !== null) {
							apiKey = oauthCredentialsList[oauthIndexToUse];
							effectivelyOAuth = true;
							oauthFallbacked = true;

							// Update index in DO storage immediately after selection
							const nextOauthIndex = (oauthIndexToUse + 1) % oauthCredentialsList.length;
							this.currentOauthIndex = nextOauthIndex;
							this.ctx.state.waitUntil(this.storage.setUserOauthIndex(userAccessToken, nextOauthIndex));
						}
					}

					// Trigger notification for standard key exhaustion
					this.ctx.waitUntil(this.notifyExhausted(userAccessToken, oauthFallbacked, modelForExhaustion));

					if (!apiKey) {
						return createErrorResponse(
							'All API keys (and fallback OAuth credentials) for your account are currently exhausted. Please try again later.',
							429,
							protocol
						);
					}
				} else {
					apiKey = apiKeys[keyIndexToUse];

					// Update index in DO storage immediately after selection
					const nextKeyIndex = (keyIndexToUse + 1) % apiKeys.length;
					this.currentKeyIndex = nextKeyIndex;
					this.ctx.state.waitUntil(this.storage.setUserKeyIndex(userAccessToken, nextKeyIndex));
				}
			}
		}

		const doProxy = async (apiKeyToUse: string, requestToProxy: Request, attempt = 1) => {
			const proxyReqBody =
				requestToProxy.method === 'POST'
					? await requestToProxy
							.clone()
							.text()
							.then((t) => {
								try {
									return t ? JSON.parse(t) : null;
								} catch {
									return null; // Return null if body is not JSON (e.g. multipart/form-data)
								}
							})
					: null;
			const pathname = new URL(requestToProxy.url).pathname;

			const isStreaming =
				pathname.includes(':stream') ||
				pathname.includes('streamGenerateContent') ||
				(proxyReqBody && (proxyReqBody as any).stream === true);

			let timeoutMs = this.ctx.upstreamTimeoutMs;
			if (isStreaming) {
				if (attempt === 1) {
					timeoutMs = 8000;
				} else if (attempt === 2) {
					timeoutMs = 20000;
				}
			}

			const handleGeminiRef = async (req: Request, key: string, mod?: string): Promise<Response> => {
				let bodyJson: any = null;
				if (req.method === 'POST') {
					try {
						const text = await req.clone().text();
						bodyJson = text ? JSON.parse(text) : null;
					} catch (e) {}
				}

				// Run our Unified Gemini Prompt Pruner!
				if (enablePruning && bodyJson && bodyJson.contents) {
					// 1. If it's a Claude-caching request, prune the cacheable payload too
					if (bodyJson.__claude_cache_control__) {
						const meta = bodyJson.__claude_cache_control__;
						
						const prunedCache = this.pruneGeminiContents(meta.cacheable_payload.contents);
						meta.cacheable_payload.contents = prunedCache.prunedContents;
						meta.remaining_contents_index = prunedCache.prunedContents.length;
						
						// Recalculate hash of the pruned cacheable payload
						const newPayloadStr = JSON.stringify(meta.cacheable_payload);
						meta.hash = await sha256Hex(newPayloadStr);
					}

					// 2. Prune the full contents list
					const { prunedContents, stats } = this.pruneGeminiContents(bodyJson.contents);
					bodyJson.contents = prunedContents;
					savedTokensCount = stats.savedTokens;
					
					if (stats.expiredRemoved > 0 || stats.duplicatesRemoved > 0 || stats.errorsTombstoned > 0) {
						console.log(`[Prompt Pruner] Pruned ${stats.expiredRemoved} expired parts, ${stats.duplicatesRemoved} duplicate parts. Tombstoned ${stats.errorsTombstoned} error logs. Restored ${stats.restoredCount} dependencies. Saved approx ${stats.savedTokens} tokens.`);
					}
				}

				if (bodyJson && bodyJson.__claude_cache_control__) {
					const meta = bodyJson.__claude_cache_control__;
					delete bodyJson.__claude_cache_control__; // clean up our private tag

					const resolvedModel = mod || model || 'gemini-1.5-flash';
					// Lookup DO SQLite Context Cache
					const cached = this.getGeminiContextCache(meta.hash, resolvedModel);

					if (cached) {
						console.log(`Durable Object Context Cache Hit for Claude-translate hash ${meta.hash}!`);
						// Force route to the specific key holding the cache
						key = cached.api_key;
						bodyJson.cachedContent = cached.gemini_cache_id;
						bodyJson.contents = bodyJson.contents.slice(meta.remaining_contents_index);
						delete bodyJson.system_instruction;
					} else {
						console.log(`Durable Object Context Cache Miss for Claude-translate hash ${meta.hash}. Creating cache on Google...`);
						try {
							const createUrl = `https://generativelanguage.googleapis.com/v1beta/cachedContents`;
							const createRes = await fetch(createUrl, {
								method: 'POST',
								headers: {
									'Content-Type': 'application/json',
									'x-goog-api-key': key
								},
								body: JSON.stringify({
									model: `models/${resolvedModel}`,
									contents: meta.cacheable_payload.contents,
									system_instruction: meta.cacheable_payload.system_instruction,
									ttl: "300s" // 5 minutes TTL
								})
							});

							if (createRes.ok) {
								const createData: any = await createRes.json();
								if (createData && createData.name) {
									const cacheId = createData.name;
									console.log(`Successfully created Gemini Context Cache: ${cacheId}`);
									
									// Store in our DO Local SQLite
									this.setGeminiContextCache(meta.hash, resolvedModel, cacheId, key, 300000); // 5 mins

									bodyJson.cachedContent = cacheId;
									bodyJson.contents = bodyJson.contents.slice(meta.remaining_contents_index);
									delete bodyJson.system_instruction;
								}
							} else {
								const errText = await createRes.text();
								console.warn(`Gemini Context Cache creation failed: ${createRes.status} ${errText}`);
							}
						} catch (e) {
							console.error("Error creating Gemini Context Cache dynamically:", e);
						}
					}
				}

				if (bodyJson) {
					// Rebuild the request with the modified body
					req = new Request(req.url, {
						method: req.method,
						headers: req.headers,
						body: JSON.stringify(bodyJson)
					});
				}

				if (effectivelyAntigravity) {
					return handleAntigravityCli(
						req as any,
						parseAntigravityCredentials(key),
						this.ctx.state,
						(r: Request, stream: boolean, token?: string) =>
							proxyRequest(
								r,
								stream,
								this.ctx.env.DB,
								this.ctx.waitUntil.bind(this.ctx),
								this.ctx.isLoggingEnabled,
								token,
								timeoutMs
							),
						mod,
						this.ctx,
						antigravityKeyStates
					);
				}

				return handleGemini(
					req as any,
					key,
					async (isStream: boolean) => await this.getNextApiBaseUrl(isStream, effectivelyOAuth),
					(r: Request, stream: boolean, token?: string) =>
						proxyRequest(
							r,
							stream,
							this.ctx.env.DB,
							this.ctx.waitUntil.bind(this.ctx),
							this.ctx.isLoggingEnabled,
							token,
							timeoutMs
						),
					this.ctx.state,
					mod,
					this.ctx.env.OAUTH_CLIENT_ID,
					this.ctx.env.OAUTH_CLIENT_SECRET,
					this.ctx,
					oauthKeyStates
				);
			};

			if (authMode === 'openai') {
				return handleOpenAI(
					proxyReqBody,
					pathname,
					requestToProxy.method,
					apiKeyToUse,
					model,
					handleGeminiRef as any,
					((key: string, mid: string | undefined, am: string, mod?: string) =>
						handleModels(key, mid, am, handleGeminiRef as any, mod)) as any,
					((req: any, key: string, resModel: string | undefined) =>
						handleEmbeddings(req, key, handleGeminiRef as any, resModel)) as any,
					requestToProxy,
					async (id: string, base64Bytes: string) => {
						await this.storage.put(`img_data_${id}`, base64Bytes);
						await this.storage.put(`img_expiry_${id}`, Date.now() + 3600 * 1000); // 1 hour expiry
					}
				);
			} else if (authMode === 'claude') {
				return handleClaude(
					proxyReqBody as any,
					pathname,
					requestToProxy.method,
					apiKeyToUse,
					model,
					handleGeminiRef as any,
					((key: string, mid: string | undefined, am: string, mod?: string) =>
						handleModels(key, mid, am, handleGeminiRef as any, mod)) as any
				);
			}

			return handleGeminiRef(requestToProxy, apiKeyToUse, model);
		};

		let response = await doProxy(apiKey, clonedRequest.clone() as any, 1);

		// Cache successful non-streaming response in Exact-Match Cache
		if (cacheHash && response.ok) {
			const clonedRes = response.clone();
			this.ctx.state.waitUntil((async () => {
				try {
					const resText = await clonedRes.text();
					const contentType = clonedRes.headers.get('content-type') || 'application/json';
					// Cache for 5 minutes (300,000 ms)
					this.setExactMatchCache(cacheHash!, {
						body: resText,
						status: clonedRes.status,
						headers: { 'Content-Type': contentType }
					}, 300000);
					console.log(`Successfully cached Exact-Match response for hash ${cacheHash}`);
				} catch (e) {
					console.error("Failed to write to Exact-Match cache in DO SQLite:", e);
				}
			})());
		}

		// Record initial usage using our real-time Spy Stream to guarantee non-truncated metrics
		response = this.wrapResponseWithSpyStream(
			response,
			apiKey,
			effectivelyOAuth,
			userAccessToken || '',
			authMode ?? null,
			model ?? null,
			savedTokensCount,
			isMetadataRequest
		);

		let stateChanged = false;
		let attemptCount = 1;
		let activeKeys = effectivelyOAuth ? oauthCredentialsList : apiKeys;
		let activeStates = effectivelyOAuth ? oauthKeyStates : keyStates;
		let activeIndex = effectivelyOAuth ? (oauthIndexToUse ?? 0) : (keyIndexToUse ?? 0);

		// Calculate total available retries across the current active pool
		// We limit retries to at most 3 or the number of keys available
		let maxAttempts = Math.max(1, Math.min(activeKeys.length, 3));

		while (
			[401, 403, 404, 429, 500, 502, 503, 504, 524].includes(response.status) &&
			attemptCount < maxAttempts
		) {
			const now = Date.now();
			stateChanged = true;

			// Mark current key as invalid or exhausted
			if (response.status === 401 || response.status === 403) {
				let lastErrorMsg = `API returned ${response.status}`;
				try {
					const clonedRes = response.clone();
					const bodyText = await clonedRes.text();
					if (bodyText) {
						lastErrorMsg = bodyText.substring(0, 500); // Take first 500 chars
					}
				} catch (e) {
					// Ignore
				}

				const lowercaseError = lastErrorMsg.toLowerCase();
				const hasSevereViolation = [
					"terms of service",
					"violat",
					"suspend",
					"banned",
					"abus",
					"infring"
				].some(pattern => lowercaseError.includes(pattern));

				activeStates[activeIndex] = {
					...activeStates[activeIndex],
					invalid: true,
					lastStatus: response.status,
					lastError: lastErrorMsg,
					lastTestedAt: now,
				};
				this.ctx.waitUntil(
					this.notifyInvalidToken(
						userAccessToken || '',
						effectivelyOAuth ? 'oauth' : 'api_key',
						apiKey,
						lastErrorMsg
					)
				);

				if (hasSevereViolation) {
					console.warn(`[KeyRotator] Severe policy violation or suspension detected: "${lastErrorMsg}". Aborting retry loop to prevent cascading burnout.`);
					break; // IMMEDIATELY abort the auto-retry loop!
				}
			} else if (response.status === 429) {
				const currentState = activeStates[activeIndex] || {};
				const currentExhausted = currentState.exhaustedUntil || {};
				const lastExhaustedUntil = currentExhausted[modelForExhaustion] || 0;

				let isDailyQuotaExhausted = false;
				let lastErrorMsg = 'Rate limit exceeded (429)';
				try {
					const clonedRes = response.clone();
					const bodyText = await clonedRes.text();
					if (bodyText) {
						lastErrorMsg = bodyText.substring(0, 500);
					}
					const lowerBody = bodyText.toLowerCase();

					const dailyNumberPattern1 = /\d+\s*(requests|queries|calls)?\s*\/day/i;
					const dailyNumberPattern2 = /\d+\s*(requests|queries|calls)?\s*per\s*day/i;

					if (
						lowerBody.includes('per day') ||
						lowerBody.includes('queries per day') ||
						lowerBody.includes('requests per day') ||
						lowerBody.includes('daily limit') ||
						lowerBody.includes('daily requests') ||
						lowerBody.includes('daily quota') ||
						dailyNumberPattern1.test(lowerBody) ||
						dailyNumberPattern2.test(lowerBody)
					) {
						isDailyQuotaExhausted = true;
					}
				} catch (e) {
					// Ignore body read errors
				}

				// If daily quota is exhausted, use 6 hours cooldown. Otherwise use standard exponential backoff.
				let cooldown = 60 * 1000;
				if (isDailyQuotaExhausted) {
					cooldown = 6 * 3600 * 1000; // 6 hours
				} else if (lastExhaustedUntil > now - 300 * 1000) {
					const prevCooldown = lastExhaustedUntil - (now - cooldown);
					cooldown = Math.min(Math.max(prevCooldown * 2, cooldown * 2), 1800 * 1000);
				}

				activeStates[activeIndex] = {
					...currentState,
					exhaustedUntil: {
						...currentExhausted,
						[modelForExhaustion]: now + cooldown,
					},
					lastStatus: response.status,
					lastError: lastErrorMsg,
					lastTestedAt: now,
				};
			}

			// --- Handle 404: model no longer available for this key ---
			if (response.status === 404) {
				// Read response body to detect "model unavailable" type errors vs other 404s
				const errorBody = await response.clone().text().catch(() => '');
				const isModelUnavailable = /no longer available|deprecated|unavailable for|model not found|not supported|not available/i.test(errorBody);

				if (isModelUnavailable) {
					// Mark this key as permanently unable to use this model
					const mu = activeStates[activeIndex]?.modelUnavailable ?? {};
					mu[modelForExhaustion] = true;
					activeStates[activeIndex] = { 
						...activeStates[activeIndex], 
						modelUnavailable: mu,
						lastStatus: response.status,
						lastError: errorBody.substring(0, 500),
						lastTestedAt: now,
					};
					stateChanged = true;

					// Log for observability
					console.warn(`[KeyRotator] Key ${apiKey} permanently unavailable for model "${modelForExhaustion}" (404). Skipping.`);
				} else {
					// Generic 404 (e.g. bad endpoint) — not a key problem, don't mark
				}
			}

			// Try to find NEXT key in the SAME pool
			let nextIndex = getStandardRotationIndex(
				activeKeys,
				(activeIndex + 1) % activeKeys.length,
				activeStates,
				modelForExhaustion,
				now
			);

			// If no more keys in current pool, try fallback to OAuth if we were on API keys
			if (nextIndex === null && !effectivelyOAuth && oauthCredentialsList.length > 0) {
				// Switch pool to OAuth
				effectivelyOAuth = true;
				activeKeys = oauthCredentialsList;
				activeStates = oauthKeyStates;
				// Start OAuth rotation from currentOauthIndex
				nextIndex = getStandardRotationIndex(
					activeKeys,
					currentOauthIndex,
					activeStates,
					modelForExhaustion,
					now
				);
				// If we switched pool, recalculate maxAttempts for the new pool
				if (nextIndex !== null) {
					maxAttempts = attemptCount + Math.min(activeKeys.length, 3);
				}
			}

			if (nextIndex === null || (nextIndex === activeIndex && !effectivelyOAuth)) {
				break;
			}

			// Update indices and key
			activeIndex = nextIndex;
			if (effectivelyOAuth) {
				oauthIndexToUse = nextIndex;
				// Update index in DO storage immediately after selection during retry
				const nextOauthIndex = (oauthIndexToUse + 1) % oauthCredentialsList.length;
				this.currentOauthIndex = nextOauthIndex;
				this.ctx.state.waitUntil(this.storage.setUserOauthIndex(userAccessToken, nextOauthIndex));
			} else {
				keyIndexToUse = nextIndex;
				// Update index in DO storage immediately after selection during retry
				const nextKeyIndex = (keyIndexToUse + 1) % apiKeys.length;
				this.currentKeyIndex = nextKeyIndex;
				this.ctx.state.waitUntil(this.storage.setUserKeyIndex(userAccessToken, nextKeyIndex));
			}
			const nextApiKey = activeKeys[activeIndex];
			const isDifferentKey = nextApiKey !== apiKey;
			apiKey = nextApiKey;

			if (!isDifferentKey) {
				// Exponential delay only if we are retrying on the exact same key
				const delay = 500 * Math.pow(2, attemptCount - 1);
				await sleep(delay);
			}

			attemptCount++;
			response = await doProxy(apiKey, clonedRequest.clone() as any, attemptCount);

			// Record retry usage using our real-time Spy Stream to guarantee non-truncated metrics
			response = this.wrapResponseWithSpyStream(
				response,
				apiKey,
				effectivelyOAuth,
				userAccessToken || '',
				authMode ?? null,
				model ?? null,
				savedTokensCount,
				isMetadataRequest
			);
		}

		// Implement Suggestion 1: Sync to D1 either on state change or every 10 successful requests
		let shouldSyncToDB = stateChanged;
		if (response.ok) {
			if (sessionId && apiKey) {
				this.setSessionKey(sessionId, apiKey);
			}

			if (request.url.includes('/cachedContents')) {
				this.ctx.waitUntil((async () => {
					try {
						const resJson = await response.clone().json() as any;
						if (resJson && resJson.name) {
							this.setSessionKey(resJson.name, apiKey);
						}
					} catch (e) {
						// Ignore
					}
				})());
			}

			// Preemptive Rate Limit check based on response headers
			if (!isMetadataRequest) {
				const rateLimit = this.parseRateLimitHeaders(response.headers);
				if (rateLimit.remainingRequests !== null && rateLimit.remainingRequests <= 1) {
					const cooldownMs = rateLimit.resetRequestsMs || rateLimit.retryAfterMs || 30000;
					activeStates[activeIndex] = {
						...activeStates[activeIndex],
						exhaustedUntil: {
							...activeStates[activeIndex].exhaustedUntil,
							[modelForExhaustion]: Date.now() + cooldownMs
						}
					};
					stateChanged = true;
					shouldSyncToDB = true;
				}
			}

			this.requestCountSinceSync++;
			this.ctx.state.waitUntil(this.storage.put(`sync_count_${userAccessToken}`, this.requestCountSinceSync));
			if (this.requestCountSinceSync >= 3) {
				shouldSyncToDB = true;
				this.requestCountSinceSync = 0;
				this.ctx.state.waitUntil(this.storage.put(`sync_count_${userAccessToken}`, 0));
			}
		}

		if (shouldSyncToDB) {
			let updatePromise;
			const nextKeyIndex = keyIndexToUse !== null ? (keyIndexToUse + 1) % apiKeys.length : currentKeyIndex;
			const nextOauthIndex =
				oauthIndexToUse !== null
					? (oauthIndexToUse + 1) % oauthCredentialsList.length
					: currentOauthIndex;

			if (effectivelyOAuth || oauthIndexToUse !== null) {
				updatePromise = this.ctx.env.DB.prepare(
					'UPDATE api_credentials SET current_key_index = ?, key_states = ?, current_oauth_index = ?, oauth_key_states = ? WHERE access_token = ?'
				)
					.bind(
						nextKeyIndex,
						JSON.stringify(keyStates),
						nextOauthIndex,
						JSON.stringify(oauthKeyStates),
						userAccessToken
					)
					.run();

				// Sync cache immediately!
				if (this.cachedCredentials) {
					this.cachedCredentials.key_states = JSON.stringify(keyStates);
					this.cachedCredentials.oauth_key_states = JSON.stringify(oauthKeyStates);
				}
			} else {
				updatePromise = this.ctx.env.DB.prepare(
					'UPDATE api_credentials SET current_key_index = ?, key_states = ? WHERE access_token = ?'
				)
					.bind(nextKeyIndex, JSON.stringify(keyStates), userAccessToken)
					.run();

				// Sync cache immediately!
				if (this.cachedCredentials) {
					this.cachedCredentials.key_states = JSON.stringify(keyStates);
				}
			}
			this.ctx.waitUntil(updatePromise);
		}

		// Fully delegated logging check inside Durable Object
		if (dbResult && dbResult.enable_logging === 1) {
			const originalUrl = request.headers.get("X-Original-Url") || request.url;
			const logRequest = new Request(originalUrl, clonedRequest as any);
			this.ctx.state.waitUntil(writeCombinedLog(this.ctx.env as any, logRequest, response.clone(), startTime, userAccessToken || undefined));
		}

		return response;
	}

	private parseRateLimitHeaders(headers: Headers) {
		const remaining = headers.get('x-ratelimit-remaining-requests');
		const reset = headers.get('x-ratelimit-reset-requests'); // e.g. "14.5s", "2m"
		const retryAfter = headers.get('retry-after'); // e.g. "15" (seconds)

		return {
			remainingRequests: remaining ? parseInt(remaining, 10) : null,
			resetRequestsMs: reset ? this.parseResetTimeToMs(reset) : null,
			retryAfterMs: retryAfter ? parseInt(retryAfter, 10) * 1000 : null,
		};
	}

	private parseResetTimeToMs(resetStr: string): number {
		if (resetStr.endsWith('ms')) return parseFloat(resetStr) || 1000;
		if (resetStr.endsWith('s')) return (parseFloat(resetStr) * 1000) || 1000;
		if (resetStr.endsWith('m')) return (parseFloat(resetStr) * 60 * 1000) || 60000;
		if (resetStr.endsWith('h')) return (parseFloat(resetStr) * 3600 * 1000) || 3600000;
		if (resetStr.endsWith('d')) return (parseFloat(resetStr) * 24 * 3600 * 1000) || 86400000;
		return parseInt(resetStr, 10) * 1000 || 60000;
	}
}

export async function extractUsageFromResponse(response: Response, mode: string): Promise<{ promptTokens: number, completionTokens: number, cachedTokens: number }> {
	let promptTokens = 0;
	let completionTokens = 0;
	let cachedTokens = 0;

	try {
		const cloned = response.clone();
		if (cloned.headers.get('content-type')?.includes('text/event-stream')) {
			// Read the stream to find usage using high-performance regex on stream chunks
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

			// 1. Parse Gemini usageMetadata if present
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

			// 2. Parse Claude / OpenAI (independent tokens parsing to handle split SSE formats like in Claude)
			const promptTokensMatch = buffer.match(/"(?:input_tokens|prompt_tokens)"\s*:\s*(\d+)/);
			if (promptTokensMatch) {
				promptTokens = parseInt(promptTokensMatch[1], 10);
			}

			// Search for all occurrences of completion/output tokens and take the maximum (bypasses initial 0 output_tokens)
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
					if (Array.isArray(data)) {
						const lastElement = data[data.length - 1];
						usage = lastElement?.usageMetadata || (lastElement?.candidates && lastElement.candidates[0]?.usageMetadata);
					} else {
						usage = data.usageMetadata || (data.candidates && data.candidates[0]?.usageMetadata);
					}
					if (usage) {
						promptTokens = usage.promptTokenCount || 0;
						completionTokens = usage.candidatesTokenCount || 0;
						cachedTokens = usage.cachedContentTokenCount || 0;
					}
				}
			} catch {
				// Fallback regex match if JSON parse fails
				const usageMetadataMatch = text.match(/"usageMetadata"\s*:\s*\{([^}]+)\}/);
				if (usageMetadataMatch) {
					const inner = usageMetadataMatch[1];
					const promptMatch = inner.match(/"promptTokenCount"\s*:\s*(\d+)/);
					const candidatesMatch = inner.match(/"candidatesTokenCount"\s*:\s*(\d+)/);
					const cachedMatch = inner.match(/"cachedContentTokenCount"\s*:\s*(\d+)/);
					if (promptMatch) promptTokens = parseInt(promptMatch[1], 10);
					if (candidatesMatch) completionTokens = parseInt(candidatesMatch[1], 10);
					if (cachedMatch) cachedTokens = parseInt(cachedMatch[1], 10);
				} else {
					const promptTokensMatch = text.match(/"(?:input_tokens|prompt_tokens)"\s*:\s*(\d+)/);
					if (promptTokensMatch) promptTokens = parseInt(promptTokensMatch[1], 10);

					const completionRegex = /"(?:output_tokens|completion_tokens)"\s*:\s*(\d+)/g;
					let match;
					let maxCompletion = 0;
					while ((match = completionRegex.exec(text)) !== null) {
						const val = parseInt(match[1], 10);
						if (val > maxCompletion) maxCompletion = val;
					}
					completionTokens = maxCompletion;
				}
			}
		}
	} catch (e) {
		console.error('Error extracting usage from response:', e);
	}

	return { promptTokens, completionTokens, cachedTokens };
}

async function sha256Hex(plain: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(plain);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
