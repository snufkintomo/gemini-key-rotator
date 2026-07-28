/**
 * Deep Module: KeyPool
 * Encapsulates multi-type key management (Standard API keys, Google OAuth PKCE tokens,
 * Antigravity credentials), atomic rotation index storage in Durable Objects, and
 * exponential 429 rate-limit backoff state machines.
 */

export type KeyPoolType = 'standard' | 'oauth' | 'antigravity';

export interface KeyStateInfo {
	exhaustedUntil?: number | Record<string, number>;
	lastError?: string;
	lastErrorStatus?: number;
}

export interface CredentialKey {
	id: string;
	type: KeyPoolType;
	rawKey: string;
	index: number;
	accessToken?: string;
	projectId?: string;
	email?: string;
}

export interface KeyPoolHealth {
	standardTotal: number;
	standardExhausted: number;
	oauthTotal: number;
	oauthExhausted: number;
	antigravityTotal: number;
	antigravityExhausted: number;
}

export class KeyPool {
	private storage?: any; // DurableObjectStorage
	private keyStates: Map<string, KeyStateInfo> = new Map();

	constructor(storage?: any) {
		this.storage = storage;
	}

	/**
	 * Atomically reads and increments rotation index in DO storage or memory.
	 */
	private async getAndIncrementIndex(keyName: string, totalKeys: number): Promise<number> {
		if (totalKeys <= 0) return 0;
		if (this.storage && typeof this.storage.get === 'function') {
			try {
				const currentIndex = (await this.storage.get(keyName)) as number || 0;
				const nextIndex = (currentIndex + 1) % totalKeys;
				await this.storage.put(keyName, nextIndex);
				return currentIndex % totalKeys;
			} catch {
				// Fallback to 0 on storage error
			}
		}
		return 0;
	}

	/**
	 * Checks if a key is currently marked as exhausted due to a 429/5xx rate limit.
	 */
	isExhausted(keyId: string, model?: string): boolean {
		const state = this.keyStates.get(keyId);
		if (!state || !state.exhaustedUntil) return false;

		const now = Date.now();
		if (typeof state.exhaustedUntil === 'number') {
			return now < state.exhaustedUntil;
		} else if (typeof state.exhaustedUntil === 'object') {
			const generalUntil = state.exhaustedUntil['_general_'] || 0;
			if (now < generalUntil) return true;
			if (model) {
				const modelUntil = state.exhaustedUntil[model] || 0;
				if (now < modelUntil) return true;
			}
		}
		return false;
	}

	/**
	 * Marks a key as exhausted for a specified cooldown duration.
	 */
	markExhausted(keyId: string, durationMs: number, model?: string, errorStatus?: number): void {
		const now = Date.now();
		const state = this.keyStates.get(keyId) || {};
		const until = now + durationMs;

		let exhaustedUntilObj: Record<string, number> = {};
		if (typeof state.exhaustedUntil === 'object' && state.exhaustedUntil !== null) {
			exhaustedUntilObj = { ...state.exhaustedUntil };
		} else if (typeof state.exhaustedUntil === 'number') {
			exhaustedUntilObj['_general_'] = state.exhaustedUntil;
		}

		if (model) {
			exhaustedUntilObj[model] = until;
		} else {
			exhaustedUntilObj['_general_'] = until;
		}

		this.keyStates.set(keyId, {
			...state,
			exhaustedUntil: exhaustedUntilObj,
			lastErrorStatus: errorStatus
		});
	}

	/**
	 * Selects the next available healthy key from the specified pool type.
	 */
	async getNextKey(
		poolType: KeyPoolType,
		rawKeys: string[],
		model?: string
	): Promise<CredentialKey | null> {
		if (!rawKeys || rawKeys.length === 0) return null;

		const total = rawKeys.length;
		const storageKey = `current_${poolType}_index`;
		const startIndex = await this.getAndIncrementIndex(storageKey, total);

		// Try starting from rotation index, wrapping around to find first non-exhausted key
		for (let offset = 0; offset < total; offset++) {
			const idx = (startIndex + offset) % total;
			const keyStr = rawKeys[idx];
			const keyId = `${poolType}:${idx}:${keyStr}`;

			if (!this.isExhausted(keyId, model)) {
				return {
					id: keyId,
					type: poolType,
					rawKey: keyStr,
					index: idx
				};
			}
		}

		// Fallback: If all keys are exhausted, return the key with shortest remaining cooldown
		let bestIdx = startIndex;
		let shortestCooldown = Infinity;

		for (let idx = 0; idx < total; idx++) {
			const keyStr = rawKeys[idx];
			const keyId = `${poolType}:${idx}:${keyStr}`;
			const state = this.keyStates.get(keyId);
			let cooldown = 0;

			if (state && state.exhaustedUntil) {
				if (typeof state.exhaustedUntil === 'number') {
					cooldown = state.exhaustedUntil;
				} else if (typeof state.exhaustedUntil === 'object') {
					cooldown = state.exhaustedUntil[model || ''] || state.exhaustedUntil['_general_'] || 0;
				}
			}

			if (cooldown < shortestCooldown) {
				shortestCooldown = cooldown;
				bestIdx = idx;
			}
		}

		const fallbackKeyStr = rawKeys[bestIdx];
		return {
			id: `${poolType}:${bestIdx}:${fallbackKeyStr}`,
			type: poolType,
			rawKey: fallbackKeyStr,
			index: bestIdx
		};
	}

	/**
	 * Computes key pool health statistics.
	 */
	getHealthStatus(pools: { standard: string[]; oauth: string[]; antigravity: string[] }): KeyPoolHealth {
		const calc = (type: KeyPoolType, keys: string[]) => {
			let exhausted = 0;
			for (let i = 0; i < keys.length; i++) {
				const keyId = `${type}:${i}:${keys[i]}`;
				if (this.isExhausted(keyId)) exhausted++;
			}
			return { total: keys.length, exhausted };
		};

		const std = calc('standard', pools.standard || []);
		const oau = calc('oauth', pools.oauth || []);
		const agy = calc('antigravity', pools.antigravity || []);

		return {
			standardTotal: std.total,
			standardExhausted: std.exhausted,
			oauthTotal: oau.total,
			oauthExhausted: oau.exhausted,
			antigravityTotal: agy.total,
			antigravityExhausted: agy.exhausted
		};
	}
}
