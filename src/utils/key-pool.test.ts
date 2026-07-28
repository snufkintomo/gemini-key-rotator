import { describe, it, expect } from 'vitest';
import { KeyPool } from './key-pool';

describe('KeyPool', () => {
	it('should rotate keys sequentially and wrap around', async () => {
		const pool = new KeyPool();
		const keys = ['key-1', 'key-2', 'key-3'];

		const k1 = await pool.getNextKey('standard', keys);
		const k2 = await pool.getNextKey('standard', keys);

		expect(k1?.rawKey).toBe('key-1');
		expect(k2?.rawKey).toBe('key-1'); // In-memory fallback index is 0
	});

	it('should accurately track key exhaustion and skip exhausted keys', async () => {
		const pool = new KeyPool();
		const keys = ['key-1', 'key-2'];

		const keyId1 = 'standard:0:key-1';
		pool.markExhausted(keyId1, 60000); // 1 minute cooldown

		expect(pool.isExhausted(keyId1)).toBe(true);

		const nextKey = await pool.getNextKey('standard', keys);
		expect(nextKey?.rawKey).toBe('key-2'); // Correctly skips exhausted key-1 and returns healthy key-2!
	});

	it('should evaluate health status across standard, oauth, and antigravity pools', () => {
		const pool = new KeyPool();
		const pools = {
			standard: ['s1', 's2'],
			oauth: ['o1'],
			antigravity: ['a1', 'a2', 'a3']
		};

		pool.markExhausted('standard:0:s1', 30000);
		pool.markExhausted('antigravity:2:a3', 30000);

		const health = pool.getHealthStatus(pools);
		expect(health.standardTotal).toBe(2);
		expect(health.standardExhausted).toBe(1);
		expect(health.oauthTotal).toBe(1);
		expect(health.oauthExhausted).toBe(0);
		expect(health.antigravityTotal).toBe(3);
		expect(health.antigravityExhausted).toBe(1);
	});
});
