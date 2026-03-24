import { describe, it, expect, vi, beforeAll } from 'vitest';

// We need to mock some browser/worker APIs that might not be available in node environment if not using the workers pool
// But vitest's node environment usually lacks crypto.subtle

// Helper functions copied/extracted from index.ts or re-implemented for testing
// In a real scenario, we might want to export these from index.ts if possible

async function sha256(plain: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return crypto.subtle.digest('SHA-256', data);
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const verifier = arrayBufferToBase64Url(array.buffer);
    const challengeBuffer = await sha256(verifier);
    const challenge = arrayBufferToBase64Url(challengeBuffer);
    return { verifier, challenge };
}

async function getDerivedKey(secret: string): Promise<CryptoKey> {
    const secretBuffer = new TextEncoder().encode(secret);
    const hashBuffer = await crypto.subtle.digest('SHA-256', secretBuffer);
    return crypto.subtle.importKey('raw', hashBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

describe('Authentication Utilities', () => {
  it('should generate valid PKCE verifier and challenge', async () => {
    const { verifier, challenge } = await generatePKCE();
    expect(verifier).toBeDefined();
    expect(challenge).toBeDefined();
    expect(verifier.length).toBeGreaterThan(40);
    expect(challenge.length).toBeGreaterThan(40);
  });

  it('should be able to encrypt and decrypt data using derived key', async () => {
    const secret = 'test-secret-key-1234567890';
    const key = await getDerivedKey(secret);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = JSON.stringify({ token: secret, expiry: Date.now() + 1000 });
    const encodedData = new TextEncoder().encode(data);

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encodedData
    );

    expect(encrypted).toBeDefined();

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );

    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe(data);
    const parsed = JSON.parse(decryptedText);
    expect(parsed.token).toBe(secret);
  });

  it('should fail decryption with wrong key', async () => {
    const secret = 'correct-secret';
    const wrongSecret = 'wrong-secret';
    const key = await getDerivedKey(secret);
    const wrongKey = await getDerivedKey(wrongSecret);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode('secret message');

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    await expect(crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      wrongKey,
      encrypted
    )).rejects.toThrow();
  });
});
