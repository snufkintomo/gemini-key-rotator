import * as cookie from 'cookie';
import type { Env, Admin } from '../index';

export async function sha256(plain: string): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return crypto.subtle.digest('SHA-256', data);
}

export function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
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

export async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const verifier = arrayBufferToBase64Url(array.buffer);
    const challengeBuffer = await sha256(verifier);
    const challenge = arrayBufferToBase64Url(challengeBuffer);
    return { verifier, challenge };
}

export async function getDerivedKey(secret: string): Promise<CryptoKey> {
    const secretBuffer = new TextEncoder().encode(secret);
    const hashBuffer = await crypto.subtle.digest('SHA-256', secretBuffer);
    return crypto.subtle.importKey('raw', hashBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function verifyLogin(request: Request, env: Env): Promise<Admin | null> {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return null;

    const cookies = cookie.parse(cookieHeader);
    const sessionCookie = cookies['session'];
    if (!sessionCookie) return null;

    const [ivHex, encryptedHex] = sessionCookie.split('.');
    if (!ivHex || !encryptedHex) return null;

    try {
        const secret = env.ADMIN_OAUTH_CLIENT_SECRET || env.ADMIN_ACCESS_TOKEN || "fixed-fallback-secret";
        const key = await getDerivedKey(secret);
        const iv = new Uint8Array(ivHex.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));
        const encrypted = new Uint8Array(encryptedHex.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );

        const decryptedText = new TextDecoder().decode(decrypted);
        const session = JSON.parse(decryptedText);

        if (Date.now() > session.expiry) return null;

        // Verify admin still exists in DB
        const admin = await env.DB.prepare("SELECT id, email, role FROM admins WHERE id = ?").bind(session.adminId).first<Admin>();
        return admin || null;
    } catch (e) {
        console.error("Cookie decryption failed:", e);
        return null;
    }
}
