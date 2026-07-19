import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { proxyRequest } from './proxy';

describe('proxyRequest Integration & Safety', () => {
    let originalFetch: typeof fetch;

    beforeEach(() => {
        originalFetch = globalThis.fetch;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
        vi.restoreAllMocks();
    });

    it('should preserve request method, headers, and body correctly when proxying', async () => {
        const mockResponse = new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

        const fetchSpy = vi.fn().mockResolvedValue(mockResponse);
        globalThis.fetch = fetchSpy;

        const requestHeaders = new Headers();
        requestHeaders.set('Content-Type', 'application/json');
        requestHeaders.set('Authorization', 'Bearer test-token');
        requestHeaders.set('Custom-Header', 'custom-value');

        const requestBody = JSON.stringify({ message: 'hello world' });
        const request = new Request('https://upstream-api.com/v1/chat/completions', {
            method: 'POST',
            headers: requestHeaders,
            body: requestBody
        });

        const mockDB = {
            prepare: vi.fn().mockReturnThis(),
            bind: vi.fn().mockReturnThis(),
            run: vi.fn().mockResolvedValue({ success: true }),
        } as any;

        const response = await proxyRequest(
            request,
            false, // isStreaming
            mockDB,
            vi.fn(), // waitUntil
            false, // enableLogging
            'access-token'
        );

        expect(response.status).toBe(200);

        // Verify that global fetch was called
        expect(fetchSpy).toHaveBeenCalledTimes(1);

        // Verify that the request passed to fetch preserves the original method, headers, and body!
        const forwardedCallArg = fetchSpy.mock.calls[0][0];
        
        // It should be passed either as a Request object or a URL/Request parameter
        if (forwardedCallArg instanceof Request) {
            expect(forwardedCallArg.method).toBe('POST');
            expect(forwardedCallArg.headers.get('Content-Type')).toBe('application/json');
            expect(forwardedCallArg.headers.get('Authorization')).toBe('Bearer test-token');
            expect(forwardedCallArg.headers.get('Custom-Header')).toBe('custom-value');
            
            const bodyText = await forwardedCallArg.text();
            expect(bodyText).toBe(requestBody);
        } else {
            // If it is passed as URL, the second parameter should be the options
            const options = fetchSpy.mock.calls[0][1];
            expect(options.method).toBe('POST');
            expect(options.headers.get('Content-Type')).toBe('application/json');
            expect(options.headers.get('Authorization')).toBe('Bearer test-token');
        }
    });

    it('should gracefully handle timeout AbortError and return 504 status', async () => {
        // Mock fetch throwing AbortError
        const abortError = new DOMException('The user aborted a request.', 'AbortError');
        const fetchSpy = vi.fn().mockRejectedValue(abortError);
        globalThis.fetch = fetchSpy;

        const request = new Request('https://upstream-api.com/v1/chat/completions', {
            method: 'POST',
            body: JSON.stringify({ message: 'test' })
        });

        const mockDB = {
            prepare: vi.fn().mockReturnThis(),
            bind: vi.fn().mockReturnThis(),
            run: vi.fn().mockResolvedValue({ success: true }),
        } as any;

        const response = await proxyRequest(
            request,
            false, // isStreaming
            mockDB,
            vi.fn(), // waitUntil
            false, // enableLogging
            'access-token'
        );

        expect(response.status).toBe(504);
        const body = await response.json<any>();
        expect(body.error.code).toBe(504);
        expect(body.error.message).toContain('timed out');
    });
});
