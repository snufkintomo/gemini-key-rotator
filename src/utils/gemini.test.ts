import { describe, it, expect } from 'vitest';
import { safeLiteCompress } from './gemini';

describe('safeLiteCompress', () => {
    it('should safely trim trailing whitespace from lines', () => {
        const contents = [
            {
                role: 'user',
                parts: [
                    { text: 'line 1   \nline 2\t\nline 3' }
                ]
            }
        ];

        const result = safeLiteCompress(contents);
        expect(result[0].parts[0].text).toBe('line 1\nline 2\nline 3');
    });

    it('should collapse 3 or more consecutive newlines to maximum of 2 newlines (1 blank line)', () => {
        const contents = [
            {
                role: 'user',
                parts: [
                    { text: 'hello\n\n\nworld\n\n\n\n\nnext' }
                ]
            }
        ];

        const result = safeLiteCompress(contents);
        expect(result[0].parts[0].text).toBe('hello\n\nworld\n\nnext');
    });

    it('should trim leading and trailing outer whitespace of the entire text', () => {
        const contents = [
            {
                role: 'user',
                parts: [
                    { text: '   \n  hello world  \n   ' }
                ]
            }
        ];

        const result = safeLiteCompress(contents);
        expect(result[0].parts[0].text).toBe('hello world');
    });

    it('should ignore non-text parts (e.g. image, inlineData, functionCall)', () => {
        const contents = [
            {
                role: 'user',
                parts: [
                    { inlineData: { mimeType: 'image/png', data: 'base64...' } },
                    { text: '  text block  \n\n\n' }
                ]
            }
        ];

        const result = safeLiteCompress(contents);
        // First part remains unchanged
        expect(result[0].parts[0]).toEqual({ inlineData: { mimeType: 'image/png', data: 'base64...' } });
        // Second part is compressed
        expect(result[0].parts[1].text).toBe('text block');
    });

    it('should handle empty contents, empty parts, or invalid objects gracefully', () => {
        expect(safeLiteCompress([])).toEqual([]);
        expect(safeLiteCompress(null as any)).toBeNull();
        expect(safeLiteCompress([{ role: 'user' } as any])).toEqual([{ role: 'user' }]);
    });
});
