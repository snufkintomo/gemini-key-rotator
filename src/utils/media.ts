/**
 * Helper to fetch and encode remote media (images, audio, etc.)
 */
export async function fetchAndEncodeMedia(url: string, typeName: string = 'Media'): Promise<{ inlineData: { mimeType: string, data: string } } | { text: string }> {
	if (url.startsWith('data:')) {
		const [header, base64Data] = url.split(',');
		const mimeType = header.match(/:(.*?);/)?.[1];
		if (mimeType && base64Data) return { inlineData: { mimeType, data: base64Data } };
		return { text: `[Invalid data URL for ${typeName}]` };
	}

	try {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 10000);

		// Pro-tier: Check size before downloading to stay within Worker memory limits
		const headResponse = await fetch(url, {
			method: 'HEAD',
			signal: controller.signal,
			headers: { 'User-Agent': 'Mozilla/5.0' },
		});

		if (headResponse.ok) {
			const contentLength = parseInt(headResponse.headers.get('content-length') || '0');
			if (contentLength > 10 * 1024 * 1024) { // 10MB limit
				return { text: `[${typeName} too large: ${contentLength} bytes]` };
			}
		}

		const mediaResponse = await fetch(url, {
			signal: controller.signal,
			headers: { 'User-Agent': 'Mozilla/5.0' },
		});
		clearTimeout(timeoutId);

		if (mediaResponse.ok) {
			const mimeType = mediaResponse.headers.get('content-type') || 'application/octet-stream';
			const buffer = await mediaResponse.arrayBuffer();
			const base64Data = btoa(String.fromCharCode(...new Uint8Array(buffer)));
			return { inlineData: { mimeType, data: base64Data } };
		} else {
			console.warn(`Failed to fetch remote ${typeName}: ${url}, status: ${mediaResponse.status}`);
			return { text: `[${typeName} Fetch Failed: ${url}]` };
		}
	} catch (e: any) {
		console.warn(`Failed to fetch remote ${typeName}: ${url}`, e);
		return { text: `[${typeName} Fetch Failed: ${url}: ${e.message}]` };
	}
}
