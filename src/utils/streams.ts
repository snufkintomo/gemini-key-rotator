/**
 * Common SSE stream parsing logic for Gemini responses.
 */
export function parseStream(this: any, chunk: string, controller: any) {
	this.buffer = (this.buffer || '') + chunk;
	const lines = this.buffer.split(/\r?\n/);
	this.buffer = lines.pop()!;
	for (const line of lines) {
		const trimmedLine = line.trim();
		if (trimmedLine.startsWith('data: ')) {
			const data = trimmedLine.substring(6).trim();
			if (data.startsWith('{')) {
				try {
					controller.enqueue(JSON.parse(data));
				} catch (e) {
					console.error('Error parsing stream JSON:', e);
				}
			}
		}
	}
}

/**
 * Flush handler for stream parsing.
 */
export function parseStreamFlush(this: any, controller: any) {
	if (this.buffer) {
		const trimmedBuffer = this.buffer.trim();
		if (trimmedBuffer.startsWith('data: ')) {
			const data = trimmedBuffer.substring(6).trim();
			try {
				controller.enqueue(JSON.parse(data));
			} catch (e) {
				// Silent fail
			}
		} else if (trimmedBuffer.startsWith('{')) {
			try {
				controller.enqueue(JSON.parse(trimmedBuffer));
			} catch (e) {
				// Silent fail
			}
		}
	}
}
