/**
 * Common SSE stream parsing logic for Gemini responses.
 */
export function parseStream(this: any, chunk: string, controller: any) {
	this.buffer = (this.buffer || '') + chunk;
	// Support both \n and \r\n, and handle potential double newlines separating SSE messages
	const lines = this.buffer.split(/\r?\n/);
	// Keep the last partial line in the buffer
	this.buffer = lines.pop()!;
	
	for (const line of lines) {
		const trimmedLine = line.trim();
		if (!trimmedLine) continue;
		
		if (trimmedLine.startsWith('data: ')) {
			const data = trimmedLine.substring(6).trim();
			// Gemini SSE sometimes sends empty data lines or keep-alives
			if (!data || data === '[DONE]') continue;
			
			if (data.startsWith('{')) {
				try {
					controller.enqueue(JSON.parse(data));
				} catch (e) {
					console.error('Error parsing stream JSON:', e, 'Data:', data);
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
