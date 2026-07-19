export function sanitizeLogBody(bodyStr: string, maxTextLength = 50000): string {
	if (!bodyStr) return '';
	if (bodyStr.length < 500) return bodyStr; // No need to process small payloads

	try {
		const parsed = JSON.parse(bodyStr);
		const sanitized = sanitizeObject(parsed, maxTextLength);
		return JSON.stringify(sanitized);
	} catch {
		// Fallback: If not JSON or fails to parse, check for Base64 URLs and truncate length safely
		return sanitizePlainString(bodyStr, maxTextLength);
	}
}

function sanitizeObject(obj: any, maxTextLength: number): any {
	if (obj === null || obj === undefined) return obj;

	if (Array.isArray(obj)) {
		return obj.map((item) => sanitizeObject(item, maxTextLength));
	}

	if (typeof obj === 'object') {
		const newObj: any = {};
		for (const [key, value] of Object.entries(obj)) {
			if (typeof value === 'string') {
				// Detect base64 data URLs
				if (value.startsWith('data:') && value.includes(';base64,')) {
					const parts = value.split(',');
					const header = parts[0];
					const length = parts[1]?.length || 0;
					newObj[key] = `${header},[Truncated Base64 Data: ${length} characters]`;
				} else if (
					key === 'data' &&
					(obj.mimeType || obj.mime_type || obj.format || value.length > 5000) &&
					isLikelyBase64(value)
				) {
					newObj[key] = `[Truncated Base64 Data: ${value.length} characters]`;
				} else if (value.length > maxTextLength) {
					newObj[key] =
						value.substring(0, maxTextLength) +
						`... [Truncated, original length: ${value.length} characters]`;
				} else {
					newObj[key] = value;
				}
			} else if (typeof value === 'object') {
				newObj[key] = sanitizeObject(value, maxTextLength);
			} else {
				newObj[key] = value;
			}
		}
		return newObj;
	}

	return obj;
}

function isLikelyBase64(str: string): boolean {
	if (str.length < 100) return false;
	// Check if it looks like standard Base64 characters (alphanumeric, +, /, optional padding =)
	const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
	// Sample the prefix first to avoid regex CPU timeout on extremely long strings
	const sample = str.substring(0, 100).replace(/\s/g, '');
	return base64Regex.test(sample);
}

function sanitizePlainString(str: string, maxTextLength: number): string {
	// Replace inline base64 data URLs in plain text using regex
	let cleaned = str.replace(/(data:[a-zA-Z0-9/+-]+;base64,)[A-Za-z0-9+/=]{100,}/g, (match, p1) => {
		return `${p1}[Truncated Base64 Data: ${match.length - p1.length} characters]`;
	});

	if (cleaned.length > maxTextLength) {
		cleaned = cleaned.substring(0, maxTextLength) + `... [Truncated, original length: ${cleaned.length} characters]`;
	}
	return cleaned;
}
