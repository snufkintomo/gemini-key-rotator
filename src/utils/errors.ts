export type Protocol = 'openai' | 'claude' | 'google';

export function createErrorResponse(
	message: string,
	status: number,
	protocol: Protocol | string | null = 'google'
): Response {
	let body: any;
	const safeProtocol = protocol === 'openai' || protocol === 'claude' ? protocol : 'google';

	if (safeProtocol === 'openai') {
		body = {
			error: {
				message: message,
				type: 'invalid_request_error',
				param: null,
				code:
					status >= 500
						? 'internal_server_error'
						: status === 429
						? 'rate_limit_exceeded'
						: 'invalid_request_error',
			},
		};
	} else if (safeProtocol === 'claude') {
		body = {
			type: 'error',
			error: {
				type: status >= 500 ? 'api_error' : status === 429 ? 'rate_limit_error' : 'invalid_request_error',
				message: message,
			},
		};
	} else {
		// Default to Gemini/Google format
		const geminiStatus =
			status === 401
				? 'UNAUTHENTICATED'
				: status === 403
				? 'PERMISSION_DENIED'
				: status === 429
				? 'RESOURCE_EXHAUSTED'
				: status >= 500
				? 'INTERNAL'
				: 'INVALID_ARGUMENT';
		body = {
			error: {
				code: status,
				message: message,
				status: geminiStatus,
			},
		};
	}

	return new Response(JSON.stringify(body), {
		status: status,
		headers: { 'Content-Type': 'application/json;charset=UTF-8' },
	});
}
