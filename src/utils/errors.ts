export type Protocol = 'openai' | 'claude' | 'gemini';

export function createErrorResponse(message: string, status: number, protocol: Protocol | null): Response {
	let body: any;

	if (protocol === 'openai') {
		body = {
			error: {
				message: message,
				type: 'invalid_request_error',
				param: null,
				code: status.toString(),
			},
		};
	} else if (protocol === 'claude') {
		body = {
			type: 'error',
			error: {
				type: 'invalid_request_error',
				message: message,
			},
		};
	} else {
		// Default to Gemini format
		body = {
			error: {
				code: status,
				message: message,
				status: 'INVALID_ARGUMENT',
			},
		};
	}

	return new Response(JSON.stringify(body), {
		status: status,
		headers: { 'Content-Type': 'application/json;charset=UTF-8' },
	});
}
