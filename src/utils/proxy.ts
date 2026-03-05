export async function proxyRequest(
	request: Request,
	isStreaming: boolean,
	db: D1Database,
	waitUntil: (promise: Promise<any>) => void,
	enableLogging: boolean,
	accessToken?: string
): Promise<Response> {
	const startTime = Date.now();

	let requestHeaders: string = '{}';
	let requestBodyStr: string = '';

	if (enableLogging) {
		const headersObj: { [key: string]: string } = {};
		request.headers.forEach((v, k) => (headersObj[k] = v));
		requestHeaders = JSON.stringify(headersObj);
		try {
			// Only try to read body if it's not a GET/HEAD request
			if (!['GET', 'HEAD'].includes(request.method)) {
				const logClone = request.clone();
				requestBodyStr = await logClone.text();
			}
		} catch (e) {
			requestBodyStr = '[Body Read Error]';
		}
	}

	const doFetch = (req: Request) => fetch(req.url, req);

	const doFetchWithContentRetry = async (originalReq: Request): Promise<Response> => {
		const maxContentRetries = 3;
		for (let i = 0; i < maxContentRetries; i++) {
			const currentReq = originalReq.clone();
			const response = await doFetch(currentReq as any);
			if (!response.ok) return response;

			if (isStreaming) {
				if (!response.body) {
					if (i < maxContentRetries - 1) await new Promise((res) => setTimeout(res, 1000));
					continue;
				}
				return response;
			} else {
				const clonedResponse = response.clone();
				try {
					await clonedResponse.json();
					return response;
				} catch (e) {
					/* ignore and retry */
				}
			}
			if (i < maxContentRetries - 1) await new Promise((res) => setTimeout(res, 1500 * (i + 1)));
		}

		const errorResponse = {
			error: {
				code: 503,
				message: 'Upstream API failed to provide a valid response.',
				status: 'SERVICE_UNAVAILABLE',
			},
		};
		return new Response(JSON.stringify(errorResponse), {
			status: 503,
			headers: { 'Content-Type': 'application/json;charset=UTF-8' },
		});
	};

	let response = await doFetchWithContentRetry(request);

	if (enableLogging) {
		const duration = Date.now() - startTime;
		const responseStatus = response.status;

		const resHeadersObj: { [key: string]: string } = {};
		response.headers.forEach((v, k) => (resHeadersObj[k] = v));
		const responseHeaders = JSON.stringify(resHeadersObj);

		let responseBodyStr = '';
		if (isStreaming) {
			responseBodyStr = '[STREAMING_RESPONSE]';
		} else {
			try {
				responseBodyStr = await response.clone().text();
			} catch {
				responseBodyStr = '[Body Read Error]';
			}
		}
		waitUntil(
			db
				.prepare(
					`
				INSERT INTO api_logs (
					timestamp, access_token, request_method, request_url, 
					request_headers, request_body, response_status, 
					response_headers, response_body, duration_ms
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`
				)
				.bind(
					new Date().toISOString(),
					accessToken || null,
					request.method,
					request.url,
					requestHeaders,
					requestBodyStr,
					responseStatus,
					responseHeaders,
					responseBodyStr,
					duration
				)
				.run()
		);
	}

	const maxRetries = 3;
	for (let i = 0; i < maxRetries && [500, 502, 503, 524].includes(response.status); i++) {
		await new Promise((res) => setTimeout(res, 1000 * (i + 1)));
		response = await doFetchWithContentRetry(request);
	}

	return response;
}
