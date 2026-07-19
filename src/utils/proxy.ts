import { sanitizeLogBody } from './sanitize';

export async function proxyRequest(
	request: Request,
	isStreaming: boolean,
	db: D1Database,
	waitUntil: (promise: Promise<any>) => void,
	enableLogging: boolean,
	accessToken?: string,
	timeoutMs?: number
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
				const rawBody = await logClone.text();
				requestBodyStr = sanitizeLogBody(rawBody);
			}
		} catch (e) {
			requestBodyStr = '[Body Read Error]';
		}
	}

	const doFetchWithTimeout = async (req: Request, currentTimeoutMs = timeoutMs ?? 15000): Promise<Response> => {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), currentTimeoutMs);
		try {
			const response = await fetch(req, {
				signal: controller.signal
			});
			clearTimeout(timeoutId);
			return response;
		} catch (e: any) {
			clearTimeout(timeoutId);
			if (e.name === 'AbortError') {
				return new Response(JSON.stringify({
					error: {
						code: 504,
						message: 'Upstream request timed out (connection/headers).',
						status: 'GATEWAY_TIMEOUT'
					}
				}), {
					status: 504,
					headers: { 'Content-Type': 'application/json;charset=UTF-8' }
				});
			}
			throw e;
		}
	};

	const doFetchWithContentRetry = async (originalReq: Request): Promise<Response> => {
		const maxContentRetries = 3;
		for (let i = 0; i < maxContentRetries; i++) {
			const currentReq = originalReq.clone();
			const response = await doFetchWithTimeout(currentReq as any);
			if (!response.ok) return response;

			if (isStreaming) {
				if (!response.body) {
					if (i < maxContentRetries - 1) await new Promise((res) => setTimeout(res, 1000));
					continue;
				}

				// 首 chunk 探針 (First-chunk Probing)
				const reader = response.body.getReader();
				let firstChunk: ReadableStreamReadResult<Uint8Array>;
				try {
					firstChunk = await reader.read();
				} catch (e) {
					reader.releaseLock();
					if (i < maxContentRetries - 1) await new Promise((res) => setTimeout(res, 1000));
					continue;
				}

				if (firstChunk.done) {
					reader.releaseLock();
					if (i < maxContentRetries - 1) {
						// 使用指數退避進行重試延遲
						const delay = 500 * Math.pow(2, i);
						await new Promise((res) => setTimeout(res, delay));
					}
					continue;
				}

				// 成功獲取有效的第一個 chunk，重構 ReadableStream 傳回
				const reconstructedStream = new ReadableStream<Uint8Array>({
					async start(controller) {
						if (firstChunk.value) {
							controller.enqueue(firstChunk.value);
						}
						try {
							while (true) {
								const { value, done } = await reader.read();
								if (done) {
									controller.close();
									break;
								}
								controller.enqueue(value);
							}
						} catch (err) {
							controller.error(err);
						} finally {
							reader.releaseLock();
						}
					}
				});

				// 包裝重構後的串流傳回
				return new Response(reconstructedStream, {
					status: response.status,
					headers: response.headers
				});
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
				const rawResponseText = await response.clone().text();
				responseBodyStr = sanitizeLogBody(rawResponseText);
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

	return response;
}
