import type { Env } from '../index';
import { sanitizeLogBody } from './sanitize';

function sanitizeHeadersAndUrl(headers: Headers, url: string) {
  const sensitiveHeaders = ['authorization', 'cookie', 'x-access-token', 'x-api-key', 'x-goog-api-key', 'x-rotator-token'];
  const sanitizedHeaders: { [key: string]: string } = {};

  for (const [key, value] of headers as any) {
    const lowerKey = key.toLowerCase();
    if (sensitiveHeaders.includes(lowerKey)) {
      sanitizedHeaders[lowerKey] = '[REDACTED]';
    } else {
      sanitizedHeaders[lowerKey] = value;
    }
  }

  let sanitizedUrl = url;
  try {
    const urlObj = new URL(url);
    let changed = false;
    const paramsToRedact = ['key', 'api_key', 'token', 'access_token'];
    for (const param of paramsToRedact) {
      if (urlObj.searchParams.has(param)) {
        urlObj.searchParams.set(param, '[REDACTED]');
        changed = true;
      }
    }
    if (changed) {
      sanitizedUrl = urlObj.toString();
    }
  } catch (e) {}

  return { sanitizedHeaders, sanitizedUrl };
}

export async function logRequest(env: Env, request: Request, accessToken?: string) {
  const startTime = Date.now();
  const { sanitizedHeaders, sanitizedUrl } = sanitizeHeadersAndUrl(request.headers, request.url);

  const rawBody = await request.clone().text();
  const sanitizedBody = sanitizeLogBody(rawBody);

  const logData = {
    timestamp: new Date().toISOString(),
    access_token: accessToken || null,
    request_method: request.method,
    request_url: sanitizedUrl,
    request_headers: JSON.stringify(sanitizedHeaders),
    request_body: sanitizedBody,
  };

  // Insert into D1
  const stmt = env.DB.prepare(`
    INSERT INTO api_logs (timestamp, access_token, request_method, request_url, request_headers, request_body, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `);
  const result = await stmt.bind(
    logData.timestamp,
    logData.access_token,
    logData.request_method,
    logData.request_url,
    logData.request_headers,
    logData.request_body
  ).run();

  return { startTime, logId: result.meta.last_row_id };
}

export async function logResponse(env: Env, startTime: number, response: Response, logId: number) {
  const duration = Date.now() - startTime;
  let responseBody: string;
  try {
    const rawResponseBody = await response.clone().text();
    responseBody = sanitizeLogBody(rawResponseBody);
  } catch (e) {
    responseBody = '<unable to read response>';
  }

  const { sanitizedHeaders } = sanitizeHeadersAndUrl(response.headers, 'https://dummy.org');

  const logData = {
    response_status: response.status,
    response_headers: JSON.stringify(sanitizedHeaders),
    response_body: responseBody,
    duration_ms: duration,
  };

  // Update the log in D1
  const stmt = env.DB.prepare(`
    UPDATE api_logs SET response_status = ?, response_headers = ?, response_body = ?, duration_ms = ?
    WHERE id = ?
  `);
  await stmt.bind(
    logData.response_status,
    logData.response_headers,
    logData.response_body,
    logData.duration_ms,
    logId
  ).run();
}

export async function writeCombinedLog(env: Env, request: Request, response: Response, startTime: number, accessToken?: string) {
  try {
    const timestamp = new Date(startTime).toISOString();
    const duration = Date.now() - startTime;

    // 1. Request details
    const { sanitizedHeaders, sanitizedUrl } = sanitizeHeadersAndUrl(request.headers, request.url);
    let sanitizedReqBody = '';
    try {
      const rawReqBody = await request.clone().text();
      sanitizedReqBody = sanitizeLogBody(rawReqBody);
    } catch (e) {}

    // 2. Response details
    let responseBody: string;
    try {
      const rawResponseBody = await response.clone().text();
      responseBody = sanitizeLogBody(rawResponseBody);
    } catch (e) {
      responseBody = '<unable to read response>';
    }
    const { sanitizedHeaders: sanitizedResHeaders } = sanitizeHeadersAndUrl(response.headers, 'https://dummy.org');

    // 3. Single Insert into D1
    const stmt = env.DB.prepare(`
      INSERT INTO api_logs (
        timestamp, access_token, request_method, request_url, request_headers, request_body,
        response_status, response_headers, response_body, duration_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      timestamp,
      accessToken || null,
      request.method,
      sanitizedUrl,
      JSON.stringify(sanitizedHeaders),
      sanitizedReqBody,
      response.status,
      JSON.stringify(sanitizedResHeaders),
      responseBody,
      duration
    ).run();

  } catch (e) {
    console.error("Failed to write combined API log:", e);
  }
}
