import type { Env } from '../index';
import { sanitizeLogBody } from './sanitize';

export async function logRequest(env: Env, request: Request, accessToken?: string) {
  const startTime = Date.now();
  const headersObj: { [key: string]: string } = {};
  for (const [key, value] of request.headers as any) {
    headersObj[key] = value;
  }

  const rawBody = await request.clone().text();
  const sanitizedBody = sanitizeLogBody(rawBody);

  const logData = {
    timestamp: new Date().toISOString(),
    access_token: accessToken || null,
    request_method: request.method,
    request_url: request.url,
    request_headers: JSON.stringify(headersObj),
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

  const headersObj: { [key: string]: string } = {};
  for (const [key, value] of response.headers as any) {
    headersObj[key] = value;
  }

  const logData = {
    response_status: response.status,
    response_headers: JSON.stringify(headersObj),
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
