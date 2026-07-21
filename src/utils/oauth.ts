import type { OAuthCredentials, GoogleTokenResponse } from '../types';
import { SystemContext } from './context';
import { sendInvalidTokenEmail } from './email';

export async function refreshOAuthToken(
	credentials: OAuthCredentials,
	ctx?: SystemContext
): Promise<GoogleTokenResponse> {
	const tokenUrl = 'https://oauth2.googleapis.com/token';
	
	if (!credentials.client_id || !credentials.client_secret || !credentials.refresh_token) {
		throw new Error(`Missing OAuth credentials: client_id=${!!credentials.client_id}, client_secret=${!!credentials.client_secret}, refresh_token=${!!credentials.refresh_token}`);
	}

	const params = new URLSearchParams();
	params.append('client_id', credentials.client_id);
	params.append('client_secret', credentials.client_secret);
	params.append('refresh_token', credentials.refresh_token);
	params.append('grant_type', 'refresh_token');

	const response = await fetch(tokenUrl, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: params.toString(),
	});

	if (!response.ok) {
		const errorData = await response.text();
		const errorMessage = `OAuth token refresh failed: ${response.status} ${errorData}`;

		if (ctx) {
			const resendKey = ctx.resendApiKey;
			const toEmail = ctx.notificationEmail;
			const rawCredentialString = `${credentials.client_id}:${credentials.client_secret}:${credentials.refresh_token}${credentials.project_id ? ':' + credentials.project_id : ''}`;

			if (resendKey && toEmail) {
				let ownerEmail: string | undefined = undefined;
				try {
					const allRows = await ctx.env.DB.prepare(
						`SELECT c.oauth_credentials, a.email FROM api_credentials c JOIN admins a ON c.owner_admin_id = a.id`
					).all<{ oauth_credentials: string, email: string }>();
					const matchingRow = allRows.results?.find(row => row.oauth_credentials?.includes(credentials.refresh_token));
					ownerEmail = matchingRow?.email;
				} catch (e) {
					console.error('Error fetching owner email for OAuth invalid token notification:', e);
				}

				const recipients = new Set<string>();
				recipients.add(toEmail.trim().toLowerCase());
				if (ownerEmail) {
					recipients.add(ownerEmail.trim().toLowerCase());
				}

				ctx.waitUntil(
					sendInvalidTokenEmail(resendKey, Array.from(recipients), 'oauth', rawCredentialString, errorMessage)
				);
			}
		}

		throw new Error(errorMessage);
	}

	const tokenData: GoogleTokenResponse = await response.json();
	return tokenData;
}

export async function getOAuthAccessToken(
	state: DurableObjectState,
	credentials: OAuthCredentials,
	ctx?: SystemContext
): Promise<string> {
	const cacheKey = `oauth_${credentials.client_id}_${credentials.refresh_token.substring(0, 10)}`;
	let cached = await state.storage.get(cacheKey) as { token: string; expires: number } | null;

	const now = Date.now();
	if (cached && cached.expires > now + 60000) {
		return cached.token;
	}

	const tokenData = await refreshOAuthToken(credentials, ctx);
	const expiresAt = now + (tokenData.expires_in * 1000);

	// Handle Google OAuth 2.0 Refresh Token Rotation (RTR)
	const rotatedRefreshToken = tokenData.refresh_token;
	if (rotatedRefreshToken && rotatedRefreshToken !== credentials.refresh_token && ctx?.env?.DB) {
		try {
			const allRows = await ctx.env.DB.prepare('SELECT access_token, oauth_credentials FROM api_credentials').all();
			const matchingResults = allRows.results?.filter(row => (row.oauth_credentials as string)?.includes(credentials.refresh_token)) || [];
			
			if (matchingResults.length > 0) {
				for (const row of matchingResults) {
					const oauth_credentials = row.oauth_credentials as string;
					const access_token = row.access_token as string;
					const parts = oauth_credentials.split(',');
					const updatedParts = parts.map(part => {
						const credParts = part.split(':');
						if (credParts.length >= 3 && credParts[2] === credentials.refresh_token) {
							credParts[2] = rotatedRefreshToken;
							return credParts.join(':');
						}
						return part;
					});
					const updatedOauthCredentials = updatedParts.join(',');
					
					const updateStmt = ctx.env.DB.prepare('UPDATE api_credentials SET oauth_credentials = ? WHERE access_token = ?');
					await updateStmt.bind(updatedOauthCredentials, access_token).run();
				}
			}
			credentials.refresh_token = rotatedRefreshToken;
		} catch (dbErr) {
			console.error('Failed to update rotated OAuth refresh token in DB:', dbErr);
		}
	}

	// Run proactive background quota pre-check (0ms latency, runs asynchronously via waitUntil)
	if (ctx?.env?.DB && ctx.waitUntil) {
		const accessToken = tokenData.access_token;
		ctx.waitUntil((async () => {
			try {
				let activeProjectId = credentials.project_id;
				if (!activeProjectId) {
					activeProjectId = await discoverProjectId(accessToken);
				}
				if (!activeProjectId) return;

				const quotaUrl = 'https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota';
				const res = await fetch(quotaUrl, {
					method: 'POST',
					headers: {
						Authorization: `Bearer ${accessToken}`,
						'Content-Type': 'application/json',
						'User-Agent': 'google-api-nodejs-client/9.15.1',
						'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
						'Client-Metadata': 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI',
					},
					body: JSON.stringify({ project: activeProjectId }),
				});

				if (res.ok) {
					const data = await res.json() as any;
					if (data && data.quota) {
						const remaining = data.quota.remaining;
						const resetTimeStr = data.quota.resetTime;

						if (remaining === 0 && resetTimeStr) {
							const resetTime = Date.parse(resetTimeStr);
							if (!isNaN(resetTime) && resetTime > Date.now()) {
								const allRows = await ctx.env.DB.prepare('SELECT access_token, oauth_credentials, oauth_key_states FROM api_credentials').all();
								const matchingResults = allRows.results?.filter(row => (row.oauth_credentials as string)?.includes(credentials.refresh_token)) || [];

								if (matchingResults.length > 0) {
									for (const row of matchingResults) {
										const oauth_credentials = row.oauth_credentials as string;
										const access_token = row.access_token as string;
										const oauth_key_states = JSON.parse(row.oauth_key_states || '[]') as any[];

										const parts = oauth_credentials.split(',');
										const index = parts.findIndex(part => {
											const credParts = part.split(':');
											return credParts.length >= 3 && credParts[2] === credentials.refresh_token;
										});

										if (index !== -1) {
											while (oauth_key_states.length <= index) {
												oauth_key_states.push({});
											}

											const keyState = oauth_key_states[index] || {};
											const currentExhausted = keyState.exhaustedUntil || {};

											oauth_key_states[index] = {
												...keyState,
												exhaustedUntil: {
													...currentExhausted,
													'_general_': resetTime
												},
												lastStatus: 429,
												lastError: `Proactive quota check: Remaining quota is 0. Exhausted until reset time (${resetTimeStr}).`,
												lastTestedAt: Date.now()
											};

											const updateStmt = ctx.env.DB.prepare('UPDATE api_credentials SET oauth_key_states = ? WHERE access_token = ?');
											await updateStmt.bind(JSON.stringify(oauth_key_states), access_token).run();
										}
									}
								}
							}
						} else if (remaining > 0) {
							// Proactively revive key if we see remaining quota!
							const allRows = await ctx.env.DB.prepare('SELECT access_token, oauth_credentials, oauth_key_states FROM api_credentials').all();
							const matchingResults = allRows.results?.filter(row => (row.oauth_credentials as string)?.includes(credentials.refresh_token)) || [];

							if (matchingResults.length > 0) {
								for (const row of matchingResults) {
									const oauth_credentials = row.oauth_credentials as string;
									const access_token = row.access_token as string;
									const oauth_key_states = JSON.parse(row.oauth_key_states || '[]') as any[];

									const parts = oauth_credentials.split(',');
									const index = parts.findIndex(part => {
										const credParts = part.split(':');
										return credParts.length >= 3 && credParts[2] === credentials.refresh_token;
									});

									if (index !== -1 && oauth_key_states[index]) {
										const keyState = { ...oauth_key_states[index] };
										let changed = false;
										if (keyState.exhaustedUntil) {
											delete keyState.exhaustedUntil;
											changed = true;
										}
										if (keyState.invalid) {
											delete keyState.invalid;
											changed = true;
										}
										if (changed) {
											keyState.lastStatus = 200;
											keyState.lastError = `Proactive quota check: Key is healthy (remaining quota: ${remaining}).`;
											keyState.lastTestedAt = Date.now();
											oauth_key_states[index] = keyState;

											const updateStmt = ctx.env.DB.prepare('UPDATE api_credentials SET oauth_key_states = ? WHERE access_token = ?');
											await updateStmt.bind(JSON.stringify(oauth_key_states), access_token).run();
										}
									}
								}
							}
						}
					}
				}
			} catch (err) {
				console.error('[KeyRotator] Proactive background quota pre-check failed:', err);
			}
		})());
	}

	await state.storage.put(cacheKey, {
		token: tokenData.access_token,
		expires: expiresAt
	});

	return tokenData.access_token;
}

export function extractProjectId(data: any): string | undefined {
	if (!data || typeof data !== "object") return undefined;
	const direct = data.antigravityProjectId ?? data.projectId ?? data.backendProjectId ?? data.userDefinedCloudaicompanionProject ?? data.cloudaicompanionProject ?? data.project;
	if (typeof direct === "string" && direct) return direct.trim();
	if (direct && typeof direct === "object" && typeof direct.id === "string" && direct.id) return direct.id.trim();
	for (const key of ["projects", "projectIds", "cloudaicompanionProjects"]) {
		const value = data[key];
		if (Array.isArray(value)) {
			for (const item of value) {
				const nested = extractProjectId(item);
				if (nested) return nested;
				if (typeof item === "string" && item) return item.trim();
			}
		}
	}
	return undefined;
}

export function sanitizeText(text: unknown): string {
	return String(text ?? "").replace(/[\uD800-\uDFFF]/g, "\uFFFD");
}

export async function discoverProjectId(accessToken: string, email?: string): Promise<string> {
	const headers = {
		'Authorization': `Bearer ${accessToken}`,
		'Content-Type': 'application/json',
		'User-Agent': 'google-api-nodejs-client/9.15.1',
		'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
		'Client-Metadata': 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI',
	};

	// 1. Try `/v1internal:loadCodeAssist` via Cloud Code Companion API
	try {
		const loadCodeAssistUrl = 'https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist';
		const res = await fetch(loadCodeAssistUrl, {
			method: 'POST',
			headers,
			body: JSON.stringify({ metadata: { ideType: 'IDE_UNSPECIFIED' } }),
		});
		if (res.ok) {
			const data = await res.json() as any;
			const pId = extractProjectId(data);
			if (pId) return pId;
		}
	} catch (err) {
		// Suppress and fall through
	}

	// 2. Try `/v1internal:listCloudAICompanionProjects` via Cloud Code Companion API
	try {
		const listProjectsUrl = 'https://cloudcode-pa.googleapis.com/v1internal:listCloudAICompanionProjects';
		const res = await fetch(listProjectsUrl, {
			method: 'POST',
			headers,
			body: JSON.stringify({}),
		});
		if (res.ok) {
			const data = await res.json() as any;
			const pId = extractProjectId(data);
			if (pId) return pId;
		}
	} catch (err) {
		// Suppress and fall through
	}

	// 3. Fallback to global Cloud Resource Manager API
	try {
		const projectUrl = 'https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE';
		const response = await fetch(projectUrl, {
			headers: {
				'Authorization': `Bearer ${accessToken}`,
			},
		});

		if (response.ok) {
			const data = await response.json() as any;
			const projects = data.projects || [];
			// Prefer standard projects first (non-gen-lang-client)
			const standardProjects = projects.filter((p: any) => p.projectId && !p.projectId.startsWith('gen-lang-client-'));
			if (standardProjects.length > 0) {
				const pId = standardProjects[0].projectId;
				await enableCompanionApi(accessToken, pId);
				return pId;
			}
			// Fallback to auto-generated AI Studio projects (gen-lang-client-*)
			const aiStudioProjects = projects.filter((p: any) => p.projectId && p.projectId.startsWith('gen-lang-client-'));
			if (aiStudioProjects.length > 0) {
				const pId = aiStudioProjects[0].projectId;
				await enableCompanionApi(accessToken, pId);
				return pId;
			}
		}
	} catch (err) {
		// Suppress and fall through
	}

	// 4. Ultimate Fallback: Generate a stable, deterministic UUID-like Project ID based on the user's email address
	// This matches the official Antigravity extension's behavior of generating a stable UUID project ID for consumer accounts!
	try {
		const seed = email || 'default-antigravity-seed';
		const msgBuffer = new TextEncoder().encode(`antigravity:${seed}`);
		const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
		// Format as UUID structure: 8-4-4-4-12
		const stableUuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
		return stableUuid;
	} catch (err) {
		// Fallback to a hardcoded stable UUID if Web Crypto fails
		return 'c08e5c8e-b2ee-590d-9b51-78923bc4de61';
	}
}

export function parseOAuthCredentials(apiKey: string, defaultClientId?: string, defaultClientSecret?: string): OAuthCredentials {
	const parts = apiKey.split(':');

	// Map indices based on expected format client_id:client_secret:refresh_token[:project_id][:email][:tier]
	let clientId = parts[0]?.trim();
	let clientSecret = parts[1]?.trim();
	let refreshToken = parts[2]?.trim();
	let projectId = parts[3]?.trim() || undefined;
	let email = parts[4]?.trim() || undefined;
	let tier = parts[5]?.trim() || undefined;

	// Fallback for defaults if fields are empty (e.g. "::refresh_token:project_id")
	if (!clientId) clientId = defaultClientId || "";
	if (!clientSecret) clientSecret = defaultClientSecret || "";

	if (!refreshToken) {
		throw new Error('Invalid OAuth credentials format. refresh_token is missing.');
	}

	return {
		client_id: clientId,
		client_secret: clientSecret,
		refresh_token: refreshToken,
		project_id: projectId,
		email,
		tier
	};
}

export async function saveDiscoveredProjectId(
	credentials: OAuthCredentials,
	discoveredProjectId: string,
	ctx: any
) {
	if (!ctx?.env?.DB) return;
	try {
		const allRows = await ctx.env.DB.prepare('SELECT access_token, oauth_credentials FROM api_credentials').all();
		const matchingResults = allRows.results?.filter(row => (row.oauth_credentials as string)?.includes(credentials.refresh_token)) || [];
		if (matchingResults.length > 0) {
			for (const row of matchingResults) {
				const oauth_credentials = row.oauth_credentials as string;
				const access_token = row.access_token as string;
				const parts = oauth_credentials.split(',');
				const updatedParts = parts.map(part => {
					const credParts = part.split(':');
					// Format is client_id:client_secret:refresh_token:project_id:email
					if (credParts.length >= 4 && credParts[2] === credentials.refresh_token) {
						credParts[3] = discoveredProjectId;
						return credParts.join(':');
					}
					return part;
				});
				const updatedOauthCredentials = updatedParts.join(',');
				await ctx.env.DB.prepare('UPDATE api_credentials SET oauth_credentials = ? WHERE access_token = ?')
					.bind(updatedOauthCredentials, access_token)
					.run();
			}
		}
		credentials.project_id = discoveredProjectId;
	} catch (e) {
		console.error('Failed to save discovered project ID to DB:', e);
	}
}

export async function enableCompanionApi(accessToken: string, projectId: string): Promise<boolean> {
	try {
		const url = `https://serviceusage.googleapis.com/v1/projects/${projectId}/services/cloudaicompanion.googleapis.com:enable`;
		const res = await fetch(url, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${accessToken}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({}),
		});
		return res.ok;
	} catch (e) {
		return false;
	}
}

export function collectModelLabels(value: any, out: string[] = []): string[] {
	if (!value || out.length > 100) return out;
	if (typeof value === 'string') {
		const trimmed = value.trim();
		if (trimmed && /gemini|claude|gpt-oss/i.test(trimmed)) {
			out.push(trimmed);
		}
		return out;
	}
	if (Array.isArray(value)) {
		for (const item of value) collectModelLabels(item, out);
		return out;
	}
	if (typeof value === 'object') {
		for (const [k, v] of Object.entries(value)) {
			if (typeof k === 'string' && /model|id|name|label/i.test(k) && typeof v === 'string') {
				// ADDED: debug logging to see what it's finding
				// console.log(`Found candidate: ${v}`); 
				if (/gemini|claude|gpt-oss/i.test(v)) out.push(v.trim());
			}
			collectModelLabels(v, out);
		}
	}
	return out;
}

export interface OAuthBucket {
	modelId: string;
	remainingAmount?: number;
	[key: string]: any;
}

export async function fetchAvailableModelsForToken(accessToken: string, projectId: string): Promise<OAuthBucket[]> {
	const url = `https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota`;
	try {
		const res = await fetch(url, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${accessToken}`,
				'Content-Type': 'application/json',
				'User-Agent': 'google-api-nodejs-client/9.15.1',
				'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
				'Client-Metadata': 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI',
			},
			body: JSON.stringify({ project: projectId }),
		});
		if (res.ok) {
			const data = await res.json() as any;
			return data.buckets || [];
		}
	} catch (e) {
		// ignore
	}
	return [];
}
