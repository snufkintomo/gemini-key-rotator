import type { OAuthCredentials, GoogleTokenResponse } from '../types';
import { SystemContext } from './context';
import { sendInvalidTokenEmail } from './email';
import { getAntigravityHeaders } from './antigravity';

export const CLOUDCODE_ENDPOINTS = [
	'https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal', // 1. Sandbox (優先)
	'https://daily-cloudcode-pa.googleapis.com/v1internal',         // 2. Daily (備用)
	'https://cloudcode-pa.googleapis.com/v1internal',               // 3. Prod (兜底)
];

/**
 * Shared DRY helper function to execute Cloud Code Companion API calls across 3 endpoints:
 * 1. Sandbox -> 2. Daily -> 3. Prod
 */
export async function fetchWithEndpointFallback(
	pathAndQuery: string,
	init: RequestInit,
	options?: {
		fetchFn?: (url: string, init: RequestInit) => Promise<Response>;
		retryWithoutUserProjectOn403?: boolean;
	}
): Promise<Response> {
	const customFetch = options?.fetchFn || ((u, i) => fetch(u, i));
	let lastRes: Response | null = null;

	for (let i = 0; i < CLOUDCODE_ENDPOINTS.length; i++) {
		const url = `${CLOUDCODE_ENDPOINTS[i]}${pathAndQuery}`;
		try {
			const res = await customFetch(url, init);

			// Return immediately if HTTP 2xx Success
			if (res.ok) {
				return res;
			}

			// Handle 403: retry without x-goog-user-project if requested and present
			if (res.status === 403 && options?.retryWithoutUserProjectOn403) {
				const headersObj = new Headers(init.headers);
				if (headersObj.has('x-goog-user-project')) {
					headersObj.delete('x-goog-user-project');
					const retryRes = await customFetch(url, { ...init, headers: headersObj });
					if (retryRes.ok) {
						return retryRes;
					}
					lastRes = retryRes;
				} else {
					lastRes = res;
				}
			} else {
				lastRes = res;
			}

			console.warn(`CloudCode Fallback: ${CLOUDCODE_ENDPOINTS[i]} returned ${res.status}, retrying next endpoint...`);
		} catch (err) {
			console.warn(`CloudCode Fallback Error on ${CLOUDCODE_ENDPOINTS[i]}:`, err);
		}
	}

	return lastRes || new Response('CloudCode All Endpoints Exhausted', { status: 503 });
}

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

				const res = await fetchWithEndpointFallback(':retrieveUserQuota', {
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

export function extractTierId(loadData: any): string {
	if (!loadData || typeof loadData !== 'object') return 'free-tier';
	
	if (Array.isArray(loadData.allowedTiers) && loadData.allowedTiers.length > 0) {
		const defaultTier = loadData.allowedTiers.find((t: any) => t.isDefault) || loadData.allowedTiers[0];
		if (defaultTier?.id) return defaultTier.id;
	}

	if (loadData.currentTier?.id) return loadData.currentTier.id;
	if (loadData.paidTier?.id) return loadData.paidTier.id;

	return 'free-tier';
}

export function extractProjectId(data: any): string | undefined {
	if (!data || typeof data !== "object") return undefined;
	
	const direct = data.antigravityProjectId ?? data.projectId ?? data.backendProjectId ?? data.userDefinedCloudaicompanionProject ?? data.cloudaicompanionProject ?? data.project;
	
	if (typeof direct === "string" && direct) {
		const cleaned = direct.trim().replace(/^projects\//, '');
		if (cleaned) return cleaned;
	}
	if (direct && typeof direct === "object") {
		const val = direct.id ?? direct.projectId ?? direct.name;
		if (typeof val === "string" && val) {
			const cleaned = val.trim().replace(/^projects\//, '');
			if (cleaned) return cleaned;
		}
	}

	// Handle LRO onboardUser response object
	if (data.response && typeof data.response === "object") {
		const nestedFromResponse = extractProjectId(data.response);
		if (nestedFromResponse) return nestedFromResponse;
	}

	for (const key of ["projects", "projectIds", "cloudaicompanionProjects"]) {
		const value = data[key];
		if (Array.isArray(value)) {
			for (const item of value) {
				const nested = extractProjectId(item);
				if (nested) return nested;
				if (typeof item === "string" && item) {
					const cleaned = item.trim().replace(/^projects\//, '');
					if (cleaned) return cleaned;
				}
			}
		}
	}
	return undefined;
}

export function sanitizeText(text: unknown): string {
	return String(text ?? "").replace(/[\uD800-\uDFFF]/g, "\uFFFD");
}

export async function discoverProjectId(accessToken: string, email?: string, isAntigravity?: boolean): Promise<string> {
	const headers: Record<string, string> = isAntigravity
		? getAntigravityHeaders(accessToken)
		: {
			'Authorization': `Bearer ${accessToken}`,
			'Content-Type': 'application/json',
			'User-Agent': 'google-api-nodejs-client/9.15.1',
			'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
			'Client-Metadata': 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI',
		  };

	const metadataObj = isAntigravity ? { ideType: 'ANTIGRAVITY' } : { ideType: 'IDE_UNSPECIFIED' };

	let loadData: any = null;

	// 1. Try `/v1internal:loadCodeAssist` via Cloud Code Companion API
	try {
		const res = await fetchWithEndpointFallback(':loadCodeAssist', {
			method: 'POST',
			headers,
			body: JSON.stringify({ metadata: metadataObj }),
		});
		if (res.ok) {
			loadData = await res.json() as any;
			const pId = extractProjectId(loadData);
			if (pId) return pId;
		}
	} catch (err) {
		// Suppress and fall through
	}

	// 2. Try `/v1internal:listCloudAICompanionProjects` via Cloud Code Companion API
	try {
		const res = await fetchWithEndpointFallback(':listCloudAICompanionProjects', {
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

	// 3. Check if account tier requires user-defined GCP project
	const onboardTierId = extractTierId(loadData);
	const requiresUserProject = loadData?.allowedTiers?.some((t: any) => t.userDefinedCloudaicompanionProject) || onboardTierId === 'standard-tier';

	let gcpProjectId: string | undefined = undefined;

	// Query Cloud Resource Manager API to discover user's active GCP projects if needed
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
			const standardProjects = projects.filter((p: any) => p.projectId && !p.projectId.startsWith('gen-lang-client-'));
			if (standardProjects.length > 0) {
				gcpProjectId = standardProjects[0].projectId;
			} else {
				const aiStudioProjects = projects.filter((p: any) => p.projectId && p.projectId.startsWith('gen-lang-client-'));
				if (aiStudioProjects.length > 0) {
					gcpProjectId = aiStudioProjects[0].projectId;
				}
			}
		}
	} catch (err) {
		// Suppress and fall through
	}

	if (gcpProjectId) {
		await enableCompanionApi(accessToken, gcpProjectId);
	}

	// 4. Try `/v1internal:onboardUser` (Official Gemini CLI / Antigravity onboarding endpoint)
	try {
		const onboardBody: any = {
			tierId: onboardTierId,
			metadata: metadataObj,
		};

		if (requiresUserProject || gcpProjectId) {
			if (gcpProjectId) {
				onboardBody.cloudaicompanionProject = gcpProjectId;
				onboardBody.metadata = {
					...metadataObj,
					duetProject: gcpProjectId,
				};
			}
		}

		const res = await fetchWithEndpointFallback(':onboardUser', {
			method: 'POST',
			headers,
			body: JSON.stringify(onboardBody),
		});

		if (res.ok) {
			const data = await res.json() as any;
			const pId = extractProjectId(data);
			if (pId) return pId;

			// Handle Async Long-Running Operation (LRO) polling if onboarding is pending
			if (!data.done && data.name) {
				const opName = data.name;
				for (let poll = 0; poll < 5; poll++) {
					await new Promise(r => setTimeout(r, 1000));
					try {
						const opRes = await fetchWithEndpointFallback(':getOperation', {
							method: 'POST',
							headers,
							body: JSON.stringify({ name: opName }),
						});
						if (opRes.ok) {
							const opData = await opRes.json() as any;
							const pollPId = extractProjectId(opData);
							if (pollPId) return pollPId;
							if (opData.done) break;
						}
					} catch (e) {
						break;
					}
				}
			}
		}
	} catch (err) {
		// Suppress and fall through
	}

	if (gcpProjectId) return gcpProjectId;

	// 5. Ultimate Fallback: Return 'default'
	return 'default';
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
		const allRows = await ctx.env.DB.prepare('SELECT access_token, oauth_credentials, antigravity_credentials FROM api_credentials').all();
		
		for (const row of (allRows.results || [])) {
			const access_token = row.access_token as string;
			const oauth_credentials = row.oauth_credentials as string || '';
			const antigravity_credentials = row.antigravity_credentials as string || '';

			let oauthUpdated = false;
			let agyUpdated = false;

			let updatedOauth = oauth_credentials;
			let updatedAgy = antigravity_credentials;

			if (oauth_credentials.includes(credentials.refresh_token)) {
				const parts = oauth_credentials.split(',');
				const updatedParts = parts.map(part => {
					const credParts = part.split(':');
					if (credParts.length >= 4 && credParts[2] === credentials.refresh_token) {
						credParts[3] = discoveredProjectId;
						oauthUpdated = true;
						return credParts.join(':');
					}
					return part;
				});
				updatedOauth = updatedParts.join(',');
			}

			if (antigravity_credentials.includes(credentials.refresh_token)) {
				const parts = antigravity_credentials.split(',');
				const updatedParts = parts.map(part => {
					const credParts = part.split(':');
					if (credParts.length >= 4 && credParts[2] === credentials.refresh_token) {
						credParts[3] = discoveredProjectId;
						agyUpdated = true;
						return credParts.join(':');
					}
					return part;
				});
				updatedAgy = updatedParts.join(',');
			}

			if (oauthUpdated) {
				await ctx.env.DB.prepare('UPDATE api_credentials SET oauth_credentials = ? WHERE access_token = ?')
					.bind(updatedOauth, access_token)
					.run();
			}
			if (agyUpdated) {
				await ctx.env.DB.prepare('UPDATE api_credentials SET antigravity_credentials = ? WHERE access_token = ?')
					.bind(updatedAgy, access_token)
					.run();
			}
		}
		credentials.project_id = discoveredProjectId;
	} catch (e) {
		console.error('Failed to save discovered project ID to DB:', e);
	}
}

export async function enableCompanionApi(accessToken: string, projectId: string): Promise<boolean> {
	if (!projectId || projectId === 'default' || projectId === 'test-project') return false;
	try {
		// 1. Official Code Assist Onboarding with cloudaicompanionProject & duetProject
		try {
			await fetchWithEndpointFallback(':onboardUser', {
				method: 'POST',
				headers: getAntigravityHeaders(accessToken, projectId),
				body: JSON.stringify({
					tierId: 'standard-tier',
					cloudaicompanionProject: projectId,
					metadata: {
						ideType: 'ANTIGRAVITY',
						duetProject: projectId,
					},
				}),
			});
		} catch (e) {
			// Suppress and fall through
		}

		// 2. Direct Service Usage API Enablement
		const url = `https://serviceusage.googleapis.com/v1/projects/${projectId}/services/cloudaicompanion.googleapis.com:enable`;
		const res = await fetch(url, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${accessToken}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({}),
		});

		// Wait 1.5s for Google system propagation
		await new Promise(r => setTimeout(r, 1500));

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
	try {
		const res = await fetchWithEndpointFallback(':retrieveUserQuota', {
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
