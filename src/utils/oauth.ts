import type { OAuthCredentials, GoogleTokenResponse } from '../types';

export async function refreshOAuthToken(credentials: OAuthCredentials): Promise<GoogleTokenResponse> {
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
		throw new Error(`OAuth token refresh failed: ${response.status} ${errorData}`);
	}

	const tokenData: GoogleTokenResponse = await response.json();
	return tokenData;
}

export async function getOAuthAccessToken(state: DurableObjectState, credentials: OAuthCredentials): Promise<string> {
	const cacheKey = `oauth_${credentials.client_id}_${credentials.refresh_token.substring(0, 10)}`;
	let cached = await state.storage.get(cacheKey) as { token: string; expires: number } | null;

	const now = Date.now();
	if (cached && cached.expires > now + 60000) {
		return cached.token;
	}

	const tokenData = await refreshOAuthToken(credentials);
	const expiresAt = now + (tokenData.expires_in * 1000);

	await state.storage.put(cacheKey, {
		token: tokenData.access_token,
		expires: expiresAt
	});

	return tokenData.access_token;
}

export async function discoverProjectId(accessToken: string): Promise<string> {
	const projectUrl = 'https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE';
	const response = await fetch(projectUrl, {
		headers: {
			'Authorization': `Bearer ${accessToken}`,
		},
	});

	if (!response.ok) {
		throw new Error(`Failed to discover project: ${response.status}`);
	}

	const data = await response.json() as any;
	const projects = data.projects || [];

	if (projects.length === 0) {
		throw new Error('No active Google Cloud projects found');
	}

	return projects[0].projectId;
}

export function parseOAuthCredentials(apiKey: string, defaultClientId?: string, defaultClientSecret?: string): OAuthCredentials {
	const parts = apiKey.split(':');
	
	// Map indices based on expected format client_id:client_secret:refresh_token[:project_id]
	let clientId = parts[0]?.trim();
	let clientSecret = parts[1]?.trim();
	let refreshToken = parts[2]?.trim();
	let projectId = parts[3]?.trim() || undefined;

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
	};
}
