/**
 * Deep Module: CompanionClient
 * Consolidates Google Cloud Code Companion API communications,
 * authorization header generation, project ID auto-discovery,
 * available model query, and multi-endpoint fallback loops.
 */

import { fetchWithEndpointFallback as rawFallback, discoverProjectId as rawDiscover, fetchAvailableModelsForToken as rawFetchModels, CLOUDCODE_ENDPOINTS } from './oauth';

export { CLOUDCODE_ENDPOINTS };

export class CompanionClient {
	/**
	 * Executes fetch with automatic endpoint fallback across primary and secondary CloudCode mirrors.
	 */
	static async fetchWithEndpointFallback(
		endpointSuffix: string,
		init: RequestInit,
		options?: { fetchFn?: (url: string, init: RequestInit) => Promise<Response> }
	): Promise<Response> {
		return rawFallback(endpointSuffix, init, options);
	}

	/**
	 * Generates authentic HTTP headers for Google Cloud Code Companion API.
	 */
	static getCompanionHeaders(accessToken: string, projectId?: string): Record<string, string> {
		const headers: Record<string, string> = {
			'Authorization': `Bearer ${accessToken}`,
			'Content-Type': 'application/json',
			'User-Agent': 'google-api-nodejs-client/9.15.1',
			'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1'
		};
		if (projectId) {
			headers['X-Goog-User-Project'] = projectId;
		}
		return headers;
	}

	/**
	 * Auto-discovers the user's Google Cloud Project ID from Companion API.
	 */
	static async discoverProjectId(accessToken: string, email?: string, isAntigravity?: boolean): Promise<string> {
		return rawDiscover(accessToken, email, isAntigravity);
	}

	/**
	 * Fetches available models for a given access token from Google Companion API.
	 */
	static async fetchAvailableModels(accessToken: string, projectId?: string): Promise<any[]> {
		return rawFetchModels(accessToken, projectId || '');
	}
}
