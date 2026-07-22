import { ApiCredentials, KeyState } from '../types';

export function parseCsvList(str: string | undefined | null): string[] {
	if (!str) return [];
	return str.split(',').map((k) => k.trim()).filter(Boolean);
}

export function getStandardRotationIndex(

	apiKeys: string[],
	startingIndex: number,
	states: KeyState[],
	model: string,
	now: number
): number | null {
	for (let i = 0; i < apiKeys.length; i++) {
		const idx = (startingIndex + i) % apiKeys.length;
		const state = states[idx];
		if (state?.invalid) continue;
		if (state?.exhaustedUntil) {
			Object.keys(state.exhaustedUntil).forEach((mod) => {
				if (state.exhaustedUntil![mod] < now) delete state.exhaustedUntil![mod];
			});
			if (Object.keys(state.exhaustedUntil).length === 0) delete state.exhaustedUntil;
		}
		if (model && state?.exhaustedUntil?.[model]) continue;
		if (!model && state?.exhaustedUntil) continue;
		if (model && state?.modelUnavailable?.[model]) continue; // permanently unavailable model for this key
		if (model && Array.isArray(state?.availableModels)) {
			if (!state.availableModels.includes(model)) continue;
		}
		return idx;
	}
	return null;
}

export interface ParsedCredentials {
	apiKeys: string[];
	keyStates: KeyState[];
	oauthCredentialsList: string[];
	oauthKeyStates: KeyState[];
	antigravityCredentialsList: string[];
	antigravityKeyStates: KeyState[];
	currentKeyIndex: number;
	currentOauthIndex: number;
	currentAntigravityIndex: number;
}

export function parseCredentials(dbResult: ApiCredentials): ParsedCredentials {
	const apiKeys = parseCsvList(dbResult.api_keys);

	let keyStates: KeyState[] = [];
	try {
		keyStates = dbResult.key_states ? JSON.parse(dbResult.key_states) : [];
		if (keyStates.length !== apiKeys.length) {
			keyStates = apiKeys.map(() => ({}));
		}
	} catch {
		keyStates = apiKeys.map(() => ({}));
	}

	const oauthCredentialsList = parseCsvList(dbResult.oauth_credentials);

	let oauthKeyStates: KeyState[] = [];
	try {
		oauthKeyStates = dbResult.oauth_key_states ? JSON.parse(dbResult.oauth_key_states) : [];
		if (oauthKeyStates.length !== oauthCredentialsList.length) {
			oauthKeyStates = oauthCredentialsList.map(() => ({}));
		}
	} catch {
		oauthKeyStates = oauthCredentialsList.map(() => ({}));
	}

	const antigravityCredentialsList = parseCsvList(dbResult.antigravity_credentials);

	let antigravityKeyStates: KeyState[] = [];
	try {
		antigravityKeyStates = dbResult.antigravity_key_states ? JSON.parse(dbResult.antigravity_key_states) : [];
		if (antigravityKeyStates.length !== antigravityCredentialsList.length) {
			antigravityKeyStates = antigravityCredentialsList.map(() => ({}));
		}
	} catch {
		antigravityKeyStates = antigravityCredentialsList.map(() => ({}));
	}

	return {
		apiKeys,
		keyStates,
		oauthCredentialsList,
		oauthKeyStates,
		antigravityCredentialsList,
		antigravityKeyStates,
		currentKeyIndex: dbResult.current_key_index || 0,
		currentOauthIndex: dbResult.current_oauth_index || 0,
		currentAntigravityIndex: dbResult.current_antigravity_index || 0,
	};
}
