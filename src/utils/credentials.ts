import { ApiCredentials, KeyState } from '../types';

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
		return idx;
	}
	return null;
}

export interface ParsedCredentials {
	apiKeys: string[];
	keyStates: KeyState[];
	oauthCredentialsList: string[];
	oauthKeyStates: KeyState[];
	currentKeyIndex: number;
	currentOauthIndex: number;
}

export function parseCredentials(dbResult: ApiCredentials): ParsedCredentials {
	const apiKeys = dbResult.api_keys
		.split(',')
		.map((k) => k.trim())
		.filter((k) => k);

	let keyStates: KeyState[] = [];
	try {
		keyStates = dbResult.key_states ? JSON.parse(dbResult.key_states) : [];
		if (keyStates.length !== apiKeys.length) {
			keyStates = apiKeys.map(() => ({}));
		}
	} catch {
		keyStates = apiKeys.map(() => ({}));
	}

	const oauthCredentialsList = dbResult.oauth_credentials
		? dbResult.oauth_credentials
				.split(',')
				.map((k) => k.trim())
				.filter((k) => k)
		: [];

	let oauthKeyStates: KeyState[] = [];
	try {
		oauthKeyStates = dbResult.oauth_key_states ? JSON.parse(dbResult.oauth_key_states) : [];
		if (oauthKeyStates.length !== oauthCredentialsList.length) {
			oauthKeyStates = oauthCredentialsList.map(() => ({}));
		}
	} catch {
		oauthKeyStates = oauthCredentialsList.map(() => ({}));
	}

	return {
		apiKeys,
		keyStates,
		oauthCredentialsList,
		oauthKeyStates,
		currentKeyIndex: dbResult.current_key_index || 0,
		currentOauthIndex: dbResult.current_oauth_index || 0,
	};
}
