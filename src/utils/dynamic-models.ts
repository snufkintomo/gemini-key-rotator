export function findDynamicModel(value: any, requestedId: string): string | undefined {
	if (!value) return undefined;

	let targetRegex: RegExp;
	const req = requestedId.toLowerCase();
	if (req === 'gemini-3.5-flash-low') {
		targetRegex = /gemini[- ]3\.5[- ]flash \(low\)/i;
	} else if (req === 'gemini-3.5-flash-medium') {
		targetRegex = /gemini[- ]3\.5[- ]flash \(medium\)/i;
	} else if (req === 'gemini-3.5-flash-high' || req === 'gemini-3-flash-agent') {
		targetRegex = /gemini[- ]3[- ]flash[- ]agent|gemini[- ]3[- ]flash \(agent\)/i;
	} else if (req.includes('claude-opus-4-6')) {
		targetRegex = /claude.*opus.*4\.6/i;
	} else if (req.includes('claude-sonnet-4-6')) {
		targetRegex = /claude.*sonnet.*4\.6/i;
	} else if (req.includes('gpt-oss-120b')) {
		targetRegex = /gpt.*oss.*120b/i;
	} else if (req === 'gemini-3.1-pro-low') {
		targetRegex = /gemini[- ]3\.1[- ]pro \(low\)/i;
	} else if (req === 'gemini-3.1-pro-high') {
		targetRegex = /gemini[- ]3\.1[- ]pro \(high\)/i;
	} else if (req.includes('gemini-2.5-pro')) {
		targetRegex = /gemini[- ]2\.5[- ]pro/i;
	} else if (req.includes('gemini-2.5-flash')) {
		targetRegex = /gemini[- ]2\.5[- ]flash/i;
	} else {
		targetRegex = new RegExp(req.replace(/-/g, '.*'), 'i');
	}

	if (typeof value === 'string') {
		return targetRegex.test(value) ? value : undefined;
	}

	if (Array.isArray(value)) {
		for (const item of value) {
			const found = findDynamicModel(item, requestedId);
			if (found) return found;
		}
		return undefined;
	}

	if (typeof value === 'object') {
		const label = value.label ?? value.displayName ?? value.name ?? value.modelId ?? value.id ?? value.model;
		if (typeof label === 'string' && targetRegex.test(label)) {
			return String(value.modelId ?? value.id ?? value.model ?? label);
		}
		for (const nested of Object.values(value)) {
			if (nested && typeof nested === 'object') {
				const found = findDynamicModel(nested, requestedId);
				if (found) return found;
			}
		}
	}

	return undefined;
}

export async function fetchAvailableRuntimeModel(
	token: string,
	projectId: string,
	requestedRuntimeModel: string,
	endpoint = 'https://cloudcode-pa.googleapis.com'
): Promise<string | undefined> {
	// Candidate endpoints
	const endpoints = [
		endpoint,
		'https://daily-cloudcode-pa.sandbox.googleapis.com'
	];
	const uniqueEndpoints = Array.from(new Set(endpoints));

	const bodies = [{}, { cloudaicompanionProject: projectId }, { project: projectId }];
	const headers = {
		Authorization: `Bearer ${token}`,
		'Content-Type': 'application/json',
		'User-Agent': 'google-api-nodejs-client/9.15.1',
		'X-Goog-Api-Client': 'google-api-nodejs-client/9.15.1',
		'Client-Metadata': 'ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI',
	};

	for (const ep of uniqueEndpoints) {
		for (const candidateBody of bodies) {
			try {
				const res = await fetch(`${ep}/v1internal:fetchAvailableModels`, {
					method: 'POST',
					headers,
					body: JSON.stringify(candidateBody),
				});
				if (!res.ok) continue;
				const data = await res.json();
				const matched = findDynamicModel(data, requestedRuntimeModel);
				if (matched) return matched;
			} catch (error) {
				// Fail-silent for individual body/endpoint attempts
			}
		}
	}
	return undefined;
}
