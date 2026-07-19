export function stripMetaSchema(schema: any): any {
	if (!schema || typeof schema !== 'object') return schema;
	if (Array.isArray(schema)) return schema.map(stripMetaSchema);

	const omit = new Set([
		'$schema',
		'$id',
		'$anchor',
		'$dynamicAnchor',
		'$vocabulary',
		'$comment',
		'$defs',
		'definitions',
		'additionalProperties'
	]);

	const out: Record<string, any> = {};
	for (const [key, value] of Object.entries(schema)) {
		if (!omit.has(key)) {
			out[key] = stripMetaSchema(value);
		}
	}
	return out;
}

export function normalizeGoogleSchema(schema: any): any {
	if (!schema || typeof schema !== 'object') return schema;
	if (Array.isArray(schema)) return schema.map(normalizeGoogleSchema);

	const out: Record<string, any> = {};
	for (const [key, value] of Object.entries(schema)) {
		if (key === 'type' && typeof value === 'string') {
			out[key] = value.toUpperCase();
		} else {
			out[key] = normalizeGoogleSchema(value);
		}
	}
	return out;
}

export function sanitizeToolsForGoogle(tools: any[] | undefined, forceUppercaseTypes = false): any[] | undefined {
	if (!tools || !Array.isArray(tools)) return tools;
	return tools.map((tool) => {
		const newTool = { ...tool };
		if (newTool.function_declarations && Array.isArray(newTool.function_declarations)) {
			newTool.function_declarations = newTool.function_declarations.map((decl: any) => {
				const newDecl = { ...decl };
				if (newDecl.parameters) {
					let cleaned = stripMetaSchema(newDecl.parameters);
					if (forceUppercaseTypes) {
						cleaned = normalizeGoogleSchema(cleaned);
					}
					newDecl.parameters = cleaned;
				}
				return newDecl;
			});
		}
		if (newTool.functionDeclarations && Array.isArray(newTool.functionDeclarations)) {
			newTool.functionDeclarations = newTool.functionDeclarations.map((decl: any) => {
				const newDecl = { ...decl };
				if (newDecl.parameters) {
					let cleaned = stripMetaSchema(newDecl.parameters);
					if (forceUppercaseTypes) {
						cleaned = normalizeGoogleSchema(cleaned);
					}
					newDecl.parameters = cleaned;
				}
				return newDecl;
			});
		}
		return newTool;
	});
}
