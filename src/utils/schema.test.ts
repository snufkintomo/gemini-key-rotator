import { describe, it, expect } from 'vitest';
import { stripMetaSchema, normalizeGoogleSchema, sanitizeToolsForGoogle } from './schema';

describe('JSON Schema Sanitization and Normalization', () => {
	it('should recursively strip meta fields and additionalProperties from schema', () => {
		const complexSchema = {
			$schema: 'http://json-schema.org/draft-07/schema#',
			$id: 'https://example.com/product.schema.json',
			title: 'Product',
			type: 'object',
			additionalProperties: false,
			properties: {
				productId: {
					description: 'The unique identifier for a product',
					type: 'integer',
					$comment: 'This is a internal identifier'
				},
				dimensions: {
					type: 'object',
					additionalProperties: false,
					properties: {
						length: { type: 'number' },
						width: { type: 'number' }
					}
				},
				tags: {
					type: 'array',
					items: {
						type: 'string',
						$anchor: 'tag-type'
					}
				}
			},
			definitions: {
				customType: { type: 'string' }
			}
		};

		const expected = {
			title: 'Product',
			type: 'object',
			properties: {
				productId: {
					description: 'The unique identifier for a product',
					type: 'integer'
				},
				dimensions: {
					type: 'object',
					properties: {
						length: { type: 'number' },
						width: { type: 'number' }
					}
				},
				tags: {
					type: 'array',
					items: {
						type: 'string'
					}
				}
			}
		};

		const cleaned = stripMetaSchema(complexSchema);
		expect(cleaned).toEqual(expected);
	});

	it('should normalize types to uppercase recursively', () => {
		const lowercaseSchema = {
			type: 'object',
			properties: {
				name: { type: 'string' },
				age: { type: 'integer' },
				scores: {
					type: 'array',
					items: { type: 'number' }
				}
			}
		};

		const expected = {
			type: 'OBJECT',
			properties: {
				name: { type: 'STRING' },
				age: { type: 'INTEGER' },
				scores: {
					type: 'ARRAY',
					items: { type: 'NUMBER' }
				}
			}
		};

		const normalized = normalizeGoogleSchema(lowercaseSchema);
		expect(normalized).toEqual(expected);
	});

	it('should sanitize tool list with both snake_case and camelCase declarations', () => {
		const originalTools = [
			{
				function_declarations: [
					{
						name: 'get_weather',
						description: 'Get weather',
						parameters: {
							$schema: 'http://json-schema.org/draft-07/schema#',
							type: 'object',
							additionalProperties: false,
							properties: {
								location: { type: 'string' }
							}
						}
					}
				]
			},
			{
				functionDeclarations: [
					{
						name: 'search_web',
						description: 'Search the web',
						parameters: {
							$id: 'search-id',
							type: 'object',
							properties: {
								query: { type: 'string' }
							}
						}
					}
				]
			}
		];

		const sanitizedWithLowercase = sanitizeToolsForGoogle(originalTools, false);
		expect(sanitizedWithLowercase![0].function_declarations[0].parameters).toEqual({
			type: 'object',
			properties: {
				location: { type: 'string' }
			}
		});
		expect(sanitizedWithLowercase![1].functionDeclarations[0].parameters).toEqual({
			type: 'object',
			properties: {
				query: { type: 'string' }
			}
		});

		const sanitizedWithUppercase = sanitizeToolsForGoogle(originalTools, true);
		expect(sanitizedWithUppercase![0].function_declarations[0].parameters).toEqual({
			type: 'OBJECT',
			properties: {
				location: { type: 'STRING' }
			}
		});
		expect(sanitizedWithUppercase![1].functionDeclarations[0].parameters).toEqual({
			type: 'OBJECT',
			properties: {
				query: { type: 'STRING' }
			}
		});
	});
});
