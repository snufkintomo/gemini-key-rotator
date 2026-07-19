import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KeyRotator, Env } from '../rotator';
import { transformClaudeToGeminiRequest } from './claude';

describe('Durable Object Local SQLite & Caching Mappings', () => {
    let mockState: any;
    let mockEnv: Env;
    let mockDB: any;
    let mockStorage: any;
    let sqliteQueries: string[] = [];
    let sqliteStorage = new Map<string, any>();

    beforeEach(() => {
        sqliteQueries = [];
        sqliteStorage.clear();
        
        mockStorage = new Map();
        mockState = {
            storage: {
                get: vi.fn(async (key: string) => mockStorage.get(key)),
                put: vi.fn(async (key: string, value: any) => mockStorage.set(key, value)),
                getAlarm: vi.fn(async () => null),
                setAlarm: vi.fn(async () => {}),
                // Mock DO SQLite in-memory engine
                sql: {
                    exec: vi.fn((query: string, ...binds: any[]) => {
                        sqliteQueries.push(query);
                        
                        // Basic mock behavior for Exact Match Cache
                        if (query.includes('SELECT response, expires_at FROM exact_match_cache')) {
                            const hash = binds[0];
                            const item = sqliteStorage.get(`exact:${hash}`);
                            return {
                                next: () => ({
                                    value: item ? { response: item.response, expires_at: item.expires_at } : null
                                })
                            };
                        }
                        if (query.includes('INSERT OR REPLACE INTO exact_match_cache')) {
                            const hash = binds[0];
                            const response = binds[1];
                            const expires_at = binds[2];
                            sqliteStorage.set(`exact:${hash}`, { response, expires_at });
                        }

                        // Basic mock behavior for Gemini Context Cache
                        if (query.includes('SELECT gemini_cache_id, api_key, expires_at FROM gemini_context_caches')) {
                            const hash = binds[0];
                            const model = binds[1];
                            const item = sqliteStorage.get(`context:${hash}:${model}`);
                            return {
                                next: () => ({
                                    value: item ? { gemini_cache_id: item.gemini_cache_id, api_key: item.api_key, expires_at: item.expires_at } : null
                                })
                            };
                        }
                        if (query.includes('INSERT OR REPLACE INTO gemini_context_caches')) {
                            const hash = binds[0];
                            const gemini_cache_id = binds[1];
                            const api_key = binds[2];
                            const model = binds[3];
                            const expires_at = binds[4];
                            sqliteStorage.set(`context:${hash}:${model}`, { gemini_cache_id, api_key, expires_at });
                        }

                        return { next: () => ({ value: null }) };
                    })
                }
            },
            waitUntil: vi.fn(),
        };

        mockDB = {
            prepare: vi.fn().mockReturnThis(),
            bind: vi.fn().mockReturnThis(),
            run: vi.fn().mockResolvedValue({ success: true }),
        };

        mockEnv = {
            DB: mockDB,
            CLOUDFLARE_AI_GATEWAY_ID: 'test-id',
            CLOUDFLARE_AI_GATEWAY_NAME: 'test-gateway',
        };
    });

    it('should initialize SQLite tables on Durable Object startup', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        expect(sqliteQueries.some(q => q.includes('CREATE TABLE IF NOT EXISTS exact_match_cache'))).toBe(true);
        expect(sqliteQueries.some(q => q.includes('CREATE TABLE IF NOT EXISTS gemini_context_caches'))).toBe(true);
    });

    it('should set and get Exact-Match Cache from DO SQLite successfully', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        const testHash = 'hash123';
        const responseData = { body: 'hello', status: 200, headers: { 'Content-Type': 'application/json' } };
        
        rotator.setExactMatchCache(testHash, responseData, 50000);
        const cached = rotator.getExactMatchCache(testHash);
        expect(cached).toEqual(responseData);
    });

    it('should set and get Gemini Context Cache from DO SQLite successfully', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        const testHash = 'prefixHash123';
        const model = 'gemini-2.5-pro';
        const cacheId = 'cachedContents/abc';
        const apiKey = 'key_a';
        
        rotator.setGeminiContextCache(testHash, model, cacheId, apiKey, 50000);
        const cached = rotator.getGeminiContextCache(testHash, model);
        expect(cached).toEqual({ gemini_cache_id: cacheId, api_key: apiKey });
    });
});

describe('Claude-to-Gemini Caching Translation Parser', () => {
    it('should extract cache control metadata from messages with ephemeral cache_control', async () => {
        const claudeReq: any = {
            model: 'claude-3-5-sonnet',
            system: 'Always answer like a pirate.',
            messages: [
                {
                    role: 'user',
                    content: [
                        {
                            type: 'text',
                            text: 'First message context...',
                            cache_control: { type: 'ephemeral' }
                        }
                    ]
                },
                {
                    role: 'assistant',
                    content: 'Aye matey!'
                },
                {
                    role: 'user',
                    content: 'And what is your command?'
                }
            ]
        };

        const geminiReq = await transformClaudeToGeminiRequest(claudeReq);
        
        // Assert that private tag exists
        expect(geminiReq.__claude_cache_control__).toBeDefined();
        expect(geminiReq.__claude_cache_control__.hash).toBeDefined();
        // Since the cache control is on index 0, remaining contents index should be 1
        expect(geminiReq.__claude_cache_control__.remaining_contents_index).toBe(1);
        expect(geminiReq.__claude_cache_control__.cacheable_payload.contents.length).toBe(1);
    });
});

describe('Unified Gemini Prompt Pruner', () => {
    let mockState: any;
    let mockEnv: Env;

    beforeEach(() => {
        mockState = {
            storage: {
                get: vi.fn(),
                put: vi.fn(),
                getAlarm: vi.fn(),
                setAlarm: vi.fn(),
                sql: null // No SQL needed for memory pruner tests
            },
            waitUntil: vi.fn(),
        };
        mockEnv = {
            DB: {} as any,
            CLOUDFLARE_AI_GATEWAY_ID: 'test-id',
            CLOUDFLARE_AI_GATEWAY_NAME: 'test-gateway',
        };
    });

    it('should prune older expired tool call and response pairs', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        const contents = [
            {
                role: 'user',
                parts: [{ text: 'Please read this file' }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'read_file', args: { path: 'src/index.ts' } } }]
            },
            {
                role: 'user', // older duplicate tool result
                parts: [{ functionResponse: { name: 'read_file', response: { content: 'const a = 1;' } } }]
            },
            {
                role: 'user',
                parts: [{ text: 'Now modify it' }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'read_file', args: { path: 'src/index.ts' } } }]
            },
            {
                role: 'user', // newer latest tool result (should be kept)
                parts: [{ functionResponse: { name: 'read_file', response: { content: 'const a = 2;' } } }]
            }
        ];

        const { prunedContents, stats } = rotator.pruneGeminiContents(contents);

        // Expect the older functionCall (index 1) and older functionResponse (index 2) to be pruned!
        expect(stats.expiredRemoved).toBe(2);
        expect(prunedContents.length).toBe(3); // User 1 + User 2 merged, Model 2, User 3
    });

    it('should collapse large duplicate text blocks', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        const largeText = 'A'.repeat(250); // > 200 chars
        const contents = [
            {
                role: 'user',
                parts: [{ text: largeText }]
            },
            {
                role: 'model',
                parts: [{ text: 'Understood.' }]
            },
            {
                role: 'user', // exact duplicate text block
                parts: [{ text: largeText }]
            }
        ];

        const { prunedContents, stats } = rotator.pruneGeminiContents(contents);
        expect(stats.duplicatesRemoved).toBe(1);
        expect(prunedContents.length).toBe(3); // Turn preserved, but with a semantic tombstone
        expect(prunedContents[2].parts[0].text).toContain("Duplicate text removed");
    });

    it('should restore pruned tool outputs if referenced in surviving turns', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        const contents = [
            {
                role: 'user',
                parts: [{ text: 'Please check the file rotator.ts' }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'read_file', args: { path: 'src/rotator.ts' } } }]
            },
            {
                role: 'user', // older duplicate tool result (would be pruned normally)
                parts: [{ functionResponse: { name: 'read_file', response: { content: 'class KeyRotator {}' } } }]
            },
            {
                role: 'user',
                parts: [{ text: 'Now check another file' }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'read_file', args: { path: 'src/rotator.ts' } } }]
            },
            {
                role: 'user', // newer latest tool result
                parts: [{ functionResponse: { name: 'read_file', response: { content: 'class KeyRotator { updated: true }' } } }]
            },
            {
                role: 'user', // surviving turn explicitly references the file rotator.ts!
                parts: [{ text: 'Why did you change the class KeyRotator inside rotator.ts?' }]
            }
        ];

        const { prunedContents, stats } = rotator.pruneGeminiContents(contents);
        
        // Since "rotator.ts" is referenced in the final user turn, 
        // the older read_file pair should NOT be pruned (it gets restored)!
        expect(stats.restoredCount).toBe(2);
        expect(stats.expiredRemoved).toBe(0); // expired count goes to 0 because of restoration
    });

    it('should merge adjacent turns of the same role to maintain alternating syntax', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        const contents = [
            {
                role: 'user',
                parts: [{ text: 'Turn 1' }]
            },
            {
                role: 'user', // consecutive user turn (can happen after pruning or bad inputs)
                parts: [{ text: 'Turn 2' }]
            },
            {
                role: 'model',
                parts: [{ text: 'Understood.' }]
            }
        ];

        const { prunedContents } = rotator.pruneGeminiContents(contents);
        
        // Expect adjacent user turns to be merged into a single user turn with both parts
        expect(prunedContents.length).toBe(2);
        expect(prunedContents[0].role).toBe('user');
        expect(prunedContents[0].parts.length).toBe(2);
        expect(prunedContents[0].parts[0].text).toBe('Turn 1');
        expect(prunedContents[0].parts[1].text).toBe('Turn 2');
    });

    it('should apply Pass 4 Error Log Tombstoning under proper rules', () => {
        const rotator = new KeyRotator(mockState, mockEnv);

        // Scenario 1: Same-Command Success Detection on a RESTORED pair
        // Turn 2 is a failed read_file command. Turn 4 is a successful read_file command.
        // Turn 5 references 'rotator.ts', restoring Turn 2's pair from Pass 1 deletion.
        // We expect Turn 2's failure to be tombstoned because there is a later success in Turn 4!
        const contents1 = [
            {
                role: 'user',
                parts: [{ text: 'Please read src/rotator.ts' }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'read_file', args: { path: 'src/rotator.ts' } } }]
            },
            {
                role: 'user', // Failed response
                parts: [{ functionResponse: { name: 'read_file', response: { exitCode: 1, error: 'FileNotFound: src/rotator.ts' } } }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'read_file', args: { path: 'src/rotator.ts' } } }]
            },
            {
                role: 'user', // Successful response
                parts: [{ functionResponse: { name: 'read_file', response: { content: 'class KeyRotator {}' } } }]
            },
            {
                role: 'user', // References the command/file, triggering restoration of the first pair!
                parts: [{ text: 'Great, why did src/rotator.ts fail previously?' }]
            }
        ];

        const res1 = rotator.pruneGeminiContents(contents1);
        expect(res1.stats.restoredCount).toBe(2); // The older pair is restored from physical deletion
        expect(res1.stats.errorsTombstoned).toBe(1); // But its failure output is tombstoned!
        const failedPart = res1.prunedContents[2].parts[0];
        expect(failedPart.functionResponse.response.output).toContain('Old build/runtime error log removed');
        expect(failedPart.functionResponse.response.exitCode).toBe(0); // cleared to 0 for LLM safety

        // Scenario 2: Under 20,000 tokens & no later success -> should NOT tombstone based on turns alone
        const contents2 = [
            {
                role: 'user',
                parts: [{ text: 'Help me fix this compilation error' }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'execute_command', args: { command: 'npm run build' } } }]
            },
            {
                role: 'user', // Old compile error (10 turns ago), but low token pressure
                parts: [{ functionResponse: { name: 'execute_command', response: { exitCode: 1, error: 'TypeScript Compilation Error' } } }]
            },
            // ... padding to 10 turns
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'What is the current error?' }] }
        ];

        const res2 = rotator.pruneGeminiContents(contents2);
        // Under low token pressure, keep maximum context
        expect(res2.stats.errorsTombstoned).toBe(0);

        // Scenario 3: Over 20,000 tokens (Heavy token pressure) AND Turn index > 8 -> should tombstone!
        // We'll simulate heavy token pressure by adding a massive text block (> 80,000 characters) to represent long history
        const massiveText = 'X'.repeat(85000);
        const contents3 = [
            {
                role: 'user',
                parts: [{ text: massiveText }]
            },
            {
                role: 'model',
                parts: [{ functionCall: { name: 'execute_command', args: { command: 'npm run build' } } }]
            },
            {
                role: 'user', // Old compile error (> 8 turns ago) under massive token pressure
                parts: [{ functionResponse: { name: 'execute_command', response: { exitCode: 1, error: 'TypeScript Compilation Error' } } }]
            },
            // padding turns
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'A' }] }, { role: 'model', parts: [{ text: 'B' }] },
            { role: 'user', parts: [{ text: 'What is the current state?' }] }
        ];

        const res3 = rotator.pruneGeminiContents(contents3);
        expect(res3.stats.errorsTombstoned).toBe(1);
        const highPressureTombstonedPart = res3.prunedContents[2].parts[0];
        expect(highPressureTombstonedPart.functionResponse.response.output).toContain('Old build/runtime error log removed');
    });

    it('should compress git diff content by keeping modified lines and folding unchanged context (Pass 5 DiffCompaction)', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        
        const originalDiff = [
            'diff --git a/src/rotator.ts b/src/rotator.ts',
            'index 123456..789abc 100644',
            '--- a/src/rotator.ts',
            '+++ b/src/rotator.ts',
            '@@ -220,20 +220,20 @@',
            ' Line 1',
            ' Line 2',
            ' Line 3',
            ' Line 4',
            ' Line 5',
            ' Line 6',
            ' Line 7',
            ' Line 8',
            '- Old Line 9',
            '+ New Line 9',
            ' Line 10',
            ' Line 11',
            ' Line 12',
            ' Line 13',
            ' Line 14',
            ' Line 15',
            ' Line 16',
            ' Line 17',
            ' Line 18',
            ' Line 19'
        ].join('\n');

        const compacted = rotator.compactGitDiff(originalDiff);
        
        expect(compacted).toContain('- Old Line 9');
        expect(compacted).toContain('+ New Line 9');
        expect(compacted).toContain('diff --git a/src/rotator.ts b/src/rotator.ts');
        expect(compacted).toContain('folded to save tokens');
        expect(compacted).not.toContain(' Line 1\n');
        expect(compacted).toContain(' Line 5');
    });

    it('should strip ANSI escape codes and styling from text (inspired by rtk)', () => {
        const rotator = new KeyRotator(mockState, mockEnv);
        const coloredText = '\x1b[31mError:\x1b[39m \x1b[1mCompilation failed\x1b[22m';
        const cleanText = rotator.stripAnsi(coloredText);
        expect(cleanText).toBe('Error: Compilation failed');
    });
});
