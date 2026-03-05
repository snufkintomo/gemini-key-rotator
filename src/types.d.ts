declare module './admin.html' {
    const content: string;
    export default content;
}

declare module './login.html' {
    const content: string;
    export default content;
}

export interface KeyState {
	exhaustedUntil?: { [model: string]: number };
	invalid?: boolean;
}

export interface ApiCredentials {
	api_keys: string;
	current_key_index: number;
	key_states: string | null; // JSON string of KeyState[]
	oauth_credentials?: string;
	current_oauth_index?: number;
	oauth_key_states?: string | null; // JSON string of KeyState[]
}

export interface GeminiModel {
	name: string;
	description: string;
	[key: string]: any;
}

export interface GeminiModelsList {
	models: GeminiModel[];
}

export interface GeminiPart {
    text?: string;
    functionCall?: {
        name: string;
        args: Record<string, any>;
    };
}

export interface GeminiCandidate {
    content?: {
        parts: GeminiPart[];
        role: string;
    };
    index: number;
    finishReason?: 'STOP' | 'MAX_TOKENS' | 'SAFETY' | 'RECITATION' | 'OTHER';
}

export interface GeminiResponse {
    candidates?: GeminiCandidate[];
    usageMetadata?: {
        promptTokenCount?: number;
        candidatesTokenCount?: number;
        totalTokenCount?: number;
        thoughtsTokenCount?: number;
    };
}

// New Claude-specific interfaces (simplified for plan, will be detailed in implementation)
// Based on Anthropic's Messages API
export interface ClaudeMessagePart {
    type: 'text' | 'image' | 'audio' | 'document' | 'tool_use' | 'tool_result' | 'thinking';
    text?: string;
    source?: {
        type: 'base64';
        media_type: string;
        data: string;
    };
    id?: string; // For tool_use
    name?: string; // For tool_use
    input?: Record<string, any>; // For tool_use
    tool_use_id?: string; // For tool_result
    content?: string | Record<string, any>; // For tool_result
    thinking?: string; // For thinking
}

export interface ClaudeMessage {
    role: 'user' | 'assistant';
    content: string | ClaudeMessagePart[];
}

export interface ClaudeTool {
    name: string;
    description?: string;
    input_schema: Record<string, any>;
}

export interface ClaudeCompletionRequest {
    model: string;
    messages: ClaudeMessage[];
    system?: string;
    max_tokens: number; // Required for Claude
    stream?: boolean;
    tools?: ClaudeTool[];
    tool_choice?: { type: 'auto' | 'tool' | 'none'; tool?: { name: string } };
    stop_sequences?: string[];
    temperature?: number;
    top_p?: number;
    top_k?: number;
    thinking?: {
        type: 'enabled';
        budget_tokens?: number;
    };
    metadata?: {
        user_id?: string;
    };
}

export interface ClaudeCompletionResponseChunk {
    type: 'message_start' | 'content_block_start' | 'content_block_delta' | 'content_block_stop' | 'message_delta' | 'message_stop';
    message?: {
        id: string;
        type: 'message';
        role: 'assistant';
        model: string;
        content: ClaudeMessagePart[];
        stop_reason: null;
        stop_sequence: null;
        usage: {
            input_tokens: number;
            output_tokens: number;
        };
    };
    delta?: {
        type: 'text_delta' | 'tool_use';
        text?: string;
        tool_use?: { id: string; name: string; input: Record<string, any> };
    };
    index?: number; // For content_block_delta
    usage?: {
        output_tokens: number;
    };
    stop_reason?: string;
    stop_sequence?: string | null;
}

export {}; // Treat this file as a module

export interface ClaudeCompletionResponse {
    id: string;
    type: 'message';
    role: 'assistant';
    model: string;
    content: ClaudeMessagePart[];
    stop_reason: string | null;
    stop_sequence: string | null;
    usage: {
        input_tokens: number;
        output_tokens: number;
    };
}

// OAuth-related types for Gemini CLI and Antigravity support
export interface OAuthCredentials {
    client_id: string;
    client_secret: string;
    refresh_token: string;
    project_id?: string; // For Gemini CLI
    email?: string;
    tier?: string;
}

export interface GoogleTokenResponse {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
    scope: string;
    token_type: string;
}

export interface GeminiCliRequest {
    model: string;
    project: string;
    request: {
        contents: {
            role: 'user' | 'model';
            parts: GeminiPart[];
        }[];
        generationConfig: {
            maxOutputTokens?: number;
            temperature?: number;
            topK?: number;
            topP?: number;
            stopSequences?: string[];
            thinkingConfig?: {
                thinkingBudget: number;
                includeThoughts: boolean;
            };
            responseSchema?: any;
            responseMimeType?: string;
        };
        safetySettings?: {
            category: string;
            threshold: string;
        }[];
        tools?: {
            functionDeclarations: {
                name: string;
                description: string;
                parameters: Record<string, any>;
            }[];
        }[];
        toolConfig?: {
            functionCallingConfig: {
                mode: 'AUTO' | 'NONE' | 'ANY';
                allowedFunctionNames?: string[];
            };
        };
        systemInstruction?: {
            role?: 'user';
            parts: { text: string }[];
        };
    };
}

export interface AntigravityRequest {
    project: string;
    userAgent: string;
    requestType: string;
    requestId: string;
    model: string;
    request: {
        contents: {
            role: 'user' | 'model';
            parts: GeminiPart[];
        }[];
        generationConfig: {
            maxOutputTokens?: number;
            temperature?: number;
            topK?: number;
            topP?: number;
            stopSequences?: string[];
            thinkingConfig?: {
                thinkingBudget: number;
                includeThoughts: boolean;
            };
        };
        safetySettings?: {
            category: string;
            threshold: string;
        }[];
        tools?: {
            functionDeclarations: {
                name: string;
                description: string;
                parameters: Record<string, any>;
            }[];
        }[];
        toolConfig?: {
            functionCallingConfig: {
                mode: 'AUTO' | 'NONE' | 'ANY';
                allowedFunctionNames?: string[];
            };
        };
        systemInstruction?: {
            role?: 'user';
            parts: { text: string }[];
        };
        sessionId?: string;
    };
}

export interface ProjectMetadata {
    project_id: string;
    project_number: string;
    name: string;
    parent?: {
        type: string;
        id: string;
    };
}
