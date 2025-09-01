declare module '*.html' {
    const content: string;
    export default content;
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
    };
}

// New Claude-specific interfaces (simplified for plan, will be detailed in implementation)
// Based on Anthropic's Messages API
export interface ClaudeMessagePart {
    type: 'text' | 'image' | 'tool_use' | 'tool_result' | 'thinking';
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
