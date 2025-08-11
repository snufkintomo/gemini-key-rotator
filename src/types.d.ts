declare module '*.html' {
    const content: string;
    export default content;
}

interface GeminiCandidate {
    content?: {
        parts: { text: string }[];
        role: string;
    };
}

interface GeminiResponse {
    candidates?: GeminiCandidate[];
}
