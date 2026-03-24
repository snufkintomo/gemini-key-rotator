import { describe, it, expect } from 'vitest';
import { transformConfig, transformOpenAIMessagesToGeminiContents, transformTools } from './openai';

describe('OpenAI to Gemini Transformation', () => {
  describe('transformConfig', () => {
    it('should transform basic parameters correctly', () => {
      const openAIReq = {
        temperature: 0.7,
        max_tokens: 100,
        top_p: 0.9,
        stop: ['\n']
      };
      const result = transformConfig(openAIReq);
      expect(result).toEqual({
        temperature: 0.7,
        maxOutputTokens: 100,
        topP: 0.9,
        stopSequences: ['\n']
      });
    });

    it('should handle temperature 0 correctly by setting it to 0.6', () => {
      const openAIReq = { temperature: 0 };
      const result = transformConfig(openAIReq);
      expect(result.temperature).toBe(0.6);
    });

    it('should handle response_format correctly', () => {
      const openAIReq = { response_format: { type: 'json_object' } };
      const result = transformConfig(openAIReq);
      expect(result.responseMimeType).toBe('application/json');
    });

    it('should handle thinking/reasoning config', () => {
      const openAIReq = { reasoning_effort: 'medium' };
      const result = transformConfig(openAIReq);
      expect(result.thinkingConfig).toEqual({
        thinkingBudget: 8192,
        includeThoughts: true
      });
    });
  });

  describe('transformOpenAIMessagesToGeminiContents', () => {
    it('should transform user and assistant messages', async () => {
      const messages = [
        { role: 'user', content: 'Hello' },
        { role: 'assistant', content: 'Hi there!' }
      ];
      const result = await transformOpenAIMessagesToGeminiContents(messages as any);
      expect(result.contents).toHaveLength(2);
      expect(result.contents[0]).toEqual({
        role: 'user',
        parts: [{ text: 'Hello' }]
      });
      expect(result.contents[1]).toEqual({
        role: 'model',
        parts: [{ text: 'Hi there!' }]
      });
    });

    it('should handle system messages correctly', async () => {
      const messages = [
        { role: 'system', content: 'You are a helpful assistant' },
        { role: 'user', content: 'Hello' }
      ];
      const result = await transformOpenAIMessagesToGeminiContents(messages as any);
      expect(result.system_instruction).toEqual({
        parts: [{ text: 'You are a helpful assistant' }]
      });
      expect(result.contents).toHaveLength(1);
    });
  });

  describe('transformTools', () => {
    it('should transform function tools correctly', () => {
      const req = {
        tools: [
          {
            type: 'function',
            function: {
              name: 'get_weather',
              description: 'Get weather',
              parameters: {
                type: 'object',
                properties: { location: { type: 'string' } }
              }
            }
          }
        ]
      };
      const { tools } = transformTools(req);
      expect(tools).toHaveLength(1);
      expect(tools![0].function_declarations).toHaveLength(1);
      expect(tools![0].function_declarations[0].name).toBe('get_weather');
    });

    it('should handle tool_choice correctly', () => {
      const req = { tool_choice: 'none' };
      const { tool_config } = transformTools(req);
      expect(tool_config).toEqual({
        function_calling_config: { mode: 'NONE' }
      });
    });
  });
});
