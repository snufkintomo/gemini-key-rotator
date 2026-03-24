import { describe, it, expect } from 'vitest';
import { transformClaudeMessagesToGeminiContents, transformClaudeToolsToGeminiTools, transformClaudeToGeminiRequest } from './claude';

describe('Claude to Gemini Transformation', () => {
  describe('transformClaudeMessagesToGeminiContents', () => {
    it('should transform basic text messages correctly', async () => {
      const messages = [
        { role: 'user', content: 'Hello' },
        { role: 'assistant', content: 'Hi!' }
      ];
      const result = await transformClaudeMessagesToGeminiContents(messages as any);
      expect(result.contents).toHaveLength(2);
      expect(result.contents[0]).toEqual({
        role: 'user',
        parts: [{ text: 'Hello' }]
      });
      expect(result.contents[1]).toEqual({
        role: 'model',
        parts: [{ text: 'Hi!' }]
      });
    });

    it('should handle system messages correctly', async () => {
      const messages = [
        { role: 'system', content: 'System instruction' },
        { role: 'user', content: 'Hello' }
      ];
      const result = await transformClaudeMessagesToGeminiContents(messages as any);
      expect(result.system_instruction).toEqual({
        parts: [{ text: 'System instruction' }]
      });
      expect(result.contents).toHaveLength(1);
    });

    it('should handle array content (text and image)', async () => {
      const messages = [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'Describe this image' },
            {
              type: 'image',
              source: {
                type: 'base64',
                media_type: 'image/jpeg',
                data: 'base64data'
              }
            }
          ]
        }
      ];
      const result = await transformClaudeMessagesToGeminiContents(messages as any);
      expect(result.contents[0].parts).toHaveLength(2);
      expect(result.contents[0].parts[0]).toEqual({ text: 'Describe this image' });
      expect(result.contents[0].parts[1]).toEqual({
        inlineData: {
          mimeType: 'image/jpeg',
          data: 'base64data'
        }
      });
    });
  });

  describe('transformClaudeToolsToGeminiTools', () => {
    it('should transform Claude tools to Gemini function declarations', () => {
      const tools = [
        {
          name: 'get_weather',
          description: 'Get weather',
          input_schema: {
            type: 'object',
            properties: {
              location: { type: 'string' }
            }
          }
        }
      ];
      const result = transformClaudeToolsToGeminiTools(tools as any);
      expect(result.tools).toHaveLength(1);
      expect(result.tools![0].function_declarations).toHaveLength(1);
      expect(result.tools![0].function_declarations[0].name).toBe('get_weather');
    });

    it('should handle tool_choice "auto"', () => {
      const result = transformClaudeToolsToGeminiTools([], { type: 'auto' } as any);
      expect(result.tool_config).toEqual({
        function_calling_config: { mode: 'AUTO' }
      });
    });

    it('should handle tool_choice for specific tool', () => {
      const result = transformClaudeToolsToGeminiTools([], { type: 'tool', tool: { name: 'my_tool' } } as any);
      expect(result.tool_config).toEqual({
        function_calling_config: { mode: 'ANY', allowed_function_names: ['my_tool'] }
      });
    });
  });

  describe('transformClaudeToGeminiRequest', () => {
    it('should compile a full request', async () => {
      const claudeReq = {
        model: 'claude-3-5-sonnet-20240620',
        messages: [{ role: 'user', content: 'Hello' }],
        max_tokens: 1024,
        temperature: 0,
        thinking: { type: 'enabled', budget_tokens: 2048 }
      };
      const result = await transformClaudeToGeminiRequest(claudeReq as any);
      expect(result.contents).toBeDefined();
      expect(result.generationConfig.maxOutputTokens).toBe(1024);
      expect(result.generationConfig.temperature).toBe(0.6); // 0 maps to 0.6
      expect(result.generationConfig.thinkingConfig.thinkingBudget).toBe(2048);
    });
  });
});
