import { describe, it, expect } from 'vitest';
import { transformConfig, transformOpenAIMessagesToGeminiContents, transformTools, handleOpenAI, processCompletionsResponse } from './openai';

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

    it('should handle nested response_format json_schema recursively', () => {
      const openAIReq = {
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'nested_test',
            schema: {
              $schema: 'http://json-schema.org/draft-07/schema#',
              type: 'object',
              additionalProperties: false,
              properties: {
                user: {
                  type: 'object',
                  additionalProperties: false,
                  properties: {
                    name: { type: 'string' }
                  }
                }
              }
            }
          }
        }
      };
      const result = transformConfig(openAIReq);
      expect(result.responseSchema).toEqual({
        type: 'object',
        properties: {
          user: {
            type: 'object',
            properties: {
              name: { type: 'string' }
            }
          }
        }
      });
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
      expect(result.contents!).toHaveLength(2);
      expect(result.contents![0]).toEqual({
        role: 'user',
        parts: [{ text: 'Hello' }]
      });
      expect(result.contents![1]).toEqual({
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
      expect(result.contents!).toHaveLength(1);
    });

    it('should merge consecutive same-role messages', async () => {
      const messages = [
        { role: 'user', content: 'First user prompt' },
        { role: 'user', content: 'Second user prompt' },
        { role: 'assistant', content: 'Response' }
      ];
      const result = await transformOpenAIMessagesToGeminiContents(messages as any);
      expect(result.contents!).toHaveLength(2); // Consecutive users are merged
      expect(result.contents![0]).toEqual({
        role: 'user',
        parts: [
          { text: 'First user prompt' },
          { text: 'Second user prompt' }
        ]
      });
    });

    it('should ensure conversation starts with a user message', async () => {
      const messages = [
        { role: 'assistant', content: 'Hello user' }
      ];
      const result = await transformOpenAIMessagesToGeminiContents(messages as any);
      expect(result.contents!).toHaveLength(2); // Dummy user message inserted at front
      expect(result.contents![0].role).toBe('user');
      expect(result.contents![0].parts[0].text).toBe('...');
      expect(result.contents![1].role).toBe('model');
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

  describe('handleOpenAI Image Generation', () => {
    it('should handle /images/generations correctly and return base64 images', async () => {
      const mockRequestPayload = {
        prompt: 'a futuristic city',
        n: 1,
        size: '1024x1024',
        response_format: 'b64_json'
      };

      const mockGeminiResponse = {
        generatedImages: [
          {
            image: {
              imageBytes: 'fake_base64_data_for_futuristic_city'
            }
          }
        ]
      };

      const mockHandleGemini = async (req: Request, apiKey: string) => {
        expect(req.url).toContain('imagen-3.0-generate-002:generateImages');
        const body: any = await req.json();
        expect(body.prompt).toBe('a futuristic city');
        expect(body.aspectRatio).toBe('1:1');
        expect(body.numberOfImages).toBe(1);

        return new Response(JSON.stringify(mockGeminiResponse), { status: 200 });
      };

      const response = await handleOpenAI(
        mockRequestPayload,
        '/v1/images/generations',
        'POST',
        'fake-api-key',
        'dall-e-3',
        mockHandleGemini
      );

      expect(response.status).toBe(200);
      const data: any = await response.json();
      expect(data.data).toHaveLength(1);
      expect(data.data[0].b64_json).toBe('fake_base64_data_for_futuristic_city');
    });

    it('should handle /images/generations returning URL format as data URL', async () => {
      const mockRequestPayload = {
        prompt: 'a space cat',
        n: 1,
        size: '1792x1024',
        response_format: 'url'
      };

      const mockGeminiResponse = {
        generatedImages: [
          {
            image: {
              imageBytes: 'space_cat_bytes'
            }
          }
        ]
      };

      const mockHandleGemini = async (req: Request, apiKey: string) => {
        expect(req.url).toContain('imagen-3.0-generate-002:generateImages');
        const body: any = await req.json();
        expect(body.aspectRatio).toBe('16:9');

        return new Response(JSON.stringify(mockGeminiResponse), { status: 200 });
      };

      const response = await handleOpenAI(
        mockRequestPayload,
        '/v1/images/generations',
        'POST',
        'fake-api-key',
        'dall-e-3',
        mockHandleGemini
      );

      expect(response.status).toBe(200);
      const data: any = await response.json();
      expect(data.data[0].url).toBe('data:image/jpeg;base64,space_cat_bytes');
    });
  });

  describe('handleOpenAI Audio Transcription', () => {
    it('should parse form-data and transcribe audio using Gemini', async () => {
      const fileContent = new TextEncoder().encode('fake-audio-bytes');
      const file = new File([fileContent], 'test.mp3', { type: 'audio/mp3' });
      file.arrayBuffer = async () => fileContent.buffer;

      const mockFormData = new FormData();
      mockFormData.append('file', file);
      mockFormData.append('model', 'whisper-1');

      const mockRequest = new Request('https://localhost/v1/audio/transcriptions', {
        method: 'POST',
        body: mockFormData
      }) as any;
      
      // Mock formData() and clone() to bypass JSDOM's broken multipart serializer
      mockRequest.formData = async () => mockFormData;
      mockRequest.clone = () => {
        const cloned = new Request('https://localhost/v1/audio/transcriptions', { method: 'POST' }) as any;
        cloned.formData = async () => mockFormData;
        return cloned;
      };

      const mockGeminiResponse = {
        candidates: [
          {
            content: {
              parts: [
                {
                  text: 'This is the transcribed audio text.'
                }
              ]
            }
          }
        ]
      };

      const mockHandleGemini = async (req: Request, apiKey: string) => {
        expect(req.url).toContain('gemini-1.5-flash:generateContent');
        const body: any = await req.json();
        expect(body.contents[0].parts[0].inlineData.mimeType).toBe('audio/mp3');
        expect(body.contents[0].parts[0].inlineData.data).toBe(btoa('fake-audio-bytes'));

        return new Response(JSON.stringify(mockGeminiResponse), { status: 200 });
      };

      const response = await handleOpenAI(
        null, // reqBody is null because form-data is not JSON
        '/v1/audio/transcriptions',
        'POST',
        'fake-api-key',
        'whisper-1',
        mockHandleGemini,
        undefined,
        undefined,
        mockRequest
      );

      expect(response.status).toBe(200);
      const data: any = await response.json();
      expect(data.text).toBe('This is the transcribed audio text.');
    });
  });

  describe('handleOpenAI Responses API', () => {
    it('should handle non-streaming /v1/responses correctly with text modality', async () => {
      const mockRequestPayload = {
        model: 'gpt-4o',
        modalities: ['text'],
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'text', text: 'Hello Gemini!' }
            ]
          }
        ]
      };

      const mockGeminiResponse = {
        candidates: [
          {
            content: {
              parts: [
                {
                  text: 'Hello user! How can I help you today?'
                }
              ]
            }
          }
        ],
        usageMetadata: {
          totalTokenCount: 15,
          promptTokenCount: 5,
          candidatesTokenCount: 10
        }
      };

      const mockHandleGemini = async (req: Request, apiKey: string) => {
        expect(req.url).toContain('gemini-2.0-flash:generateContent');
        const body: any = await req.json();
        expect(body.contents[0].parts[0].text).toBe('Hello Gemini!');
        return new Response(JSON.stringify(mockGeminiResponse), { status: 200 });
      };

      const response = await handleOpenAI(
        mockRequestPayload,
        '/v1/responses',
        'POST',
        'fake-api-key',
        'gemini-2.0-flash',
        mockHandleGemini
      );

      expect(response.status).toBe(200);
      const data: any = await response.json();
      expect(data.object).toBe('response');
      expect(data.status).toBe('completed');
      expect(data.output[0].content[0].text).toBe('Hello user! How can I help you today?');
      expect(data.usage.total_tokens).toBe(15);
    });

    it('should handle non-streaming /v1/responses with audio modality and trigger wav output MimeType', async () => {
      const mockRequestPayload = {
        model: 'gpt-4o-audio-preview',
        modalities: ['text', 'audio'],
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'text', text: 'Say something.' }
            ]
          }
        ]
      };

      const mockGeminiResponse = {
        candidates: [
          {
            content: {
              parts: [
                { text: 'This is the spoken output.' },
                {
                  inlineData: {
                    mimeType: 'audio/wav',
                    data: 'fake_wav_audio_base64_data'
                  }
                }
              ]
            }
          }
        ]
      };

      const mockHandleGemini = async (req: Request, apiKey: string) => {
        const body: any = await req.json();
        expect(body.generationConfig.responseMimeType).toBe('audio/wav');
        return new Response(JSON.stringify(mockGeminiResponse), { status: 200 });
      };

      const response = await handleOpenAI(
        mockRequestPayload,
        '/v1/responses',
        'POST',
        'fake-api-key',
        'gemini-2.0-flash',
        mockHandleGemini
      );

      expect(response.status).toBe(200);
      const data: any = await response.json();
      expect(data.output[0].content).toHaveLength(2);
      expect(data.output[0].content[0].text).toBe('This is the spoken output.');
      expect(data.output[0].content[1].type).toBe('audio');
      expect(data.output[0].content[1].audio.data).toBe('fake_wav_audio_base64_data');
    });
  });

  describe('processCompletionsResponse', () => {
    it('should include thoughtsTokenCount in completion_tokens and total_tokens for non-streaming response', () => {
      const mockGeminiData = {
        candidates: [
          {
            index: 0,
            content: {
              role: 'model',
              parts: [{ text: 'Hello!' }]
            },
            finishReason: 'STOP'
          }
        ],
        usageMetadata: {
          promptTokenCount: 10,
          candidatesTokenCount: 20,
          thoughtsTokenCount: 15,
          totalTokenCount: 45
        }
      };

      const resultStr = processCompletionsResponse(mockGeminiData, 'gemini-2.5-pro', 'mock-id');
      const result = JSON.parse(resultStr);

      expect(result.usage.completion_tokens).toBe(35); // candidatesTokenCount (20) + thoughtsTokenCount (15)
      expect(result.usage.prompt_tokens).toBe(10);
      expect(result.usage.total_tokens).toBe(45);
    });
  });
});
