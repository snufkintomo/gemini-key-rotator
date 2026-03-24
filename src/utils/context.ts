import { Env } from '../rotator';

export class SystemContext {
	state: DurableObjectState;
	env: Env;

	constructor(state: DurableObjectState, env: Env) {
		this.state = state;
		this.env = env;
	}

	get isLoggingEnabled(): boolean {
		return this.env.ENABLE_API_LOGGING === 'true';
	}

	get isCloudflareAIGatewayEnabled(): boolean {
		return this.env.ENABLE_CLOUDFLARE_AI_GATEWAY === 'true';
	}

	get isOrgGeminiApiEnabled(): boolean {
		return this.env.ENABLE_ORG_GEMINI_API_BASE_URL === 'true';
	}

	get isUsageStatisticsEnabled(): boolean {
		return this.env.ENABLE_USAGE_STATISTICS === 'true';
	}

	get notificationEmail(): string | undefined {
		return this.env.NOTIFICATION_EMAIL;
	}

	get resendApiKey(): string | undefined {
		return this.env.RESEND_API_KEY;
	}

	get cloudflareAIGatewayBase(): string {
		return `https://gateway.ai.cloudflare.com/v1/${this.env.CLOUDFLARE_AI_GATEWAY_ID}/${this.env.CLOUDFLARE_AI_GATEWAY_NAME}`;
	}

	get orgGeminiApiBaseUrl(): string {
		return 'https://generativelanguage.googleapis.com';
	}

	waitUntil(promise: Promise<any>): void {
		this.state.waitUntil(promise);
	}
}
