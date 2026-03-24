/**
 * Email utility using Resend API
 */

export async function sendInvalidTokenEmail(
	resendApiKey: string,
	toEmail: string,
	tokenType: 'api_key' | 'oauth',
	rawToken: string,
	reason: string
) {
	const url = 'https://api.resend.com/emails';
	
	const subject = `[Gemini Rotator] ${tokenType.toUpperCase()} Invalidated`;
	
	// Mask the token for security: keep first 6 and last 6, mask middle
	let maskedToken = rawToken;
	if (rawToken.length > 15) {
		maskedToken = `${rawToken.substring(0, 6)}...${rawToken.substring(rawToken.length - 6)}`;
	} else if (rawToken.length > 4) {
		maskedToken = `${rawToken.substring(0, 2)}...${rawToken.substring(rawToken.length - 2)}`;
	}

	const html = `
		<h1>Token Invalidated</h1>
		<p>Your Gemini Key Rotator has detected an invalid token and removed it from rotation.</p>
		<ul>
			<li><strong>Type:</strong> ${tokenType}</li>
			<li><strong>Token (Masked):</strong> <code>${maskedToken}</code></li>
			<li><strong>Reason:</strong> ${reason}</li>
			<li><strong>Time:</strong> ${new Date().toISOString()}</li>
		</ul>
		<p>Please check your credentials in the admin dashboard.</p>
	`;

	try {
		const response = await fetch(url, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${resendApiKey}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				from: 'Gemini Rotator <onboarding@resend.dev>', // Default Resend domain
				to: toEmail,
				subject: subject,
				html: html,
			}),
		});

		if (!response.ok) {
			const error = await response.text();
			console.error(`Failed to send email via Resend: ${response.status} ${error}`);
		}
	} catch (e) {
		console.error('Error sending email via Resend:', e);
	}
}

/**
 * Send email notification when all API keys are exhausted
 */
export async function sendExhaustedEmail(
	resendApiKey: string,
	toEmail: string,
	userToken: string,
	hasFallbackOAuth: boolean,
	model: string
) {
	const url = 'https://api.resend.com/emails';
	const subject = `[Gemini Rotator] API KEYS EXHAUSTED - Fallback to ${hasFallbackOAuth ? 'OAuth' : 'NONE'}`;

	const maskedToken = `${userToken.substring(0, 4)}...${userToken.substring(userToken.length - 4)}`;

	const html = `
		<h1>API Keys Exhausted</h1>
		<p>All standard Gemini API keys for a user account have been exhausted (429 rate limited).</p>
		<ul>
			<li><strong>User Token (Masked):</strong> <code>${maskedToken}</code></li>
			<li><strong>Status:</strong> ${hasFallbackOAuth ? 'Falling back to OAuth credentials' : 'CRITICAL: No fallback available, requests failing'}</li>
			<li><strong>Model requested:</strong> ${model}</li>
			<li><strong>Time:</strong> ${new Date().toISOString()}</li>
		</ul>
		<p>Please consider adding more API keys or checking usage patterns.</p>
	`;

	try {
		const response = await fetch(url, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${resendApiKey}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				from: 'Gemini Rotator <onboarding@resend.dev>',
				to: toEmail,
				subject: subject,
				html: html,
			}),
		});

		if (!response.ok) {
			const error = await response.text();
			console.error(`Failed to send exhausted email: ${response.status} ${error}`);
		}
	} catch (e) {
		console.error('Error sending exhausted email:', e);
	}
}
