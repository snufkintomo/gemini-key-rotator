/**
 * Email utility using Resend API
 */

export async function sendInvalidTokenEmail(
	resendApiKey: string,
	toEmail: string | string[],
	tokenType: 'api_key' | 'oauth',
	rawToken: string,
	reason: string
) {
	const url = 'https://api.resend.com/emails';
	
	const subject = `[Gemini Rotator] ${tokenType.toUpperCase()} Invalidated`;
	
	let maskedToken = rawToken;
	let oauthEmail = '';
	let oauthProject = '';

	if (tokenType === 'oauth') {
		const parts = rawToken.split(':');
		const refreshToken = parts[2]?.trim() || '';
		oauthProject = parts[3]?.trim() || 'default';
		oauthEmail = parts[4]?.trim() || '';

		let maskedRefreshToken = refreshToken;
		if (refreshToken.length > 12) {
			maskedRefreshToken = `${refreshToken.substring(0, 10)}...${refreshToken.substring(refreshToken.length - 6)}`;
		}
		maskedToken = maskedRefreshToken;
	} else {
		// Mask the token for security: keep first 6 and last 6, mask middle
		if (rawToken.length > 15) {
			maskedToken = `${rawToken.substring(0, 6)}...${rawToken.substring(rawToken.length - 6)}`;
		} else if (rawToken.length > 4) {
			maskedToken = `${rawToken.substring(0, 2)}...${rawToken.substring(rawToken.length - 2)}`;
		}
	}

	const html = `
		<h1>Token Invalidated</h1>
		<p>Your Gemini Key Rotator has detected an invalid token and removed it from rotation.</p>
		<ul>
			<li><strong>Type:</strong> ${tokenType}</li>
			${oauthEmail ? `<li><strong>Account Owner Email:</strong> <code style="color: #d9383a; font-weight: bold; font-size: 1.1em;">${oauthEmail}</code></li>` : ''}
			${oauthProject ? `<li><strong>Project ID:</strong> <code>${oauthProject}</code></li>` : ''}
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
	toEmail: string | string[],
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

/**
 * Send email notification for keys with long-term 0% success rate
 */
export async function sendZeroSuccessRateAlertEmail(
	resendApiKey: string,
	toEmail: string,
	failedKeys: Array<{
		rawKey: string;
		keyType: string;
		totalRequests: number;
		model: string;
		userToken: string;
	}>
) {
	const url = 'https://api.resend.com/emails';
	const subject = `[Gemini Rotator] Alert: 0% Success Rate Keys Detected`;

	let rowsHtml = '';
	for (const keyInfo of failedKeys) {
		const raw = keyInfo.rawKey;
		let maskedToken = raw;
		if (raw.length > 15) {
			maskedToken = `${raw.substring(0, 6)}...${raw.substring(raw.length - 6)}`;
		} else if (raw.length > 4) {
			maskedToken = `${raw.substring(0, 2)}...${raw.substring(raw.length - 2)}`;
		}

		const ut = keyInfo.userToken;
		const maskedUserToken = ut.length > 8 ? `${ut.substring(0, 4)}...${ut.substring(ut.length - 4)}` : ut;

		rowsHtml += `
			<tr>
				<td style="padding: 8px; border: 1px solid #ddd; font-family: monospace;">${maskedToken}</td>
				<td style="padding: 8px; border: 1px solid #ddd; text-align: center;">${keyInfo.keyType}</td>
				<td style="padding: 8px; border: 1px solid #ddd;">${keyInfo.model.replace(/^models\//, '')}</td>
				<td style="padding: 8px; border: 1px solid #ddd; text-align: center;">${keyInfo.totalRequests}</td>
				<td style="padding: 8px; border: 1px solid #ddd; font-family: monospace;">${maskedUserToken}</td>
			</tr>
		`;
	}

	const html = `
		<h1>Zero Success Rate Keys Alert</h1>
		<p>The following keys have been used in the past 7 days, but have a <strong>0% success rate</strong>. They may be invalid, deactivated, or out of quota.</p>
		<table style="width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 15px;">
			<thead>
				<tr style="background-color: #f7f7f7;">
					<th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Key (Masked)</th>
					<th style="padding: 10px; border: 1px solid #ddd; text-align: center;">Type</th>
					<th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Model</th>
					<th style="padding: 10px; border: 1px solid #ddd; text-align: center;">Requests</th>
					<th style="padding: 10px; border: 1px solid #ddd; text-align: left;">User Token (Masked)</th>
				</tr>
			</thead>
			<tbody>
				${rowsHtml}
			</tbody>
		</table>
		<p>Please log in to your admin dashboard to diagnose, reset, or remove these credentials.</p>
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
			console.error(`Failed to send zero success rate alert email: ${response.status} ${error}`);
		}
	} catch (e) {
		console.error('Error sending zero success rate alert email:', e);
	}
}
