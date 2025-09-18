const API_URL = import.meta.env.VITE_API_URL || '';
import { RegistrationData } from '../models/User';

class AuthService {
	static async register(user: RegistrationData) {
		const response = await fetch(`${API_URL}/auth/register`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(user),
		});
		return await this.handleResponse(response, 'Registration failed');
	}

	static async login(email: string, password: string, recaptchaToken: string): Promise<any> {
		const response = await fetch(`${API_URL}/auth/login`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ email, password, recaptchaToken }),
		});
		return await this.handleResponse(response, 'Login failed');
	}

	static async verify2fa(email: string, password: string, code2fa: string, disable2fa: boolean): Promise<any> {
		const response = await fetch(`${API_URL}/auth/login-with-2fa`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ email, password, code2fa, disable2fa }),
		});
		return await this.handleResponse(response, '2FA verification failed');
	}

	static async verifyEmail(token: string | null) {
		const response = await fetch(`${API_URL}/auth/verify?token=${token}`, {
			method: 'GET',
		});
		return await this.handleResponse(response, 'Email verification failed');
	}

	static async enable2fa() {
		const jwt = localStorage.getItem('jwt');
		if (!jwt) return null;

		const response = await fetch(`${API_URL}/auth/enable-2fa`, {
			method: 'GET',
			headers: {
				'Authorization': `Bearer ${jwt}`,
				'Content-Type': 'application/json',
			},
		});
		return await this.handleResponse(response, 'Failed to enable 2fa');
	}

	static async verifyEnable2fa(code: number) {
		const jwt = localStorage.getItem('jwt');
		if (!jwt) return null;

		const response = await fetch(`${API_URL}/auth/verify-2fa`, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${jwt}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ code2fa: code }),
		});
		return await this.handleResponse(response, 'Failed to verify 2fa code');
	}

	static logout() {
		localStorage.removeItem('jwt');
	}

	static async handleResponse(response: Response, defaultErrorMessage: string) {
		if (response.status < 200 || response.status >= 300) {
			const errorText = await response.text();
			let error;
			try {
				error = JSON.parse(errorText);
			} catch {
				error = { message: errorText };
			}
			const statusMessage = this.createErrorOfStatusCode(response.status);
			console.log(statusMessage);
			throw new Error(`${statusMessage}: ${error.message || defaultErrorMessage}`);
		}
		const text = await response.text();
		if (!text) return null;
		try {
			return JSON.parse(text);
		} catch {
			return text;
		}
	}

	static createErrorOfStatusCode(status: number) {
		switch (status) {
			case 400:
				return 'Bad Request';
			case 401:
				return 'Unauthorized';
			case 403:
				return 'Forbidden';
			case 404:
				return 'Not Found';
			case 500:
				return 'Internal Server Error';
			default:
				return 'An error occurred';
		}
	}
}

export default AuthService;
