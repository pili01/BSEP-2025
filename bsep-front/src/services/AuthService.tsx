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
		if (response.status < 200 || response.status >= 300) {
			const error = await response.text();
			throw new Error(error || 'Registration failed');
		}
		return;
	}

	static async login(email: string, password: string, recaptchaToken: string): Promise<any> {
		const response = await fetch(`${API_URL}/auth/login`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ email, password, recaptchaToken }),
		});
		if (response.status < 200 || response.status >= 300) {
			const error = await response.json();
			throw new Error(error.message || 'Login failed');
		}
		return await response.json();
	}

	static async verify2fa(email: string, password: string, code2fa: string, disable2fa: boolean): Promise<any> {
		const response = await fetch(`${API_URL}/auth/login-with-2fa`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ email, password, code2fa, disable2fa }),
		});
		if (response.status < 200 || response.status >= 300) {
			const error = await response.json();
			throw new Error(error.message || 'Login failed');
		}
		return await response.json();
	}

	static async verifyEmail(token: string | null) {
		const response = await fetch(`${API_URL}/auth/verify?token=${token}`, {
			method: 'GET',
		});
		if (response.status < 200 || response.status >= 300) {
			const error = await response.text();
			throw new Error(error || 'Email verification failed');
		}
		return;
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
		if (response.status < 200 || response.status >= 300) {
			const error = await response.json();
			throw new Error(error.message || 'Failed to fetch current user');
		}
		return await response.json();
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
			body: JSON.stringify({ code2fa:code }),
		});
		if (response.status < 200 || response.status >= 300) {
			const error = await response.json();
			throw new Error(error.message || 'Failed to fetch current user');
		}
		return await response.json();
	}

	static logout() {
		localStorage.removeItem('jwt');
	}
}

export default AuthService;
