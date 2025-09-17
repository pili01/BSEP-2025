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
}

export default AuthService;
