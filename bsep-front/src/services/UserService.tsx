import { StoredPassword } from "../models/StoredPassword";

const API_URL = import.meta.env.VITE_API_URL || '';

class UserService {

	static async getAllUsers(): Promise<any> {
		const jwt = localStorage.getItem('jwt');
		if (!jwt) throw new Error('No JWT token found');

		const response = await fetch(`${API_URL}/auth/allRegularUsers`, {
			method: 'GET',
			headers: {
				'Authorization': `Bearer ${jwt}`,
				'Content-Type': 'application/json',
			},
		});
		return await this.handleResponse(response, 'Failed to get users');
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

export default UserService;
