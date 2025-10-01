import { Certificate, CertificateDto } from '../models/Certificate';

const API_URL = import.meta.env.VITE_API_URL || '';

class CertificateService {

    // Issue certificate
    static async issueCertificate(requestDto: CertificateDto): Promise<string> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('No JWT token found');

        const response = await fetch(`${API_URL}/certificates/issue`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestDto)
        });

        return await this.handleResponse(response, 'Failed to issue certificate');
    }

    static async getAllCertificates(): Promise<Certificate[]> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('No JWT token found');

        const response = await fetch(`${API_URL}/certificates/admin/all`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
        });

        return await this.handleResponse(response, 'Failed to get all certificates');
    }

		static async getIntermidiateCertificatesForUser(): Promise<Certificate[]> {
				const jwt = localStorage.getItem('jwt');
				if (!jwt) throw new Error('No JWT token found');

				const response = await fetch(`${API_URL}/certificates/intermediate/organization`, {
						method: 'GET',
						headers: {
								'Authorization': `Bearer ${jwt}`,
								'Content-Type': 'application/json',
						},
				});

				return await this.handleResponse(response, 'Failed to get intermediate certificates for user');
		}

    static async getCertificateChain(): Promise<Certificate[]> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('No JWT token found');

        const response = await fetch(`${API_URL}/certificates/ca/chain`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
        });

        return await this.handleResponse(response, 'Failed to get certificate chain');
    }

    static async getCaUserCertificates(): Promise<Certificate[]> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('No JWT token found');

        const response = await fetch(`${API_URL}/certificates/ca-user/my`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
        });

        return await this.handleResponse(response, 'Failed to get user certificates');
    }

    static async getAvailableCaCertificates(): Promise<Array<{[key: string]: string}>> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('No JWT token found');

        const response = await fetch(`${API_URL}/certificates/ca/list`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
        });

        return await this.handleResponse(response, 'Failed to get available CA certificates');
    }

    static async getIntermediateCertificatesByOrganization(): Promise<Certificate[]> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('No JWT token found');

        const response = await fetch(`${API_URL}/certificates/intermediate/organization`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
        });

        return await this.handleResponse(response, 'Failed to get intermediate certificates');
    }

    private static async handleResponse(response: Response, defaultErrorMessage: string) {
        if (response.status < 200 || response.status >= 300) {
            const errorText = await response.text();
            let error;
            try {
                error = JSON.parse(errorText);
            } catch {
                error = { message: errorText };
            }
            const statusMessage = this.createErrorOfStatusCode(response.status);
            console.error(statusMessage);
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

    private static createErrorOfStatusCode(status: number) {
        switch (status) {
            case 400: return 'Bad Request';
            case 401: return 'Unauthorized';
            case 403: return 'Forbidden';
            case 404: return 'Not Found';
            case 500: return 'Internal Server Error';
            default: return 'An error occurred';
        }
    }
}

export default CertificateService;