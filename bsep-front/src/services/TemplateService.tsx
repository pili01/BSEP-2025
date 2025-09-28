import { CertificateTemplate, CertificateTemplateDto } from '../models/CertificateTemplate'; 

const API_URL = import.meta.env.VITE_API_URL || '';

class TemplateService {

    static async createTemplate(templateData: CertificateTemplateDto): Promise<CertificateTemplate> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('No JWT token found.');

        const response = await fetch(`${API_URL}/certificate-templates/create`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(templateData),
        });

        return await this.handleResponse(response, 'Failed to create template.');
    }

    static async getAllTemplates(): Promise<CertificateTemplate[]> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('Nema JWT tokena. Korisnik nije autorizovan.');

        const response = await fetch(`${API_URL}/certificate-templates/all`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
        });

        return await this.handleResponse(response, 'Failed to get all templates.');
    }

    static async getTemplateById(id: number): Promise<CertificateTemplate> {
        const jwt = localStorage.getItem('jwt');
        if (!jwt) throw new Error('Nema JWT tokena. Korisnik nije autorizovan.');

        const response = await fetch(`${API_URL}/certificate-templates/${id}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Content-Type': 'application/json',
            },
        });

        return await this.handleResponse(response, `Failed to get template with id ${id}.`);
    }

		static async getMyTemplates(): Promise<CertificateTemplateDto[]> {
				const jwt = localStorage.getItem('jwt');
				if (!jwt) throw new Error('No JWT token found');

				const response = await fetch(`${API_URL}/api/certificate-templates/my-templates`, {
						method: 'GET',
						headers: {
								'Authorization': `Bearer ${jwt}`,
								'Content-Type': 'application/json',
						},
				});

				return await this.handleResponse(response, 'Failed to get user templates');
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

export default TemplateService;