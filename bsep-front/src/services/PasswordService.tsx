import { StoredPassword } from "../models/StoredPassword";

const API_URL = import.meta.env.VITE_API_URL || '';
const serviceUrl = `${API_URL}/passwords`;

class PasswordService {

	static async addPassword(passwordData: StoredPassword): Promise<any> {
		const jwt = localStorage.getItem('jwt');
		if (!jwt) throw new Error('No JWT token found');

		const response = await fetch(`${serviceUrl}/add`, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${jwt}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(passwordData),
		});
		return await this.handleResponse(response, 'Failed to add password');
	}

	static async getPasswords(): Promise<any> {
		const jwt = localStorage.getItem('jwt');
		if (!jwt) throw new Error('No JWT token found');

		const response = await fetch(`${serviceUrl}/get`, {
			method: 'GET',
			headers: {
				'Authorization': `Bearer ${jwt}`,
				'Content-Type': 'application/json',
			},
		});
		return await this.handleResponse(response, 'Failed to get passwords');
	}

	static async savePublicKey(publicKey: string): Promise<any> {
		const jwt = localStorage.getItem('jwt');
		if (!jwt) throw new Error('No JWT token found');

		const response = await fetch(`${API_URL}/auth/savePublicKey`, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${jwt}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ publicKey }),
		});
		return await this.handleResponse(response, 'Failed to save public key');
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

	static async generateUserKeyPair(): Promise<any> {
		const keyPair = await window.crypto.subtle.generateKey(
			{
				name: "RSA-OAEP",
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256",
			},
			true,
			["encrypt", "decrypt"]
		);
		return keyPair;
	}

	static async encryptWithPublicKey(base64Key: string, data: string): Promise<string> {
		// Uvoz javnog ključa iz base64 formata
		const publicKey = await window.crypto.subtle.importKey(
			"spki",
			this.base64ToArrayBuffer(base64Key),
			{
				name: "RSA-OAEP",
				hash: "SHA-256",
			},
			true,
			["encrypt"]
		);

		// enkodiranje podataka u ArrayBuffer iz stringa
		const encoder = new TextEncoder();
		const encodedData = encoder.encode(data);
		const encryptedData = await window.crypto.subtle.encrypt(
			{
				name: "RSA-OAEP"
			},
			publicKey,
			encodedData
		);
		return this.arrayBufferToBase64(encryptedData); // vraćamo kao base64 string
	}

	static async decryptWithPrivateKey(privateKey: CryptoKey, data: string): Promise<string> {
		const decryptedData = await window.crypto.subtle.decrypt(
			{
				name: "RSA-OAEP"
			},
			privateKey,
			this.base64ToArrayBuffer(data)
		);
		const decoder = new TextDecoder();
		return decoder.decode(decryptedData);
	}

	// Pomoćne funkcije za konverziju između ArrayBuffer i Base64 stringova za lakše skladištenje i prenos
	static arrayBufferToBase64(buffer: ArrayBuffer) {
		return btoa(String.fromCharCode(...new Uint8Array(buffer)));
	}

	static base64ToArrayBuffer(base64: string) {
		const publicKeyBuffer = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
		return publicKeyBuffer.buffer;
	}

	// Generisanje para ključeva i vraćanje javnog ključa kao base64 string
	static async generateAndReturnPublicKey(passwordForLockFile: string): Promise<string> {
		const keyPair = await this.generateUserKeyPair();
		const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
		const base64PublicKey = this.arrayBufferToBase64(publicKey);
		this.savePrivateKeyEncrypted(keyPair.privateKey, passwordForLockFile, "private-key.enc");
		return base64PublicKey;
	}


	// Dekripcija podataka pomoću privatnog ključa iz fajla
	static async decryptWithPrivateKeyFile(file: File, encryptedBase64: string, decryptionPassword: string): Promise<string> {
		const privateKey = await PasswordService.importEncryptedPrivateKeyFromFile(file, decryptionPassword);
		return await PasswordService.decryptWithPrivateKey(privateKey, encryptedBase64);
	}

	// Šifrovanje privatnog ključa lozinkom i preuzimanje kao fajl
	static async savePrivateKeyEncrypted(privateKey: CryptoKey, password: string, fileName: string = "private-key.enc") {
		// Izvoz privatnog ključa u PKCS8 (ArrayBuffer)
		const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
		// Derivacija AES ključa iz lozinke
		const enc = new TextEncoder();
		const salt = window.crypto.getRandomValues(new Uint8Array(16));
		const iv = window.crypto.getRandomValues(new Uint8Array(12));
		const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
		const aesKey = await window.crypto.subtle.deriveKey(
			{
				name: "PBKDF2",
				salt,
				iterations: 100000,
				hash: "SHA-256"
			},
			keyMaterial,
			{ name: "AES-GCM", length: 256 },
			true,
			["encrypt"]
		);
		// Šifrovanje privatnog ključa
		const encrypted = await window.crypto.subtle.encrypt(
			{ name: "AES-GCM", iv },
			aesKey,
			pkcs8
		);
		// Priprema podataka za fajl (salt, iv, encrypted)
		const blob = new Blob([
			salt,
			iv,
			new Uint8Array(encrypted)
		]);
		// Preuzimanje fajla
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = fileName;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}

	// Učitavanje privatnog ključa iz šifrovanog fajla (PBKDF2 + AES-GCM)
	static async importEncryptedPrivateKeyFromFile(file: File, password: string): Promise<CryptoKey> {
		return new Promise((resolve, reject) => {
			const reader = new FileReader();
			reader.onload = async (e) => {
				try {
					const buffer = new Uint8Array(e.target?.result as ArrayBuffer);
					// Prvih 16 bajtova je salt, sledećih 12 bajtova je iv, ostatak je šifrovani ključ
					const salt = buffer.slice(0, 16);
					const iv = buffer.slice(16, 28);
					const encrypted = buffer.slice(28);
					const enc = new TextEncoder();
					const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
					const aesKey = await window.crypto.subtle.deriveKey(
						{
							name: "PBKDF2",
							salt,
							iterations: 100000,
							hash: "SHA-256"
						},
						keyMaterial,
						{ name: "AES-GCM", length: 256 },
						true,
						["decrypt"]
					);
					const pkcs8 = await window.crypto.subtle.decrypt(
						{ name: "AES-GCM", iv },
						aesKey,
						encrypted
					);
					const privateKey = await window.crypto.subtle.importKey(
						"pkcs8",
						pkcs8,
						{
							name: "RSA-OAEP",
							hash: "SHA-256",
						},
						true,
						["decrypt"]
					);
					resolve(privateKey);
				} catch (err) {
					reject(err);
				}
			};
			reader.onerror = reject;
			reader.readAsArrayBuffer(file);
		});
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

export default PasswordService;
