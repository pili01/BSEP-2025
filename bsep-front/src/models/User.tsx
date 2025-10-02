export interface RegistrationData {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    organization: string;
}

export interface User {
    id?: number;
    email: string;
    firstName: string;
    lastName: string;
    organization: string;
    twoFactorEnabled?: boolean;
    role: UserRole;
    publicKey: string;
    token?: string; // JWT token
    isInitialPassword: boolean;
}

export enum UserRole {
    CA_USER = 'CA_USER',
    REGULAR_USER = 'REGULAR_USER',
    ADMIN = 'ADMIN'
}