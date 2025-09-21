export interface StoredPassword {
    id?: string;
    username: string;
    siteName: string;
    ownerId?: number;
    shares: PasswordShare[];
}

export interface PasswordShare {
    userId?: number;
    encryptedPassword: string;
}
