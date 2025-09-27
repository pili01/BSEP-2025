export interface UserSession {
    id?: number;
    jti: string;
    ipAddress?: string;
    device?: string;
    lastActivity?: string; 
    createdAt: string; 
}
