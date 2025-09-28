export enum CertificateType {
    ROOT = 'ROOT',
    INTERMEDIATE = 'INTERMEDIATE',
    END_ENTITY = 'END_ENTITY'
}

export enum RevokedReason {
    UNSPECIFIED = 'UNSPECIFIED',
    KEY_COMPROMISE = 'KEY_COMPROMISE',
    CA_COMPROMISE = 'CA_COMPROMISE',
    AFFILIATION_CHANGED = 'AFFILIATION_CHANGED',
    SUPERSEDED = 'SUPERSEDED',
    CESSATION_OF_OPERATION = 'CESSATION_OF_OPERATION',
    CERTIFICATE_HOLD = 'CERTIFICATE_HOLD',
    REMOVE_FROM_CRL = 'REMOVE_FROM_CRL',
    PRIVILEGE_WITHDRAWN = 'PRIVILEGE_WITHDRAWN',
    AA_COMPROMISE = 'AA_COMPROMISE'
}

export interface Certificate {
    serialNumber: string;
    subjectName: string;
		targetUserEmail?: string; 
    issuerName: string;
    startDate: string; 
    endDate: string;   
    isRevoked: boolean;
    revokedReason?: RevokedReason;
    revokedAt?: string; 
    type: CertificateType;
    organization: string;
    keystorePath?: string;
    commonName?: string;
    keyUsage?: string;
    extendedKeyUsage?: string;
    sansRegex?: string;
    issuerSerialNumber?: string;
    keystorePassword?: string;
}

export interface CertificateDto {
    targetUserEmail?: string; 
    commonName: string; 
    organization: string;
    templateId?: number; 
    validityInDays: number;
    type: CertificateType;
    issuerSerialNumber?: string;
    keyUsage: string[]; 
    extendedKeyUsage: string[];
}

