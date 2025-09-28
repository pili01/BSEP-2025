export interface CertificateTemplate {
    id?: number; 
    templateName: string;
    caIssuerSerialNumber: string | null;
    commonNameRegex: string | null;
    sansRegex: string | null;
    maxValidityDays: number;
    keyUsage: string | null;
    extendedKeyUsage: string | null;
}

export interface CertificateTemplateDto {
    templateName: string;
    caIssuerSerialNumber: string | null;
    commonNameRegex: string | null;
    sansRegex: string | null;
    maxValidityDays: number;
    keyUsage: string | null;
    extendedKeyUsage: string | null;
}