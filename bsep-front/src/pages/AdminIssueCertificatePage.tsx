import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Paper,
    Typography,
    TextField,
    Button,
    Box,
    FormControl,
    InputLabel,
    Select,
    MenuItem,
    CircularProgress,
    Divider,
    Autocomplete,
    Alert,
    Chip
} from '@mui/material';
import { Certificate, CertificateType, CertificateDto } from '../models/Certificate';
import { CertificateTemplate } from '../models/CertificateTemplate';
import CertificateService from '../services/CertificateService';
import TemplateService from '../services/TemplateService';

interface Props {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
}

interface CertificateFormData {
    type: CertificateType;
    targetUserEmail: string;
    organization: string;
    commonName: string;
    keyUsage: string;
    extendedKeyUsage: string;
    validityInDays: number;
    issuerSerialNumber: string;
    subjectAlternativeNames: string;
    selectedTemplateId?: string;
}

interface CaOption {
    serialNumber: string;
    subjectName: string;
    revoked: boolean;
    type?: string;
}

export default function AdminIssueCertificatePage({ showSnackbar }: Props) {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [templatesLoading, setTemplatesLoading] = useState(false);
    const [caLoading, setCaLoading] = useState(false);
    const [error, setError] = useState('');

    const [availableTemplates, setAvailableTemplates] = useState<CertificateTemplate[]>([]);
    const [availableCAs, setAvailableCAs] = useState<CaOption[]>([]);

    const [formData, setFormData] = useState<CertificateFormData>({
        type: CertificateType.END_ENTITY,
        targetUserEmail: '',
        organization: '',
        commonName: '',
        keyUsage: 'DigitalSignature,KeyEncipherment',
        extendedKeyUsage: 'ServerAuth',
        validityInDays: 365,
        issuerSerialNumber: '',
        subjectAlternativeNames: '',
        selectedTemplateId: ''
    });

    useEffect(() => {
        loadAvailableCAs();
        loadAllTemplates();
    }, []);

    const loadAvailableCAs = async () => {
        try {
            setCaLoading(true);
            const [caList, intermediateList] = await Promise.all([
                CertificateService.getAvailableCaCertificates(),
                CertificateService.getCertificateChain()
            ]);

            const combinedCAs: CaOption[] = [
                ...caList.map(ca => ({
                    serialNumber: ca.serialNumber || '',
                    subjectName: ca.subjectName || '',
                    revoked: typeof ca.revoked === 'string' ? ca.revoked === 'true' : !!ca.revoked,
                    type: 'CA'
                })),
                ...intermediateList
                    .filter(cert => cert.type === CertificateType.ROOT || cert.type === CertificateType.INTERMEDIATE)
                    .map(cert => ({
                        serialNumber: cert.serialNumber,
                        subjectName: cert.subjectName,
                        revoked: cert.revoked || false,
                        type: cert.type
                    }))
            ];

            const uniqueCAs = combinedCAs.filter((ca, index, self) =>
                index === self.findIndex(c => c.serialNumber === ca.serialNumber)
            );
            const filtered = uniqueCAs.filter(ca => !ca.revoked);
            setAvailableCAs(filtered);
        } catch (err) {
            console.error('Failed to load CAs:', err);
            showSnackbar('Failed to load available Certificate Authorities', 'warning');
        } finally {
            setCaLoading(false);
        }
    };

    const loadAllTemplates = async () => {
        try {
            setTemplatesLoading(true);
            const templates = await TemplateService.getAllTemplates();
            setAvailableTemplates(templates);
        } catch (err) {
            console.error('Failed to load templates:', err);
            showSnackbar('Failed to load templates', 'warning');
        } finally {
            setTemplatesLoading(false);
        }
    };

    const updateField = (field: keyof CertificateFormData, value: string | CertificateType | number) => {
        setFormData(prev => ({ ...prev, [field]: value }));
        setError('');
    };

    const applyTemplate = (template: CertificateTemplate | null) => {
        if (template) {
            setFormData(prev => ({
                ...prev,
                keyUsage: template.keyUsage || prev.keyUsage,
                extendedKeyUsage: template.extendedKeyUsage || prev.extendedKeyUsage,
                validityInDays: template.maxValidityDays || prev.validityInDays,
                issuerSerialNumber: template.caIssuerSerialNumber || prev.issuerSerialNumber,
                selectedTemplateId: template.id?.toString() || ''
            }));
        } else {
            setFormData(prev => ({ ...prev, selectedTemplateId: '' }));
        }
    };

    const validateTemplate = (template: CertificateTemplate): string[] => {
        const issues: string[] = [];

        if (template.commonNameRegex && formData.commonName) {
            const regex = new RegExp(template.commonNameRegex);
            if (!regex.test(formData.commonName)) {
                issues.push(`Common Name does not match template pattern: ${template.commonNameRegex}`);
            }
        }

        if (template.sansRegex && formData.subjectAlternativeNames) {
            const regex = new RegExp(template.sansRegex);
            const sanEntries = formData.subjectAlternativeNames.split(',').map(s => s.trim());
            const invalidSans = sanEntries.filter(san => !regex.test(san));
            if (invalidSans.length > 0) {
                issues.push(`Subject Alternative Names do not match template pattern: ${template.sansRegex}`);
            }
        }

        // Validate validity period
        if (formData.validityInDays > template.maxValidityDays) {
            issues.push(`Validity period exceeds template maximum: ${template.maxValidityDays} days`);
        }

        // Validate issuer
        if (template.caIssuerSerialNumber && formData.issuerSerialNumber !== template.caIssuerSerialNumber) {
            issues.push(`Certificate must be issued by specified CA: ${template.caIssuerSerialNumber}`);
        }

        return issues;
    };

    const validateForm = (): boolean => {
        if (!formData.commonName.trim()) {
            setError('Common Name is required.');
            return false;
        }
        if (!formData.organization.trim()) {
            setError('Organization is required.');
            return false;
        }
        if (formData.type !== CertificateType.ROOT && !formData.issuerSerialNumber.trim()) {
            setError('Issuer Serial Number is required for non-ROOT certificates.');
            return false;
        }
        if (formData.type !== CertificateType.ROOT && !formData.targetUserEmail.trim()) {
            setError('Target User Email is required for non-ROOT certificates.');
            return false;
        }
        if (formData.validityInDays < 1 || formData.validityInDays > 3650) {
            setError('Validity must be between 1 and 3650 days.');
            return false;
        }
        if (!formData.keyUsage.trim()) {
            setError('Key Usage is required.');
            return false;
        }
        if (!formData.extendedKeyUsage.trim()) {
            setError('Extended Key Usage is required.');
            return false;
        }

        if (formData.selectedTemplateId) {
            const selectedTemplate = availableTemplates.find(t => t.id?.toString() === formData.selectedTemplateId);
            if (selectedTemplate) {
                const templateIssues = validateTemplate(selectedTemplate);
                if (templateIssues.length > 0) {
                    setError(`Template validation failed: ${templateIssues.join('; ')}`);
                    return false;
                }
            }
        }

        return true;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) return;

        const keyUsageArray = formData.keyUsage.split(',').map(s => s.trim()).filter(s => s.length > 0);
        const extendedKeyUsageArray = formData.extendedKeyUsage.split(',').map(s => s.trim()).filter(s => s.length > 0);

        const certificateRequest: CertificateDto = {
            type: formData.type,
            targetUserEmail: formData.targetUserEmail,
            commonName: formData.commonName,
            organization: formData.organization,
            keyUsage: keyUsageArray,
            extendedKeyUsage: extendedKeyUsageArray,
            issuerSerialNumber: formData.type === CertificateType.ROOT ? undefined : formData.issuerSerialNumber,
            validityInDays: formData.validityInDays
        };

        try {
            setLoading(true);
            await CertificateService.issueCertificate(certificateRequest);
            showSnackbar('Certificate successfully issued!', 'success');
            navigate('/');
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Unknown error during certificate issuance.';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

    const selectedTemplate = availableTemplates.find(t => t.id?.toString() === formData.selectedTemplateId);
    const templateValidationIssues = selectedTemplate ? validateTemplate(selectedTemplate) : [];

    return (
        <Box
            component="main"
            sx={{
                minHeight: '100vh',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                p: 2
            }}
        >
            <Paper elevation={3} sx={{ width: 800, p: 4, borderRadius: 2 }}>
                <Typography variant="h4" component="h1" align="center" gutterBottom>
                    <strong>Issue Certificate</strong>
                </Typography>
                <Typography variant="subtitle1" align="center" color="text.secondary" gutterBottom>
                    Administrator Certificate Issuance
                </Typography>

                <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {/* Certificate Type */}
                    <FormControl fullWidth>
                        <InputLabel>Certificate Type</InputLabel>
                        <Select
                            value={formData.type}
                            label="Certificate Type"
                            onChange={(e) => updateField('type', e.target.value as CertificateType)}
                        >
                            <MenuItem value={CertificateType.ROOT}>
                                <Box>
                                    <Typography variant="body2">Root Certificate</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                        Self-signed root authority certificate
                                    </Typography>
                                </Box>
                            </MenuItem>
                            <MenuItem value={CertificateType.INTERMEDIATE}>
                                <Box>
                                    <Typography variant="body2">Intermediate Certificate</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                        CA certificate signed by root or another intermediate
                                    </Typography>
                                </Box>
                            </MenuItem>
                            <MenuItem value={CertificateType.END_ENTITY}>
                                <Box>
                                    <Typography variant="body2">End Entity Certificate</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                        User/device certificate for applications
                                    </Typography>
                                </Box>
                            </MenuItem>
                        </Select>
                    </FormControl>

                    {/* Template Selection */}
                    <FormControl fullWidth>
                        <Autocomplete
                            options={availableTemplates}
                            getOptionLabel={(option) => `${option.templateName} (Max: ${option.maxValidityDays}d)`}
                            value={selectedTemplate || null}
                            onChange={(_, newValue) => applyTemplate(newValue)}
                            loading={templatesLoading}
                            renderOption={(props, option) => (
                                <Box component="li" {...props}>
                                    <Box>
                                        <Typography variant="body2">{option.templateName}</Typography>
                                        <Typography variant="caption" color="text.secondary">
                                            Max validity: {option.maxValidityDays} days |
                                            Key Usage: {option.keyUsage} |
                                            Extended: {option.extendedKeyUsage}
                                        </Typography>
                                    </Box>
                                </Box>
                            )}
                            renderInput={(params) => (
                                <TextField
                                    {...params}
                                    label="Select Template (Optional)"
                                    helperText="Choose a template to auto-fill and validate certificate parameters"
                                    InputProps={{
                                        ...params.InputProps,
                                        endAdornment: (
                                            <>
                                                {templatesLoading && <CircularProgress size={20} />}
                                                {params.InputProps.endAdornment}
                                            </>
                                        ),
                                    }}
                                />
                            )}
                        />
                    </FormControl>

                    {selectedTemplate && templateValidationIssues.length > 0 && (
                        <Alert severity="warning">
                            <Typography variant="subtitle2">Template Validation Issues:</Typography>
                            {templateValidationIssues.map((issue, index) => (
                                <Typography key={index} variant="body2">• {issue}</Typography>
                            ))}
                        </Alert>
                    )}

                    <Divider />

                    {/* Basic Certificate Information */}
                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <TextField
                            label="Common Name"
                            value={formData.commonName}
                            onChange={(e) => updateField('commonName', e.target.value)}
                            required
                            sx={{ flex: 2 }}
                            helperText="e.g., www.example.com, John Doe, or CA Name"
                        />

                        <TextField
                            label="Organization"
                            value={formData.organization}
                            onChange={(e) => updateField('organization', e.target.value)}
                            required
                            sx={{ flex: 1 }}
                        />
                    </Box>

                    {formData.type !== CertificateType.ROOT && (
                        <TextField
                            label="Target User Email"
                            type="email"
                            value={formData.targetUserEmail}
                            onChange={(e) => updateField('targetUserEmail', e.target.value)}
                            required
                            fullWidth
                            helperText="Email of the user who will receive this certificate"
                        />
                    )}

                    <TextField
                        label="Subject Alternative Names"
                        value={formData.subjectAlternativeNames}
                        onChange={(e) => updateField('subjectAlternativeNames', e.target.value)}
                        fullWidth
                        multiline
                        rows={2}
                        helperText="Comma-separated: DNS:*.example.com, IP:192.168.1.1, email:user@example.com"
                    />

                    <Divider />

                    {/* Certificate Parameters */}
                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <TextField
                            label="Validity (Days)"
                            type="number"
                            value={formData.validityInDays}
                            onChange={(e) => updateField('validityInDays', Number(e.target.value))}
                            required
                            sx={{ flex: 1 }}
                            InputProps={{ inputProps: { min: 1, max: 3650 } }}
                        />

                        {formData.type !== CertificateType.ROOT && (
                            <FormControl sx={{ flex: 2 }} required>
                                <InputLabel>Issuer Certificate</InputLabel>
                                <Select
                                    value={formData.issuerSerialNumber}
                                    label="Issuer Certificate"
                                    onChange={(e) => updateField('issuerSerialNumber', e.target.value)}
                                >
                                    {caLoading ? (
                                        <MenuItem disabled>
                                            <CircularProgress size={20} /> Loading...
                                        </MenuItem>
                                    ) : (
                                        availableCAs.map((ca, index) => (
                                            <MenuItem key={index} value={ca.serialNumber}>
                                                <Box>
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Typography variant="body2">
                                                            {ca.subjectName}
                                                        </Typography>
                                                        {ca.type && (
                                                            <Chip
                                                                label={ca.type}
                                                                size="small"
                                                                variant="outlined"
                                                                color={ca.type === 'ROOT' ? 'error' : 'primary'}
                                                            />
                                                        )}
                                                    </Box>
                                                    <Typography variant="caption" color="text.secondary">
                                                        Serial: {ca.serialNumber}
                                                    </Typography>
                                                </Box>
                                            </MenuItem>
                                        ))
                                    )}
                                </Select>
                            </FormControl>
                        )}
                    </Box>

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <TextField
                            label="Key Usage"
                            value={formData.keyUsage}
                            onChange={(e) => updateField('keyUsage', e.target.value)}
                            required
                            sx={{ flex: 1 }}
                            helperText="e.g., DigitalSignature,KeyEncipherment"
                        />

                        <TextField
                            label="Extended Key Usage"
                            value={formData.extendedKeyUsage}
                            onChange={(e) => updateField('extendedKeyUsage', e.target.value)}
                            required
                            sx={{ flex: 1 }}
                            helperText="e.g., ServerAuth,ClientAuth"
                        />
                    </Box>

                    {selectedTemplate && templateValidationIssues.length === 0 && (
                        <Alert severity="success">
                            <Typography variant="subtitle2">
                                Template Applied: {selectedTemplate.templateName}
                            </Typography>
                            <Typography variant="body2">
                                All template requirements are satisfied
                            </Typography>
                        </Alert>
                    )}

                    {error && (
                        <Alert severity="error">
                            {error}
                        </Alert>
                    )}

                    <Button
                        type="submit"
                        variant="contained"
                        fullWidth
                        disabled={loading || (selectedTemplate && templateValidationIssues.length > 0)}
                        sx={{ mt: 2, py: 1.5 }}
                    >
                        {loading ? <CircularProgress size={24} /> : 'Issue Certificate'}
                    </Button>
                </Box>
            </Paper>
        </Box>
    );
}