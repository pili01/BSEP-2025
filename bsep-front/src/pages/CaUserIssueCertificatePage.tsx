import React, { useState, useEffect } from 'react';
import { useUser } from '../context/UserContext';
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
import { CertificateType, CertificateDto } from '../models/Certificate';
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
    type?: string;
}

export default function CaUserIssueCertificatePage({ showSnackbar }: Props) {
    const { user } = useUser();
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
        organization: user?.organization || '',
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
        loadMyTemplates();
    }, []);

    const loadAvailableCAs = async () => {
        try {
            setCaLoading(true);
            const interCerts = await CertificateService.getIntermidiateCertificatesForUser();
            setAvailableCAs(
                interCerts.map(cert => ({
                    serialNumber: cert.serialNumber || '',
                    subjectName: cert.subjectName || '',
                    type: cert.type
                }))
            );
        } catch (err) {
            showSnackbar('Failed to load available intermediate certificates', 'warning');
        } finally {
            setCaLoading(false);
        }
    };

    const loadMyTemplates = async () => {
        try {
            setTemplatesLoading(true);
            const templates = await TemplateService.getMyTemplates();
            setAvailableTemplates(templates);
        } catch (err) {
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
        if (formData.validityInDays > template.maxValidityDays) {
            issues.push(`Validity period exceeds template maximum: ${template.maxValidityDays} days`);
        }
        if (template.caIssuerSerialNumber && formData.issuerSerialNumber !== template.caIssuerSerialNumber) {
            issues.push(`Certificate must be issued by CA: ${template.caIssuerSerialNumber}`);
        }
        return issues;
    };

    const validateForm = (): boolean => {
        if (!formData.commonName.trim()) {
            setError('Common Name is required.');
            return false;
        }
        if (formData.type !== CertificateType.ROOT && !formData.issuerSerialNumber.trim()) {
            setError('Issuer Serial Number is required.');
            return false;
        }
        if (formData.type !== CertificateType.ROOT && !formData.targetUserEmail.trim()) {
            setError('Target User Email is required.');
            return false;
        }
        if (formData.selectedTemplateId) {
            const template = availableTemplates.find(t => t.id?.toString() === formData.selectedTemplateId);
            if (template) {
                const templateIssues = validateTemplate(template);
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
            organization: formData.organization,
            commonName: formData.commonName,
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
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 2 }}>
            <Paper elevation={3} sx={{ width: 800, p: 4, borderRadius: 2 }}>
                <Typography variant="h4" component="h1" align="center" gutterBottom>
                    <strong>Issue Certificate</strong>
                </Typography>
                <Typography variant="subtitle1" align="center" color="text.secondary" gutterBottom>
                    CA User Certificate Issuance
                </Typography>
                <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    <FormControl fullWidth>
                        <InputLabel>Certificate Type</InputLabel>
                        <Select
                            value={formData.type}
                            label="Certificate Type"
                            onChange={(e) => updateField('type', e.target.value as CertificateType)}
                        >
                            <MenuItem value={CertificateType.INTERMEDIATE}>Intermediate Certificate</MenuItem>
                            <MenuItem value={CertificateType.END_ENTITY}>End Entity Certificate</MenuItem>
                        </Select>
                    </FormControl>

                    <Autocomplete
                        options={availableTemplates}
                        getOptionLabel={(option) => option.templateName}
                        value={selectedTemplate || null}
                        onChange={(_, newValue) => applyTemplate(newValue)}
                        loading={templatesLoading}
                        renderInput={(params) => (
                            <TextField
                                {...params}
                                label="Select Template (Optional)"
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

                    {selectedTemplate && templateValidationIssues.length > 0 && (
                        <Alert severity="warning">
                            <Typography variant="subtitle2">Template Issues:</Typography>
                            {templateValidationIssues.map((issue, i) => (
                                <Typography key={i} variant="body2">• {issue}</Typography>
                            ))}
                        </Alert>
                    )}

                    <TextField
                        label="Common Name"
                        value={formData.commonName}
                        onChange={(e) => updateField('commonName', e.target.value)}
                        required
                        fullWidth
                    />

                    {formData.type !== CertificateType.ROOT && (
                        <TextField
                            label="Target User Email"
                            type="email"
                            value={formData.targetUserEmail}
                            onChange={(e) => updateField('targetUserEmail', e.target.value)}
                            required
                            fullWidth
                        />
                    )}

                    <TextField
                        label="Subject Alternative Names"
                        value={formData.subjectAlternativeNames}
                        onChange={(e) => updateField('subjectAlternativeNames', e.target.value)}
                        fullWidth
                        multiline
                        rows={2}
                        helperText="Comma-separated values"
                    />

                    <Divider />

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <TextField
                            label="Validity (Days)"
                            type="number"
                            value={formData.validityInDays}
                            onChange={(e) => updateField('validityInDays', Number(e.target.value))}
                            required
                            sx={{ flex: 1 }}
                        />

                        <FormControl sx={{ flex: 2 }} required>
                            <InputLabel>Issuer Certificate</InputLabel>
                            <Select
                                value={formData.issuerSerialNumber}
                                onChange={(e) => updateField('issuerSerialNumber', e.target.value)}
                            >
                                {caLoading ? (
                                    <MenuItem disabled>
                                        <CircularProgress size={20} /> Loading...
                                    </MenuItem>
                                ) : (
                                    availableCAs.map((ca, index) => (
                                        <MenuItem key={index} value={ca.serialNumber}>
                                            {ca.subjectName} ({ca.serialNumber})
                                        </MenuItem>
                                    ))
                                )}
                            </Select>
                        </FormControl>
                    </Box>

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <TextField
                            label="Key Usage"
                            value={formData.keyUsage}
                            onChange={(e) => updateField('keyUsage', e.target.value)}
                            required
                            sx={{ flex: 1 }}
                        />
                        <TextField
                            label="Extended Key Usage"
                            value={formData.extendedKeyUsage}
                            onChange={(e) => updateField('extendedKeyUsage', e.target.value)}
                            required
                            sx={{ flex: 1 }}
                        />
                    </Box>

                    {error && <Alert severity="error">{error}</Alert>}

                    <Button type="submit" variant="contained" fullWidth disabled={loading || (selectedTemplate && templateValidationIssues.length > 0)}>
                        {loading ? <CircularProgress size={24} /> : 'Issue Certificate'}
                    </Button>
                </Box>
            </Paper>
        </Box>
    );
}
