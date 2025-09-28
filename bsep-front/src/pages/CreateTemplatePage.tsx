import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Paper,
    Typography,
    TextField,
    Button,
    Box,
    Checkbox,
    FormControlLabel,
    FormGroup,
    FormLabel,
    MenuItem,
    Select,
    FormControl,
    InputLabel,
    CircularProgress,
    Divider
} from '@mui/material';
import { CertificateTemplateDto } from '../models/CertificateTemplate';
import TemplateService from '../services/TemplateService';

const keyUsageOptions = [
    'DigitalSignature',
    'NonRepudiation', 
    'KeyEncipherment',
    'DataEncipherment',
    'KeyAgreement',
    'KeyCertSign',
    'CRLSign'
];

const extendedKeyUsageOptions = [
    'ServerAuth',
    'ClientAuth',
    'CodeSigning',
    'EmailProtection',
    'TimeStamping',
    'OCSPSigning'
];

const commonNamePatterns = [
    { value: '.*', label: 'Any value (.*)' },
    { value: '^[A-Z].*', label: 'Starts with Uppercase letter (^[A-Z].*)' },
    { value: '^[a-z].*', label: 'Starts with Lowercase letter (^[a-z].*)' },
    { value: '^[a-zA-Z0-9.-]+$', label: 'Alphanumeric and dots/dashes only (^[a-zA-Z0-9.-]+$)' },
    { value: '^(?!.*[^.]{64})[a-zA-Z0-9.-]{1,63}$', label: 'Standard DNS Label Format (Max 63 chars)' }
];

const sanPatterns = [
    { value: '.*', label: 'Any value (.*)' },
    { value: '^dns:[a-zA-Z0-9.-]+$', label: 'Only DNS entries (e.g. dns:sub.domain.com)' },
    { value: '^email:.*@gmail\\.com$', label: 'Only @gmail.com emails (e.g. email:user@gmail.com)' },
    { value: '^(dns|email):.*$', label: 'Only DNS or Email entries' },
    { value: '^ip:[0-9]{1,3}(\\.[0-9]{1,3}){3}$', label: 'Only IPv4 addresses (e.g. ip:192.168.1.1)' }
];

interface Props {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
}

interface FormData {
    templateName: string;
    caIssuerSerialNumber: string;
    commonNameRegex: string;
    sansRegex: string;
    maxValidityDays: number;
    keyUsage: string[];
    extendedKeyUsage: string[];
}

export default function CreateTemplatePage({ showSnackbar }: Props) {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    
    const [formData, setFormData] = useState<FormData>({
        templateName: '',
        caIssuerSerialNumber: '',
        commonNameRegex: commonNamePatterns[0].value,
        sansRegex: sanPatterns[0].value,
        maxValidityDays: 365,
        keyUsage: ['DigitalSignature', 'KeyEncipherment'],
        extendedKeyUsage: ['ServerAuth']
    });

    const updateField = (field: keyof FormData, value: string | number) => {
        setFormData(prev => ({ ...prev, [field]: value }));
        setError('');
    };

    const toggleUsage = (type: 'keyUsage' | 'extendedKeyUsage', value: string) => {
        setFormData(prev => {
            const currentList = prev[type];
            const updatedList = currentList.includes(value)
                ? currentList.filter(item => item !== value)
                : [...currentList, value];
            return { ...prev, [type]: updatedList };
        });
        setError('');
    };

    const validateForm = (): boolean => {
        if (!formData.templateName.trim()) {
            setError('Template Name is required.');
            return false;
        }
        if (!formData.caIssuerSerialNumber.trim()) {
            setError('CA Issuer Serial Number is required.');
            return false;
        }
        if (formData.maxValidityDays < 1 || formData.maxValidityDays > 3650) {
            setError('Max Validity Days must be between 1 and 3650 (10 years).');
            return false;
        }
        if (formData.keyUsage.length === 0 && formData.extendedKeyUsage.length === 0) {
            setError('You must select at least one Key Usage or Extended Key Usage.');
            return false;
        }
        return true;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        
        if (!validateForm()) return;

        const templateDto: CertificateTemplateDto = {
            ...formData,
            keyUsage: formData.keyUsage.join(','),
            extendedKeyUsage: formData.extendedKeyUsage.join(',')
        };

        try {
            setLoading(true);
            await TemplateService.createTemplate(templateDto);
            showSnackbar('Certificate Template successfully created!', 'success');
            navigate('/');
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Unknown error during template creation.';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

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
            <Paper elevation={3} sx={{ width: 600, p: 4, borderRadius: 2 }}>
                <Typography variant="h4" component="h1" align="center" gutterBottom>
                    <strong>Create New Template</strong>
                </Typography>
                
                <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    <TextField
                        label="Template Name"
                        value={formData.templateName}
                        onChange={(e) => updateField('templateName', e.target.value)}
                        required
                        fullWidth
                    />
                    
                    <TextField
                        label="CA Issuer Serial Number"
                        value={formData.caIssuerSerialNumber}
                        onChange={(e) => updateField('caIssuerSerialNumber', e.target.value)}
                        required
                        fullWidth
                        helperText="Serial number of the CA certificate that can issue certificates from this template."
                    />
                    
                    <Divider />
                    
                    <TextField
                        label="Max Validity Days"
                        type="number"
                        value={formData.maxValidityDays}
                        onChange={(e) => updateField('maxValidityDays', Number(e.target.value))}
                        required
                        fullWidth
                        InputProps={{ inputProps: { min: 1, max: 3650 } }}
                    />
                    
                    <FormControl fullWidth>
                        <InputLabel>Common Name Regex</InputLabel>
                        <Select
                            value={formData.commonNameRegex}
                            label="Common Name Regex"
                            onChange={(e) => updateField('commonNameRegex', e.target.value)}
                        >
                            {commonNamePatterns.map((pattern) => (
                                <MenuItem key={pattern.value} value={pattern.value}>
                                    {pattern.label}
                                </MenuItem>
                            ))}
                        </Select>
                        <Typography variant="caption" sx={{ mt: 0.5, color: 'text.secondary' }}>
                            Selected Regex: <em>{formData.commonNameRegex}</em>
                        </Typography>
                    </FormControl>

                    <FormControl fullWidth>
                        <InputLabel>Subject Alternative Names Regex</InputLabel>
                        <Select
                            value={formData.sansRegex}
                            label="Subject Alternative Names Regex"
                            onChange={(e) => updateField('sansRegex', e.target.value)}
                        >
                            {sanPatterns.map((pattern) => (
                                <MenuItem key={pattern.value} value={pattern.value}>
                                    {pattern.label}
                                </MenuItem>
                            ))}
                        </Select>
                        <Typography variant="caption" sx={{ mt: 0.5, color: 'text.secondary' }}>
                            Selected Regex: <em>{formData.sansRegex}</em>
                        </Typography>
                    </FormControl>

                    <Divider />

                    <Box>
                        <FormLabel component="legend">Key Usage (Select allowed purposes)</FormLabel>
                        <FormGroup row>
                            {keyUsageOptions.map((option) => (
                                <FormControlLabel
                                    key={option}
                                    control={
                                        <Checkbox
                                            checked={formData.keyUsage.includes(option)}
                                            onChange={() => toggleUsage('keyUsage', option)}
                                        />
                                    }
                                    label={option}
                                />
                            ))}
                        </FormGroup>
                    </Box>

                    <Box>
                        <FormLabel component="legend">Extended Key Usage (Select allowed usage contexts)</FormLabel>
                        <FormGroup row>
                            {extendedKeyUsageOptions.map((option) => (
                                <FormControlLabel
                                    key={option}
                                    control={
                                        <Checkbox
                                            checked={formData.extendedKeyUsage.includes(option)}
                                            onChange={() => toggleUsage('extendedKeyUsage', option)}
                                        />
                                    }
                                    label={option}
                                />
                            ))}
                        </FormGroup>
                    </Box>

                    {error && (
                        <Typography variant="body2" color="error" align="center">
                            {error}
                        </Typography>
                    )}
                    
                    <Button
                        type="submit"
                        variant="contained"
                        fullWidth
                        disabled={loading}
                        sx={{ mt: 2, py: 1.5 }}
                    >
                        {loading ? <CircularProgress size={24} /> : 'Save Template'}
                    </Button>
                </Box>
            </Paper>
        </Box>
    );
}