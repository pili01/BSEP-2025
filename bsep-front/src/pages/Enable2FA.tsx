import * as React from 'react';
import { useNavigate } from 'react-router-dom';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import AuthService from '../services/AuthService';
import { CircularProgress } from '@mui/material';

type Props = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

export default function Enable2FA({ showSnackbar }: Props) {
    const [qrCode, setQrCode] = React.useState<string | null>(null);
    const [backupCodes, setBackupCodes] = React.useState<string[]>([]);
    const [code, setCode] = React.useState<number | null>(null);
    const [error, setError] = React.useState('');
    const [success, setSuccess] = React.useState(false);
    const [loading, setLoading] = React.useState(false);
    const navigate = useNavigate();


    React.useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await AuthService.enable2fa();
                setQrCode(response.qrCodeImage);
                setBackupCodes(response.backupCodes);
            } catch (error) {
                setError('Failed to enable 2FA');
                navigate('/');
                const errorMessage = (error instanceof Error && error.message) ? error.message : 'Unknown error';
                showSnackbar(errorMessage, 'error');
            }
        };
        fetchData();
    }, []);

    const handleVerify = async () => {
        setError('');
        try {
            setLoading(true);
            if (code === null) {
                setError('Please enter the number code from your authenticator app.');
                return;
            }
            await AuthService.verifyEnable2fa(code);
            setSuccess(true);
            navigate('/');
            showSnackbar('2FA enabled successfully!', 'success');
        } catch (error) {
            const errorMessage = (error instanceof Error && error.message) ? error.message : 'Unknown error';
            setError('Verification failed: ' + errorMessage);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Paper elevation={4} sx={{ width: 400, p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, borderRadius: 3 }}>
                <WarningAmberIcon sx={{ fontSize: 48, color: '#d32f2f' }} />
                <Typography variant="h5" align="center" gutterBottom>
                    Enable Two-Factor Authentication
                </Typography>
                <Typography variant="body2" color="error" align="center" sx={{ mb: 2 }}>
                    Save your backup codes! If you lose access to your authenticator app, you will need these codes to log in. Losing them may result in permanent loss of account access.
                </Typography>
                {qrCode && <img src={qrCode} alt="QR Code" style={{ marginBottom: 16, width: 180, height: 180 }} />}
                <Box sx={{ mb: 2, width: '100%' }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Backup Codes:</Typography>
                    <Paper variant="outlined" sx={{ p: 2, mb: 1 }}>
                        <ul style={{ margin: 0, paddingLeft: 18 }}>
                            {backupCodes.map((code, idx) => (
                                <li key={idx} style={{ fontFamily: 'monospace', fontSize: 15 }}>{code}</li>
                            ))}
                        </ul>
                    </Paper>
                </Box>
                <TextField
                    label="Enter code from authenticator app"
                    value={code}
                    onChange={e => {
                        const val = e.target.value;
                        setCode(val === '' ? null : Number(val));
                    }}
                    required
                    fullWidth
                />
                {error && <Typography variant="body2" color="error" align="center">{error}</Typography>}
                <Button
                    variant="contained"
                    color="primary"
                    size="large"
                    onClick={handleVerify}
                    disabled={success || loading}
                    sx={{ mt: 2, borderRadius: 2 }}
                >
                    {loading ? <CircularProgress size={24} /> : 'Verify'}
                </Button>
            </Paper>
        </Box>
    );
}
