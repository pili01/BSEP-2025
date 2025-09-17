import * as React from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CircularProgress from '@mui/material/CircularProgress';
import AuthService from '../services/AuthService';

type Props = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

export default function VerifyEmail({ showSnackbar }: Props) {
    const location = useLocation();
    const searchParams = new URLSearchParams(location.search);
    const token = searchParams.get('token');
    const [loading, setLoading] = React.useState(false);
    const [success, setSuccess] = React.useState<boolean | null>(null);
    const [message, setMessage] = React.useState('');
    const navigate = useNavigate();

    const handleVerify = async () => {
        setLoading(true);
        setMessage('');
        try {
            await AuthService.verifyEmail(token);
            setSuccess(true);
            setMessage('Your email has been successfully verified!');
            showSnackbar('Email verified successfully!', 'success');
            navigate('/login');
        } catch (err) {
            setSuccess(false);
            setMessage('Verification failed. Please try again or contact support.');
            showSnackbar('Email verification failed: ' + (err instanceof Error ? err.message : 'Unknown error'), 'error');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Paper elevation={4} sx={{ width: 350, p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, borderRadius: 3 }}>
                <CheckCircleIcon sx={{ fontSize: 64, color: success === true ? 'green' : '#1976d2' }} />
                <Typography variant="h5" align="center" gutterBottom>
                    Verify your email address
                </Typography>
                <Typography variant="body1" align="center" color={success === false ? 'error' : 'text.secondary'}>
                    {message || 'Click the button below to verify your email.'}
                </Typography>
                <Button
                    variant="contained"
                    color="primary"
                    size="large"
                    onClick={handleVerify}
                    disabled={loading || success === true}
                    sx={{ mt: 2, borderRadius: 2 }}
                >
                    {loading ? <CircularProgress size={24} /> : 'Verify mail'}
                </Button>
            </Paper>
        </Box>
    );
}
