import * as React from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Link from '@mui/material/Link';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import EmailIcon from '@mui/icons-material/Email';
import AuthService from '../services/AuthService';
import { useNavigate } from 'react-router-dom';

type ForgotPasswordProps = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

export default function ForgotPassword({ showSnackbar }: ForgotPasswordProps) {
    const [email, setEmail] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    const [sent, setSent] = React.useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        
        if (!email.trim()) {
            showSnackbar('Please enter your email address.', 'error');
            return;
        }

        try {
            setLoading(true);
            await AuthService.forgotPassword(email);
            setSent(true);
            showSnackbar('Password reset email sent! Check your inbox.', 'success');
        } catch (err) {
            const errorMessage = (err instanceof Error && err.message) ? err.message : 'Failed to send reset email';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

    if (sent) {
        return (
            <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Paper elevation={3} sx={{ width: 400, p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, borderRadius: 3 }}>
                    <EmailIcon sx={{ fontSize: 64, color: '#1976d2' }} />
                    <Typography variant="h5" align="center" gutterBottom>
                        Check your email
                    </Typography>
                    <Typography variant="body1" align="center" color="text.secondary">
                        We've sent a password reset link to <strong>{email}</strong>
                    </Typography>
                    <Typography variant="body2" align="center" color="text.secondary">
                        If you don't see the email, check your spam folder.
                    </Typography>
                    <Button
                        variant="outlined"
                        color="primary"
                        onClick={() => navigate('/login')}
                        sx={{ mt: 2, borderRadius: 2 }}
                    >
                        Back to Login
                    </Button>
                </Paper>
            </Box>
        );
    }

    return (
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Paper elevation={3} sx={{ width: 400, p: 4, display: 'flex', flexDirection: 'column', gap: 3, borderRadius: 3 }}>
                <Typography variant="h4" component="h1" align="center" gutterBottom>
                    <b>Forgot Password</b>
                </Typography>
                <Typography variant="body2" align="center" color="text.secondary" gutterBottom>
                    Enter your email address and we'll send you a link to reset your password.
                </Typography>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                    <TextField 
                        label="Email Address" 
                        name="email" 
                        type="email" 
                        value={email} 
                        onChange={(e) => setEmail(e.target.value)}
                        required 
                        fullWidth 
                        autoFocus
                        placeholder="Enter your email"
                    />
                    
                    <Button 
                        variant="contained" 
                        type="submit" 
                        fullWidth 
                        disabled={loading}
                        sx={{ mt: 2, py: 1.5, borderRadius: 2 }}
                    >
                        {loading ? <CircularProgress size={24} /> : 'Send Reset Link'}
                    </Button>
                </form>

                <Box sx={{ textAlign: 'center', mt: 2 }}>
                    <Typography variant="body2">
                        Remember your password?{' '}
                        <Link href="/login" sx={{ textDecoration: 'none' }}>
                            Back to Login
                        </Link>
                    </Typography>
                </Box>
            </Paper>
        </Box>
    );
}