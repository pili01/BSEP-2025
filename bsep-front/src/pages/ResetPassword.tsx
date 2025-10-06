import * as React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import LinearProgress from '@mui/material/LinearProgress';
import CircularProgress from '@mui/material/CircularProgress';
import LockResetIcon from '@mui/icons-material/LockReset';
import zxcvbn from "zxcvbn-typescript";
import AuthService from '../services/AuthService';

const passwordStrengthLabels = [
    'Very Weak',
    'Weak',
    'Fair',
    'Good',
    'Strong',
];

type ResetPasswordProps = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

export default function ResetPassword({ showSnackbar }: ResetPasswordProps) {
    const location = useLocation();
    const searchParams = new URLSearchParams(location.search);
    const token = searchParams.get('token');
    const email = searchParams.get('email');
    const navigate = useNavigate();

    const [form, setForm] = React.useState({
        password: '',
        confirmPassword: '',
    });
    const [passwordScore, setPasswordScore] = React.useState(0);
    const [passwordFeedback, setPasswordFeedback] = React.useState('');
    const [error, setError] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    const [showPassword, setShowPassword] = React.useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = React.useState(false);

    // Password requirements (Unicode-friendly)
    const hasUpper = /\p{Lu}/u.test(form.password);      // Uppercase
    const hasLower = /\p{Ll}/u.test(form.password);      // Lowercase
    const hasNumber = /\p{Nd}/u.test(form.password);     // Number (Unicode digit)
    const hasSpecial = /[^\p{L}\p{Nd}]/u.test(form.password); // Special char
    const hasMinLength = form.password.length >= 8;
    const hasMaxLength = form.password.length <= 64;
    const passwordsMatch = form.password === form.confirmPassword && form.password.length > 0;

    React.useEffect(() => {
        if (!token) {
            showSnackbar('Invalid reset link. Please request a new password reset.', 'error');
            navigate('/forgot-password');
            return;
        }
    }, [token, navigate, showSnackbar]);

    React.useEffect(() => {
        const result = zxcvbn(form.password);
        setPasswordScore(result.score);
        setPasswordFeedback(result.feedback.suggestions.join(' '));
    }, [form.password]);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setForm({ ...form, [e.target.name]: e.target.value });
        setError('');
    };

    const checkPasswordRequirements = () => {
        return hasUpper && hasLower && hasNumber && hasSpecial && hasMinLength && hasMaxLength && passwordsMatch && passwordScore >= 2;
    };

    const validate = () => {
        if (!form.password || !form.confirmPassword) {
            setError('All fields are required.');
            return false;
        }
        if (form.password.length < 8) {
            setError('Password must be at least 8 characters.');
            return false;
        }
        if (form.password.length > 64) {
            setError('Password must be at most 64 characters.');
            return false;
        }
        if (form.password !== form.confirmPassword) {
            setError('Passwords do not match.');
            return false;
        }
        if (!checkPasswordRequirements()) {
            setError('Password does not meet requirements.');
            return false;
        }
        return true;
    };

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (!validate()) return;

        try {
            setLoading(true);
            await AuthService.resetPassword(token, form.password, form.confirmPassword, email);
            showSnackbar('Password reset successfully! Please log in with your new password.', 'success');
            navigate('/login');
        } catch (err) {
            const errorMessage = (err instanceof Error && err.message) ? err.message : 'Failed to reset password';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Paper elevation={3} sx={{ width: 450, p: 4, display: 'flex', flexDirection: 'column', gap: 3, borderRadius: 3 }}>
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 2 }}>
                    <LockResetIcon sx={{ fontSize: 48, color: '#1976d2', mb: 1 }} />
                    <Typography variant="h4" component="h1" align="center" gutterBottom>
                        <b>Reset Password</b>
                    </Typography>
                    <Typography variant="body2" align="center" color="text.secondary">
                        Enter your new password below.
                    </Typography>
                </Box>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <TextField
                        label="New Password"
                        name="password"
                        type={showPassword ? 'text' : 'password'}
                        value={form.password}
                        onChange={handleChange}
                        required
                        fullWidth
                        placeholder="Enter new password"
                    />
                    <Button
                        variant="text"
                        size="small"
                        sx={{ alignSelf: 'flex-end', mb: 1 }}
                        onClick={() => setShowPassword((prev) => !prev)}
                    >
                        {showPassword ? 'Hide password' : 'Show password'}
                    </Button>

                    <LinearProgress
                        variant="determinate"
                        value={(passwordScore + 1) * 20}
                        sx={{
                            height: 8,
                            borderRadius: 2,
                            mb: 1,
                            '& .MuiLinearProgress-bar': {
                                backgroundColor:
                                    passwordScore < 2 ? '#d32f2f' :
                                        passwordScore === 2 ? '#ffa726' :
                                            passwordScore === 3 ? '#388e3c' :
                                                '#2e7d32',
                            },
                        }}
                    />
                    <Typography variant="caption" color={passwordScore < 2 ? 'error' : 'success.main'}>
                        Strength: {passwordStrengthLabels[passwordScore]} {passwordFeedback && `- ${passwordFeedback}`}
                    </Typography>

                    <Box sx={{ mt: 1, mb: 1 }}>
                        <Typography variant="body2" sx={{ fontWeight: 'bold' }}>Password requirements:</Typography>
                        <ul style={{ paddingLeft: 18, margin: 0 }}>
                            <li style={{ color: hasUpper ? 'green' : 'red' }}>
                                {hasUpper ? '✔' : '✖'} At least one uppercase letter
                            </li>
                            <li style={{ color: hasLower ? 'green' : 'red' }}>
                                {hasLower ? '✔' : '✖'} At least one lowercase letter
                            </li>
                            <li style={{ color: hasNumber ? 'green' : 'red' }}>
                                {hasNumber ? '✔' : '✖'} At least one number
                            </li>
                            <li style={{ color: hasSpecial ? 'green' : 'red' }}>
                                {hasSpecial ? '✔' : '✖'} At least one special character
                            </li>
                            <li style={{ color: hasMinLength ? 'green' : 'red' }}>
                                {hasMinLength ? '✔' : '✖'} Minimum 8 characters
                            </li>
                            <li style={{ color: hasMaxLength ? 'green' : 'red' }}>
                                {hasMaxLength ? '✔' : '✖'} Maximum 64 characters
                            </li>
                            <li style={{ color: passwordsMatch ? 'green' : 'red' }}>
                                {passwordsMatch ? '✔' : '✖'} Passwords match
                            </li>
                            <li style={{ color: passwordScore >= 2 ? 'green' : 'red' }}>
                                {passwordScore >= 2 ? '✔' : '✖'} Password strength: Fair or better
                            </li>
                        </ul>
                    </Box>

                    <TextField
                        label="Confirm New Password"
                        name="confirmPassword"
                        type={showConfirmPassword ? 'text' : 'password'}
                        value={form.confirmPassword}
                        onChange={handleChange}
                        required
                        fullWidth
                        placeholder="Confirm new password"
                    />
                    <Button
                        variant="text"
                        size="small"
                        sx={{ alignSelf: 'flex-end', mb: 1 }}
                        onClick={() => setShowConfirmPassword((prev) => !prev)}
                    >
                        {showConfirmPassword ? 'Hide password' : 'Show password'}
                    </Button>

                    {error && <Typography variant="body2" color="error" align="center">{error}</Typography>}

                    <Button
                        variant="contained"
                        sx={{ mt: 2, py: 1.5, borderRadius: 2 }}
                        fullWidth
                        type="submit"
                        disabled={loading || !checkPasswordRequirements()}
                    >
                        {loading ? <CircularProgress size={24} /> : 'Reset Password'}
                    </Button>
                </form>

                <Box sx={{ textAlign: 'center', mt: 2 }}>
                    <Typography variant="body2">
                        Remember your password?{' '}
                        <Button
                            variant="text"
                            size="small"
                            onClick={() => navigate('/login')}
                            sx={{ textTransform: 'none', p: 0, minWidth: 'auto' }}
                        >
                            Back to Login
                        </Button>
                    </Typography>
                </Box>
            </Paper>
        </Box>
    );
}