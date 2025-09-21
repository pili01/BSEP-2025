import * as React from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Link from '@mui/material/Link';
import Box from '@mui/material/Box';
import LinearProgress from '@mui/material/LinearProgress';
import zxcvbn from "zxcvbn-typescript";
import AuthService from '../services/AuthService';
import { CircularProgress } from '@mui/material';
import { useNavigate } from 'react-router-dom';

const passwordStrengthLabels = [
    'Very Weak',
    'Weak',
    'Fair',
    'Good',
    'Strong',
];

type SignUpProps = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

export default function SignUp({ showSnackbar }: SignUpProps) {
    const [form, setForm] = React.useState({
        email: '',
        password: '',
        confirmPassword: '',
        firstName: '',
        lastName: '',
        organization: '',
    });
    const [passwordScore, setPasswordScore] = React.useState(0);
    const [passwordFeedback, setPasswordFeedback] = React.useState('');
    const [error, setError] = React.useState('');
    const [showPassword, setShowPassword] = React.useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = React.useState(false);
    const [loading, setLoading] = React.useState(false);
    const navigate = useNavigate();

    // Password requirements (Unicode-friendly)
    const hasUpper = /\p{Lu}/u.test(form.password);      // Uppercase
    const hasLower = /\p{Ll}/u.test(form.password);      // Lowercase
    const hasNumber = /\p{Nd}/u.test(form.password);     // Number (Unicode digit)
    const hasSpecial = /[^\p{L}\p{Nd}]/u.test(form.password); // Special char
    const hasMinLength = form.password.length >= 8;
    const hasMaxLength = form.password.length <= 64;
    const passwordsMatch = form.password === form.confirmPassword && form.password.length > 0;

    React.useEffect(() => {
        const result = zxcvbn(form.password);
        setPasswordScore(result.score);
        setPasswordFeedback(result.feedback.suggestions.join(' '));
    }, [form.password]);

    interface SignUpForm {
        email: string;
        password: string;
        confirmPassword: string;
        firstName: string;
        lastName: string;
        organization: string;
    }

    interface HandleChangeEvent {
        target: {
            name: keyof SignUpForm;
            value: string;
        };
    }

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setForm({ ...form, [e.target.name]: e.target.value });
        setError('');
    };

    const checkPasswordRequirements = () => {
        return hasUpper && hasLower && hasNumber && hasSpecial && hasMinLength && hasMaxLength && passwordsMatch && passwordScore >= 2;
    };

    const validate = () => {
        if (!form.email || !form.password || !form.confirmPassword || !form.firstName || !form.lastName || !form.organization) {
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

    interface HandleSubmitEvent extends React.FormEvent<HTMLFormElement> { }

    const handleSubmit = async (e: HandleSubmitEvent) => {
        e.preventDefault();
        if (!validate()) return;
        try {
            setLoading(true);
            await AuthService.register(form);
            showSnackbar('Registration successful!', 'success');
            navigate('/login');
        } catch (err) {
            const errorMessage = (err instanceof Error && err.message) ? err.message : 'Unknown error';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Paper elevation={3} sx={{ width: 350, p: 3, display: 'flex', flexDirection: 'column', gap: 2, borderRadius: 2 }}>
                <Typography variant="h4" component="h1" align="center" gutterBottom>
                    <b>Sign Up</b>
                </Typography>
                <Typography variant="body2" align="center" gutterBottom>
                    Register as a regular user.
                </Typography>
                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <TextField label="Email" name="email" type="email" value={form.email} onChange={handleChange} required fullWidth />
                    <TextField label="First Name" name="firstName" value={form.firstName} onChange={handleChange} required fullWidth />
                    <TextField label="Last Name" name="lastName" value={form.lastName} onChange={handleChange} required fullWidth />
                    <TextField label="Organization" name="organization" value={form.organization} onChange={handleChange} required fullWidth />
                    <TextField label="Password" name="password" type={showPassword ? 'text' : 'password'} value={form.password} onChange={handleChange} required fullWidth placeholder="Password" />
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
                    <TextField label="Confirm Password" name="confirmPassword" type={showConfirmPassword ? 'text' : 'password'} value={form.confirmPassword} onChange={handleChange} required fullWidth placeholder="Repeat password" />
                    <Button
                        variant="text"
                        size="small"
                        sx={{ alignSelf: 'flex-end', mb: 1 }}
                        onClick={() => setShowConfirmPassword((prev) => !prev)}
                    >
                        {showConfirmPassword ? 'Hide password' : 'Show password'}
                    </Button>
                    {error && <Typography variant="body2" color="error" align="center">{error}</Typography>}
                    <Button variant="contained" sx={{ mt: 1 }} fullWidth type="submit" disabled={loading}>{loading ? <CircularProgress size={24} /> : 'Register'}</Button>
                </form>
                <Typography variant="body2" align="center">
                    Already have an account?{' '}
                    <Link href="/login">Log in</Link>
                </Typography>
            </Paper>
        </Box>
    );
}
