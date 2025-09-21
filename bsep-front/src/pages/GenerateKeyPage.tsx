import React, { useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import CircularProgress from '@mui/material/CircularProgress';
import PasswordService from '../services/PasswordService';
import AuthService from '../services/AuthService';
import { useNavigate } from 'react-router-dom';

type Props = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

const GenerateKeyPage: React.FC<Props> = ({ showSnackbar }) => {
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [step, setStep] = useState<'form' | 'done'>('form');
    const [showPassword, setShowPassword] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchData = async () => {
            try {
                const me = await AuthService.getMyInfo();
                if (me && me.publicKey && me.publicKey !== '') {
                    showSnackbar('You already have a public key set. Redirecting...', 'info');
                    navigate('/');
                }
            } catch (error) {
                const errorMessage = (error instanceof Error && error.message) ? error.message : 'Unknown error';
                showSnackbar(errorMessage, 'error');
            }
        };
        fetchData();
    }, []);

    const handleGenerate = async () => {
        setError('');
        if (!password || password.length < 6) {
            setError('Password must be at least 6 characters.');
            return;
        }
        try {
            setLoading(true);
            const pubKey = await PasswordService.generateAndReturnPublicKey(password);
            await PasswordService.savePublicKey(pubKey);
            showSnackbar('Public key generated and saved successfully.', 'success');
            setStep('done');
        } catch (err) {
            setError('Error generating key pair.');
            const errorMessage = (err instanceof Error && err.message) ? err.message : 'Unknown error';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleFinish = () => {
        navigate('/');
    };

    return (
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Paper elevation={4} sx={{ width: 400, p: 4, borderRadius: 3, display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Typography variant="h5" align="center" gutterBottom>
                    Public Key Generation
                </Typography>
                {step === 'form' && (
                    <>
                        <Typography variant="body1" align="center" sx={{ mb: 2 }}>
                            Enter a password to encrypt your private key. <b>Remember this password</b> — it will be required to decrypt your passwords later.
                        </Typography>
                        <TextField
                            label="Password for Key Encryption"
                            type={showPassword ? 'text' : 'password'}
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            fullWidth
                            sx={{ mb: 2 }}
                        />
                        <Button
                            variant="text"
                            size="small"
                            sx={{ alignSelf: 'flex-end', mb: 1 }}
                            onClick={() => setShowPassword((prev) => !prev)}
                        >
                            {showPassword ? 'Hide password' : 'Show password'}
                        </Button>
                        {error && <Typography color="error" align="center">{error}</Typography>}
                        <Button variant="contained" color="primary" onClick={handleGenerate} disabled={loading}>
                            {loading ? <CircularProgress size={24} /> : 'Download private Key'}
                        </Button>
                    </>
                )}
                {step === 'done' && (
                    <>
                        <Typography variant="body1" align="center" sx={{ mb: 2 }} color='warning.main'>
                            <span style={{ color: '#2e7d32', fontWeight: 500 }}>Your private key has been saved successfully.</span><br /><br />
                            <b>Important:</b> Keep your private key in a safe place and <b>never share it</b> with anyone. This key is required to decrypt your passwords.<br /><br />
                            Also, <b>remember your password</b> for unlocking the key. If you forget it, you will lose access to all your saved passwords.
                        </Typography>
                        <Button variant="contained" color="primary" onClick={handleFinish}>
                            Continue
                        </Button>
                    </>
                )}
            </Paper>
        </Box>
    );
};

export default GenerateKeyPage;
