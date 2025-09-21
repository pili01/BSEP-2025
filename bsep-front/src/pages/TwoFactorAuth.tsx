import * as React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import { CircularProgress, FormControlLabel, Checkbox } from '@mui/material';
import AuthService from '../services/AuthService';
import { useUser } from '../context/UserContext';

type Props = {
  showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

export default function TwoFactorAuth({ showSnackbar }: Props) {
  const location = useLocation();
  const navigate = useNavigate();
  const { email, password } = location.state || {};
  const [code, setCode] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');
  const [success, setSuccess] = React.useState(false);
  const [disable2fa, setDisable2fa] = React.useState(false);
  const { user, setUser, logout } = useUser();


  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      setLoading(true);
      const response = await AuthService.verify2fa(email, password, code, disable2fa);
      if (response.token) {
        localStorage.setItem('jwt', response.token);
        setSuccess(true);
        showSnackbar('Login successful', 'success');
        const userInfo = await AuthService.getMyInfo();
        console.log("User info after login:", userInfo);
        if (!userInfo) {
          showSnackbar('Failed to fetch user info after login', 'error');
          return;
        }
        await setUser(userInfo);
        navigate('/');
      } else {
        setError('Invalid code or login failed.');
        showSnackbar('Invalid code or login failed.', 'error');
      }
    } catch (err) {
      setError('Verification failed. Please try again.');
      showSnackbar('Verification failed. Please try again.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Paper elevation={4} sx={{ width: 350, p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, borderRadius: 3 }}>
        <VerifiedUserIcon sx={{ fontSize: 64, color: '#1976d2' }} />
        <Typography variant="h5" align="center" gutterBottom>
          Two-Factor Authentication
        </Typography>
        <Typography variant="body1" align="center" color="text.secondary">
          Enter the code from your authenticator app or a backup code to log in.
        </Typography>
        <form onSubmit={handleSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>
          <TextField
            label="2FA or Backup Code"
            name="code"
            value={code}
            onChange={e => setCode(e.target.value)}
            required
            fullWidth
            autoFocus
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={disable2fa}
                onChange={e => setDisable2fa(e.target.checked)}
                color="primary"
              />
            }
            label="Disable 2FA for future logins"
            sx={{ mt: -1 }}
          />
          {error && <Typography variant="body2" color="error" align="center">{error}</Typography>}
          <Button
            variant="contained"
            color="primary"
            size="large"
            type="submit"
            disabled={loading || success}
            sx={{ mt: 2, borderRadius: 2 }}
          >
            {loading ? <CircularProgress size={24} /> : 'Verify & Login'}
          </Button>
        </form>
      </Paper>
    </Box>
  );
}
