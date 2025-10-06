import * as React from 'react';
import ReCAPTCHA from 'react-google-recaptcha';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Link from '@mui/material/Link';
import Box from '@mui/material/Box';
import AuthService from '../services/AuthService';
import { CircularProgress } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../context/UserContext';

type Props = {
  showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

export default function Login({ showSnackbar }: Props) {
  const [form, setForm] = React.useState({
    email: '',
    password: '',
  });
  const [recaptchaToken, setRecaptchaToken] = React.useState<string | null>(null);
  const recaptchaRef = React.useRef<ReCAPTCHA>(null);
  const [showPassword, setShowPassword] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const navigate = useNavigate();
  const { user, setUser, logout } = useUser();

  interface LogInForm {
    email: string;
    password: string;
  }

  const handleRecaptchaChange = (token: string | null) => {
    setRecaptchaToken(token);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleLogin = async () => {
    if (!recaptchaToken) {
      alert('Molimo potvrdite da niste robot!');
      return;
    }
    try {
      setLoading(true);
      const response = await AuthService.login(form.email, form.password, recaptchaToken);
      if (response.twoFaEnabled) {
        navigate('/2fa', { state: { email: form.email, password: form.password } });
      } else if (response.token) {
        localStorage.setItem('jwt', response.token);
        showSnackbar("Login successful", 'success');
        const userInfo = await AuthService.getMyInfo();
        console.log("User info after login:", userInfo);
        if (!userInfo) {
          showSnackbar('Failed to fetch user info after login', 'error');
          return;
        }
        await setUser(userInfo);
        navigate('/');
      } else {
        showSnackbar('Login failed: Unknown response from server', 'error');
      }
    } catch (error) {
      if (recaptchaRef.current) {
        (recaptchaRef.current as any).reset();
      }
      const errorMessage = (error instanceof Error && error.message) ? error.message : 'Unknown error';
      showSnackbar(errorMessage, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Paper elevation={3} sx={{ width: 300, p: 3, display: 'flex', flexDirection: 'column', gap: 2, borderRadius: 2 }}>
        <Typography variant="h4" component="h1" align="center" gutterBottom>
          <b>Welcome!</b>
        </Typography>
        <Typography variant="body2" align="center" gutterBottom>
          Login to continue.
        </Typography>
        <TextField label="Email" name="email" type="email" value={form.email} onChange={handleChange} required fullWidth />
        <TextField label="Password" name="password" type={showPassword ? 'text' : 'password'} value={form.password} onChange={handleChange} required fullWidth placeholder="Password" />
        <Button
          variant="text"
          size="small"
          sx={{ alignSelf: 'flex-end', mb: 1 }}
          onClick={() => setShowPassword((prev) => !prev)}
        >
          {showPassword ? 'Hide password' : 'Show password'}
        </Button>
        <ReCAPTCHA
          ref={recaptchaRef}
          sitekey={import.meta.env.VITE_RECAPTCHA_SITE_KEY}
          onChange={handleRecaptchaChange}
        />
        <Button variant="contained" sx={{ mt: 1 }} fullWidth onClick={handleLogin} disabled={recaptchaToken && !loading ? false : true}>
          {loading ? <CircularProgress size={24} /> : 'Log in'}
        </Button>
        <Typography variant="body2" align="center">
          Forgotten password?{' '}
          <Link href="/forgot-password">Reset it</Link>
        </Typography>
        <Typography variant="body2" align="center">
          Don&apos;t have an account?{' '}
          <Link href="/sign-up">Sign up</Link>
        </Typography>
      </Paper>
    </Box>
  );
}
