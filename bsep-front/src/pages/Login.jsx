import * as React from 'react';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Link from '@mui/material/Link';
import Box from '@mui/material/Box';

export default function Login() {
  return (
    <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Paper elevation={3} sx={{ width: 300, p: 3, display: 'flex', flexDirection: 'column', gap: 2, borderRadius: 2 }}>
        <Typography variant="h4" component="h1" align="center" gutterBottom>
          <b>Welcome!</b>
        </Typography>
        <Typography variant="body2" align="center" gutterBottom>
          Sign in to continue.
        </Typography>
        <TextField
          label="Email"
          name="email"
          type="email"
          placeholder="johndoe@email.com"
          variant="outlined"
          fullWidth
        />
        <TextField
          label="Password"
          name="password"
          type="password"
          placeholder="password"
          variant="outlined"
          fullWidth
        />
        <Button variant="contained" sx={{ mt: 1 }} fullWidth>Log in</Button>
        <Typography variant="body2" align="center">
          Don&apos;t have an account?{' '}
          <Link href="/sign-up">Sign up</Link>
        </Typography>
      </Paper>
    </Box>
  );
}
