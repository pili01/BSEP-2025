import { useState } from 'react'
import './App.css'
import NavBar from './pages/Navbar'
import { Route, Routes } from 'react-router-dom'
import Login from './pages/Login'
import SignUp from './pages/SignUp'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import { Alert, Snackbar } from '@mui/material'
import VerifyEmail from './pages/VerifyEmail'
import TwoFactorAuth from './pages/TwoFactorAuth'
import Enable2FA from './pages/Enable2FA'
import SavedPasswords from './pages/SavedPasswords'
import { UserProvider } from './context/UserContext'
import GenerateKeyPage from './pages/GenerateKeyPage'

function App() {
  const [mode, setMode] = useState<'dark' | 'light'>('dark');
  const theme = createTheme({ palette: { mode } });
  const [snackbars, setSnackbars] = useState<Array<{ id: number, message: string, severity: 'success' | 'error' | 'info' | 'warning' }>>([]);

  const toggleTheme = () => {
    setMode((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbars((prev) => [...prev, { id: Date.now(), message, severity }]);
  };

  return (
    <ThemeProvider theme={theme}>
      <UserProvider>
      {snackbars.map((snack, idx) => (
        <Snackbar
          key={snack.id}
          open={true}
          autoHideDuration={3000}
          onClose={(_, reason) => {
            // Zatvaraj samo kad istekne timeout ili kad korisnik klikne X
            if (reason === 'timeout' || reason === 'clickaway') {
              setSnackbars((prev) => prev.filter((s) => s.id !== snack.id));
            }
          }}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
          sx={{ mb: `${idx * 60}px` }}
        >
          <Alert
            onClose={() => setSnackbars((prev) => prev.filter((s) => s.id !== snack.id))}
            severity={snack.severity}
            sx={{ width: '100%' }}
          >
            {snack.message}
          </Alert>
        </Snackbar>

      ))}
      <NavBar toggleTheme={toggleTheme} mode={mode} />
      <Routes>
        <Route path='/' element={<h1>Home page</h1>} />
        <Route path='/login' element={<Login showSnackbar={showSnackbar}/>} />
        <Route path='/sign-up' element={<SignUp showSnackbar={showSnackbar} />} />
        <Route path='/verify-email' element={<VerifyEmail showSnackbar={showSnackbar} />} />
        <Route path='/2fa' element={<TwoFactorAuth showSnackbar={showSnackbar} />} />
        <Route path='/enable-2fa' element={<Enable2FA showSnackbar={showSnackbar} />} />
        <Route path='/password-manager' element={<SavedPasswords showSnackbar={showSnackbar} />} />
        <Route path='/generate-key' element={<GenerateKeyPage showSnackbar={showSnackbar} />} />
        <Route path='*' element={<h1>404 Not Found</h1>} />
      </Routes>
      </UserProvider>
    </ThemeProvider>
  );
}

export default App;
