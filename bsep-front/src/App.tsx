import { useState, useEffect } from 'react'
import './App.css'
import NavBar from './pages/Navbar'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import Login from './pages/Login'
import SignUp from './pages/SignUp'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import { Alert, Snackbar } from '@mui/material'
import VerifyEmail from './pages/VerifyEmail'
import TwoFactorAuth from './pages/TwoFactorAuth'
import Enable2FA from './pages/Enable2FA'
import SavedPasswords from './pages/SavedPasswords'
import { UserProvider, useUser } from './context/UserContext'
import GenerateKeyPage from './pages/GenerateKeyPage'
import CreateCSR from './pages/CreateCSR'
import CSRRequests from './pages/CSRRequests'
import SessionsPage from './pages/SessionsPage';
import AdminCertificates from './pages/AdminCertificates'
import AdminIssueCertificatePage from './pages/AdminIssueCertificatePage'
import CACertificates from './pages/CACertificates'
import UserCertificates from './pages/UserCertificates'
import ProtectedRoute from './components/ProtectedRoute'
import CreateTemplatePage from './pages/CreateTemplatePage'
import { UserRole } from './models/User'
import CaUserIssueCertificatePage from './pages/CaUserIssueCertificatePage'
import ChangeInitialPasswordPage from './pages/ChangeInitialPasswordPage'
import RegisterCAUserPage from './pages/RegisterCAUserPage'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'

function AppContent() {
  const [mode, setMode] = useState<'dark' | 'light'>('dark');
  const theme = createTheme({ palette: { mode } });
  const [snackbars, setSnackbars] = useState<Array<{ id: number, message: string, severity: 'success' | 'error' | 'info' | 'warning' }>>([]);
  const navigate = useNavigate();
  const { logout } = useUser();

  const toggleTheme = () => {
    setMode((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info' | 'warning') => {
    setSnackbars((prev) => [...prev, { id: Date.now(), message, severity }]);
  };

  useEffect(() => {
    const handleSessionRevoked = (event: any) => {
      if (event.reason?.message?.includes('Session revoked') ||
        event.reason?.message?.includes('Your session has been revoked')) {
        showSnackbar('Your session has been revoked by an administrator', 'warning');
        logout();
        navigate('/login');
      }
    };

    window.addEventListener('unhandledrejection', handleSessionRevoked);

    return () => {
      window.removeEventListener('unhandledrejection', handleSessionRevoked);
    };
  }, [logout, navigate]);

  return (
    <ThemeProvider theme={theme}>
      {snackbars.map((snack, idx) => (
        <Snackbar
          key={snack.id}
          open={true}
          autoHideDuration={3000}
          onClose={(_, reason) => {
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
        <Route path='/' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.ADMIN, UserRole.REGULAR_USER, UserRole.CA_USER]}>
            <h1>Home page</h1>
          </ProtectedRoute>
        } />
        <Route path='/login' element={<Login showSnackbar={showSnackbar} />} />
        <Route path='/sign-up' element={<SignUp showSnackbar={showSnackbar} />} />
        <Route path='/forgot-password' element={<ForgotPassword showSnackbar={showSnackbar} />} />
        <Route path='/reset-password' element={<ResetPassword showSnackbar={showSnackbar} />} />
        <Route path='/verify-email' element={<VerifyEmail showSnackbar={showSnackbar} />} />
        <Route path='/2fa' element={<TwoFactorAuth showSnackbar={showSnackbar} />} />
        <Route path='/enable-2fa' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.ADMIN, UserRole.REGULAR_USER, UserRole.CA_USER]}>
            <Enable2FA showSnackbar={showSnackbar} />
          </ProtectedRoute>
        } />
        <Route path='/password-manager' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.REGULAR_USER]}>
            <SavedPasswords showSnackbar={showSnackbar} />
          </ProtectedRoute>
        } />
        <Route path='/generate-key' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.REGULAR_USER]}>
            <GenerateKeyPage showSnackbar={showSnackbar} />
          </ProtectedRoute>
        } />
        <Route path='/create-csr' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.REGULAR_USER]}>
            <CreateCSR />
          </ProtectedRoute>
        } />
        <Route path='/csr-requests' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.CA_USER, UserRole.ADMIN]}>
            <CSRRequests />
          </ProtectedRoute>
        } />
        <Route path='/sessions' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.ADMIN, UserRole.REGULAR_USER, UserRole.CA_USER]}>
            <SessionsPage showSnackbar={showSnackbar} />
          </ProtectedRoute>
        } />
        <Route path='/admin-certificates' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.ADMIN]}>
            <AdminCertificates />
          </ProtectedRoute>
        } />
        <Route path='/ca-certificates' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.CA_USER, UserRole.ADMIN]}>
            <CACertificates />
          </ProtectedRoute>
        } />
        <Route path='/my-certificates' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.REGULAR_USER, UserRole.CA_USER, UserRole.ADMIN]}>
            <UserCertificates />
          </ProtectedRoute>
        } />
        <Route path='/templates' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.CA_USER, UserRole.ADMIN]}>
            <CreateTemplatePage showSnackbar={showSnackbar} />
          </ProtectedRoute>
        } />
        <Route path='/adminIssue' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.ADMIN]}>
            <AdminIssueCertificatePage showSnackbar={showSnackbar} />
          </ProtectedRoute>
        } />
        <Route path='/caIssue' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.CA_USER]}>
            <CaUserIssueCertificatePage showSnackbar={showSnackbar} />
          </ProtectedRoute>
        } />
        <Route path='/registerCA' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.ADMIN]}>
            <RegisterCAUserPage />
          </ProtectedRoute>
        } />
        <Route path='/change-initial-password' element={
          <ProtectedRoute showSnackbar={showSnackbar} allowedRoles={[UserRole.CA_USER]}>
            <ChangeInitialPasswordPage />
          </ProtectedRoute>
        } />
        <Route path='*' element={<h1>404 Not Found</h1>} />
      </Routes>
    </ThemeProvider>
  );
}

function App() {
  return (
    <UserProvider>
      <AppContent />
    </UserProvider>
  );
}

export default App;
