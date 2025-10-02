import React, { useState } from 'react';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import AuthService from '../services/AuthService';
import { useUser } from '../context/UserContext';
import { UserRole } from '../models/User';
import { 
    Paper,
    Typography, 
    CircularProgress, 
    Box,
    TextField, 
    Button, 
    Alert,
    Divider,
    Container 
} from '@mui/material';
import PersonAddAlt1Icon from '@mui/icons-material/PersonAddAlt1';

const RegisterCAUserPage: React.FC = () => {
    const { user, loading: userLoading } = useUser();
    const navigate = useNavigate();

    const [formData, setFormData] = useState({
        email: '',
        firstName: '',
        lastName: '',
        organization: '',
        password: 'InitialPassword123!', 
        confirmPassword: 'InitialPassword123!',
    });
    const [loading, setLoading] = useState(false);
    const [isInitialCheck, setIsInitialCheck] = useState(true);
    const [error, setError] = useState(''); 

    if (!userLoading && (!user || user.role !== UserRole.ADMIN)) {
        toast.error('Access denied. Only Admins can register CA Users.');
        navigate('/');
        return null;
    }

    if (userLoading || !user) {
        return (
            <Container maxWidth="lg" sx={{ mt: 4, display: 'flex', justifyContent: 'center', minHeight: '80vh' }}>
                <CircularProgress />
            </Container>
        );
    }
    
    if (user.role !== UserRole.ADMIN && isInitialCheck) {
        setIsInitialCheck(false);
        return null;
    }


    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        setError('');
    };

    const validateForm = (): boolean => {
        if (!formData.email.trim() || !formData.firstName.trim() || !formData.lastName.trim() || !formData.organization.trim()) {
            setError('All fields are required.');
            return false;
        }

        if (!/\S+@\S+\.\S+/.test(formData.email)) {
            setError('Invalid email format.');
            return false;
        }
        setError('');
        return true;
    };


    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!validateForm()) return;

        setLoading(true);

        try {
            await AuthService.registerCAUser(formData);

            toast.success(`CA User ${formData.email} successfully registered!`);
     
            setFormData({
                email: '',
                firstName: '',
                lastName: '',
                organization: '',
                password: 'InitialPassword123!',
                confirmPassword: 'InitialPassword123!',
            });
            
        } catch (error: any) {
            const errorMessage = error.message || 'CA User registration failed.';
            toast.error(errorMessage);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box 
            component="main" 
            sx={{ 
                minHeight: '100vh', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                p: 2 
            }}
        >
            <Paper elevation={6} sx={{ width: { xs: '100%', sm: 500, md: 550 }, p: 4, borderRadius: 2 }}>
                
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 3 }}>
                    <PersonAddAlt1Icon sx={{ fontSize: 40, color: 'primary.main', mb: 1 }} />
                    <Typography variant="h4" component="h1" gutterBottom align="center">
                        <strong>Register New CA User</strong>
                    </Typography>
                    <Typography variant="subtitle1" color="text.secondary" align="center">
                        Create a new Certificate Authority operator account.
                    </Typography>
                </Box>

                <Divider sx={{ my: 3 }} />

                <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    
                    <TextField
                        fullWidth
                        label="Email"
                        name="email"
                        type="email"
                        required
                        value={formData.email}
                        onChange={handleChange}
                        disabled={loading}
                        variant="outlined"
                    />

                    <Box sx={{ display: 'flex', gap: 3 }}>
                        <TextField
                            fullWidth
                            label="First Name"
                            name="firstName"
                            type="text"
                            required
                            value={formData.firstName}
                            onChange={handleChange}
                            disabled={loading}
                            variant="outlined"
                            sx={{ flex: 1 }} 
                        />
                        <TextField
                            fullWidth
                            label="Last Name"
                            name="lastName"
                            type="text"
                            required
                            value={formData.lastName}
                            onChange={handleChange}
                            disabled={loading}
                            variant="outlined"
                            sx={{ flex: 1 }}
                        />
                    </Box>

                    <TextField
                        fullWidth
                        label="Organization"
                        name="organization"
                        type="text"
                        required
                        value={formData.organization}
                        onChange={handleChange}
                        disabled={loading}
                        variant="outlined"
                    />
                    
                    {error && <Alert severity="error">{error}</Alert>}

                    <Alert severity="info" sx={{ mt: 1 }}>
                        The initial password is automatically generated by the system and sent to the user via email.
                    </Alert>

                    <Button
                        type="submit"
                        fullWidth
                        variant="contained"
                        color="primary"
                        sx={{ py: 1.5 }}
                        disabled={loading}
                        startIcon={loading ? <CircularProgress size={20} color="inherit" /> : null}
                    >
                        {loading ? 'Registering...' : 'Register CA User'}
                    </Button>
                </Box>
            </Paper>
        </Box>
    );
};

export default RegisterCAUserPage;