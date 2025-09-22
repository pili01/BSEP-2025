import { useContext, useEffect, useRef } from "react";
import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';
import { useUser } from "../context/UserContext";
import { Navigate } from "react-router-dom";
import { UserRole } from "../models/User";

interface ProtectedRouteProps {
    allowedRoles: UserRole[];
    children: React.ReactNode;
}

type Props = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

const ProtectedRoute: React.FC<ProtectedRouteProps & Props> = ({ allowedRoles, children, showSnackbar }) => {
    const { user, loading } = useUser();
    const notified = useRef(false);

    useEffect(() => {
        if (!loading) {
            if (!user && !notified.current) {
                showSnackbar("You need to log in first", "warning");
                notified.current = true;
            } else if (user && !allowedRoles.includes(user.role) && !notified.current) {
                showSnackbar("You do not have permission to access this page", "error");
                notified.current = true;
            }
        }
    }, [user, allowedRoles, showSnackbar, loading]);

    if (loading) {
        return (
            <Box sx={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', minHeight: '60vh' }}>
                <CircularProgress color="primary" size={60} thickness={5} />
                <Box sx={{ mt: 3, fontWeight: 'bold', fontSize: 24, color: 'primary.main', letterSpacing: 1 }}>
                    Loading...
                </Box>
            </Box>
        );
    }

    if (!user) {
        console.log('No user, redirecting to login');   
        return <Navigate to="/login" replace />;
    }

    if (!allowedRoles.includes(user.role)) {
        return <Navigate to="/" replace />;
    }

    return <>{children}</>;
};

export default ProtectedRoute;