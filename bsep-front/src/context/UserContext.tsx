import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import AuthService from '../services/AuthService';
import { Navigate, useNavigate } from 'react-router-dom';
import { User, UserRole } from '../models/User'; 
import { useLocation } from 'react-router-dom';

interface UserContextType {
    user: User | null;
    setUser: (user: User | null) => void;
    logout: () => void;
    loading: boolean;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

export const useUser = () => {
    const context = useContext(UserContext);
    if (!context) throw new Error('useUser must be used within a UserProvider');
    return context;
};

interface JwtPayload {
    sub: string;
    iat: number;
    exp: number;
    jti: string;
    userId: number;
    role: string;
    organization: string;
    initialPassword: boolean; 
}

export const UserProvider = ({ children }: { children: ReactNode }) => {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();
    const location = useLocation();
    const pagesNotToRedirect = ['/login', '/sign-up', '/verify-email', '/2fa', '/change-initial-password','/forgot-password', '/reset-password']; // DODATO

    useEffect(() => {
        // Poziva se nakon što se korisnik setuje (ili nakon svakog rendera)
        checkUserData();
    }, [user]);

    const fetchUserData = async () => {
        setLoading(true);
        const token = localStorage.getItem('jwt') || '';
        const payload = decodeToken(token); // Parsiramo payload

        if (!token || isTokenExpired(payload)) {
            console.log('Token missing or expired, logging out');
            logout();
            setLoading(false);
            return;
        }

        await AuthService.getMyInfo()
            .then((userData) => {
                if (localStorage.getItem('jwt'))
                    userData.token = localStorage.getItem('jwt');

                // KLJUČNA IZMENA: Dodajemo claim iz JWT-a u User objekat
                userData.isInitialPassword = payload.initialPassword; 
                
                setUserAndStore(userData);
            })
            .catch(() => {
                if (pagesNotToRedirect.includes(location.pathname)) {
                    setLoading(false);
                    return;
                }
                setUserAndStore(null);
                console.log('No valid session, redirecting to login');
                navigate('/login');
            });
        setLoading(false);
    }

    const checkUserData = async () => {
        if (user && user.isInitialPassword && location.pathname !== '/change-initial-password') {
            console.log('Initial password required, redirecting to change password page');
            navigate('/change-initial-password');
            return; 
        }

        if (!pagesNotToRedirect.includes(location.pathname) && location.pathname !== '/generate-key') {
            if (user?.role === UserRole.REGULAR_USER && (user.publicKey == null || user.publicKey === '')) {
                console.log('No public key found, redirecting to key generation');
                navigate('/generate-key');
            }
        }
    }

    useEffect(() => {
        fetchUserData();
    }, [location.pathname]); // Promenjeno da se oslanja samo na promenu putanje, ne na celu lokaciju

    const setUserAndStore = (u: User | null) => {
        if (u) {
            console.log('Setting user and storing in localStorage:', u);
            localStorage.setItem('user', JSON.stringify(u));
            setUser(u);
        } else {
            localStorage.removeItem('user');
            localStorage.removeItem('jwt');
            setUser(null);
            if (pagesNotToRedirect.includes(location.pathname)) return;
            navigate('/login');
        }
    };

    const logout = async () => {
        try {
            await AuthService.logout(); 
        } catch (error) {
            console.warn('Backend logout failed:', error);
        }
        setUserAndStore(null);
    };

    function decodeToken(token: string): Partial<JwtPayload> {
        if (!token) return {};
        try {
            const payloadBase64 = token.split('.')[1];
            return JSON.parse(atob(payloadBase64));
        } catch (e) {
            console.error("Failed to decode JWT payload:", e);
            return {};
        }
    }

    function isTokenExpired(payload: Partial<JwtPayload>): boolean {
        if (!payload || !payload.exp) return true;
        // exp je u sekundama od epohe
        const now = Math.floor(Date.now() / 1000);
        return payload.exp < now;
    }

    return (
        <UserContext.Provider value={{ user, setUser: setUserAndStore, logout, loading }}>
            {children}
        </UserContext.Provider>
    );
};