import React, { createContext, useContext, useState, useEffect, ReactNode, use } from 'react';
import AuthService from '../services/AuthService';
import { Navigate, useNavigate } from 'react-router-dom';
import { User, UserRole } from '../models/User';
import { useLocation } from 'react-router-dom';

interface UserContextType {
    user: User | null;
    setUser: (user: User | null) => void;
    logout: () => void;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

export const useUser = () => {
    const context = useContext(UserContext);
    if (!context) throw new Error('useUser must be used within a UserProvider');
    return context;
};

export const UserProvider = ({ children }: { children: ReactNode }) => {
    const [user, setUser] = useState<User | null>(null);
    const navigate = useNavigate();
    const location = useLocation();
    const pagesNotToRedirect = ['/login', '/sign-up', '/verify-email', '/2fa'];

    useEffect(() => {
        // Pokušaj učitati korisnika iz localStorage na mount
        console.log('Checking for existing user session...');
        AuthService.getMyInfo()
            .then((userData) => {
                if (localStorage.getItem('jwt'))
                    userData.token = localStorage.getItem('jwt');
                setUserAndStore(userData);
                // console.log('User session found:', userData);
                if (!pagesNotToRedirect.includes(location.pathname) && location.pathname !== '/generate-key') {
                    if (userData.role === UserRole.REGULAR_USER && (userData.publicKey == null || userData.publicKey === '')) {
                        console.log('No public key found, redirecting to key generation');
                        navigate('/generate-key');
                    }
                }
            })
            .catch(() => {
                if (pagesNotToRedirect.includes(location.pathname)) return;
                setUserAndStore(null);
                console.log('No valid session, redirecting to login');
                navigate('/login');
            });
        const stored = localStorage.getItem('user');
        if (stored) {
            setUser(JSON.parse(stored));
        }
        if (user && isTokenExpired(localStorage.getItem('jwt') || '')) {
            logout();
            setUser({ id: 0, email: '', firstName: '', lastName: '', organization: '', twoFactorEnabled: false } as User);
        }
    }, [location]);

    const setUserAndStore = (u: User | null) => {
        if (u) {
            // Prvo postavi u localStorage
            localStorage.setItem('user', JSON.stringify(u));
            // if (u.token) localStorage.setItem('jwt', u.token);
            setUser(u);
        } else {
            localStorage.removeItem('user');
            localStorage.removeItem('jwt');
            setUser(null);
            if (pagesNotToRedirect.includes(location.pathname)) return;
            navigate('/login');
        }
    };

    const logout = () => {
        setUserAndStore(null);
    };

    function isTokenExpired(token: string): boolean {
        if (!token) return true;
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (!payload.exp) return true;
        // exp je u sekundama od epohe
        const now = Math.floor(Date.now() / 1000);
        return payload.exp < now;
    }

    return (
        <UserContext.Provider value={{ user, setUser: setUserAndStore, logout }}>
            {children}
        </UserContext.Provider>
    );
};
