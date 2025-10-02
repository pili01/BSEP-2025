import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../context/UserContext';
import AuthService from '../services/AuthService';
import { toast } from 'react-toastify'; 


const ChangeInitialPasswordPage: React.FC = () => {
    const { user, setUser, loading: userLoading } = useUser();
    const navigate = useNavigate();

    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);

    if (!userLoading && user && !user.isInitialPassword) {
        navigate('/');
        return null;
    }

    if (userLoading || !user) {
        return <div className="text-center p-5">Loading user data...</div>;
    }

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);

        if (newPassword !== confirmPassword) {
            toast.error('New password and confirmation password do not match.');
            setLoading(false);
            return;
        }

        if (!newPassword) {
             toast.error('New password cannot be empty.');
             setLoading(false);
             return;
        }

        try {
            const response = await AuthService.changeInitialPassword({
                newPassword: newPassword,
            });

            const newToken = response.token; 

            localStorage.setItem('jwt', newToken);

            const updatedUser = {
                ...user,
                token: newToken,
                isInitialPassword: false,
            };
            setUser(updatedUser);

            toast.success('Password successfully changed! Welcome.');
            navigate('/');
            
        } catch (error: any) {
            const errorMessage = error?.response?.data?.message || 'Failed to change password. Please try again.';
            toast.error(errorMessage);
            setNewPassword('');
            setConfirmPassword('');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-100">
            <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-lg shadow-xl border border-red-500">
                <h2 className="text-3xl font-bold text-center text-red-600">
                    🔒 Initial Password Required
                </h2>
                <p className="text-center text-gray-600">
                    As a **CA User**, you must change your initial password for security reasons.
                </p>

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-700">New Password</label>
                        <input
                            type="password"
                            required
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            className="w-full p-3 mt-1 border border-gray-300 rounded-md focus:ring-red-500 focus:border-red-500"
                            placeholder="Enter new secure password"
                            autoComplete="new-password"
                            disabled={loading}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Confirm New Password</label>
                        <input
                            type="password"
                            required
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            className="w-full p-3 mt-1 border border-gray-300 rounded-md focus:ring-red-500 focus:border-red-500"
                            placeholder="Confirm new password"
                            autoComplete="new-password"
                            disabled={loading}
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full py-3 text-lg font-semibold text-white bg-red-600 rounded-md hover:bg-red-700 focus:outline-none focus:ring-4 focus:ring-red-500 focus:ring-opacity-50 transition duration-150 ease-in-out disabled:opacity-50"
                    >
                        {loading ? 'Changing...' : 'Change Password'}
                    </button>
                </form>
            </div>
        </div>
    );
};

export default ChangeInitialPasswordPage;