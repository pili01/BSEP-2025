import React, { useEffect, useState } from 'react';
import { Box, Button, CircularProgress, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import SessionService from '../services/SessionService';
import { UserSession } from '../models/UserSession';
import { useUser } from '../context/UserContext';
interface SessionsPageProps {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
}

const SessionsPage: React.FC<SessionsPageProps> = ({ showSnackbar }) => {
    const { user } = useUser();
    const [sessions, setSessions] = useState<UserSession[]>([]);
    const [loading, setLoading] = useState<boolean>(true);
    const [revoking, setRevoking] = useState<string | null>(null);

    const fetchSessions = async () => {
        setLoading(true);
        try {
            const data = await SessionService.getUserSessions();
            setSessions(data);
        } catch (err: any) {
            console.error(err);
            showSnackbar(err.message || 'Failed to fetch sessions', 'error');
        } finally {
            setLoading(false);
        }
    };

    const revokeSession = async (jti: string) => {
        if (!window.confirm('Are you sure you want to revoke this session?')) return;
        setRevoking(jti);
        try {
            await SessionService.revokeSession(jti);
            setSessions(prev => prev.filter(s => s.jti !== jti));
            showSnackbar('Session revoked successfully', 'success');
        } catch (err: any) {
            console.error(err);
            showSnackbar(err.message || 'Failed to revoke session', 'error');
        } finally {
            setRevoking(null);
        }
    };

    useEffect(() => {
        fetchSessions();
    }, []);

    if (!user) return null; 

    return (
        <Box sx={{ p: 4 }}>
            <Typography variant="h4" gutterBottom>Session Management</Typography>

            {loading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
                    <CircularProgress size={60} />
                </Box>
            ) : (
                <TableContainer component={Paper} sx={{ mt: 3 }}>
                    <Table>
                        <TableHead>
                            <TableRow>
                                <TableCell>Device</TableCell>
                                <TableCell>IP Address</TableCell>
                                <TableCell>Created At</TableCell>
                                <TableCell>Last Activity</TableCell>
                                <TableCell>JTI</TableCell>
                                <TableCell>Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {sessions.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={6} align="center">No sessions found.</TableCell>
                                </TableRow>
                            )}
                            {sessions.map(s => (
                                <TableRow key={s.jti}>
                                    <TableCell>{s.device || 'Unknown'}</TableCell>
                                    <TableCell>{s.ipAddress || '-'}</TableCell>
                                    <TableCell>{new Date(s.createdAt).toLocaleString()}</TableCell>
                                    <TableCell>{s.lastActivity ? new Date(s.lastActivity).toLocaleString() : '-'}</TableCell>
                                    <TableCell>{s.jti}</TableCell>
                                    <TableCell>
                                        <Button
                                            variant="contained"
                                            color="error"
                                            size="small"
                                            onClick={() => revokeSession(s.jti)}
                                            disabled={revoking === s.jti}
                                        >
                                            {revoking === s.jti ? 'Revoking...' : 'Revoke'}
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            )}
        </Box>
    );
};

export default SessionsPage;
