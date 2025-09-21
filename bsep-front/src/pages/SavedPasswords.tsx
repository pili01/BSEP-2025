import React, { useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Modal from '@mui/material/Modal';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import IconButton from '@mui/material/IconButton';
import PeopleIcon from '@mui/icons-material/People';
import ShareIcon from '@mui/icons-material/Share';
import VisibilityIcon from '@mui/icons-material/Visibility';
import AddCircleIcon from '@mui/icons-material/AddCircle';
import { PasswordShare, StoredPassword } from '../models/StoredPassword';
import { User } from '../models/User';
import PasswordService from '../services/PasswordService';
import { useUser } from '../context/UserContext';
import UserService from '../services/UserService';
import { CircularProgress } from '@mui/material';

type Props = {
    showSnackbar: (message: string, severity: 'success' | 'error' | 'info' | 'warning') => void;
};

const SavedPasswords: React.FC<Props> = ({ showSnackbar }) => {
    const [passwords, setPasswords] = useState<StoredPassword[]>([]);
    const [selectedPassword, setSelectedPassword] = useState<StoredPassword | null>(null);
    const [decryptedPassword, setDecryptedPassword] = useState<string | null>(null);
    const [showDecryptModal, setShowDecryptModal] = useState(false);
    const [decryptFile, setDecryptFile] = useState<File | null>(null);
    const [decryptLoading, setDecryptLoading] = useState(false);
    const [decryptError, setDecryptError] = useState('');
    const [decryptTarget, setDecryptTarget] = useState<StoredPassword | null>(null);
    const [showUsersModal, setShowUsersModal] = useState(false);
    const [showShareModal, setShowShareModal] = useState(false);
    const [users, setUsers] = useState<User[]>([]);
    const [usersForSharing, setUsersForSharing] = useState<User[]>([]);
    const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
    const [showAddModal, setShowAddModal] = useState(false);
    const [newSiteName, setNewSiteName] = useState('');
    const [newSiteUsername, setNewSiteUsername] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [showNewPassword, setShowNewPassword] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [loading, setLoading] = React.useState(false);
    const { user, setUser, logout } = useUser();
    const [showPassword, setShowPassword] = useState(false);
    const [decryptionPassword, setDecryptionPassword] = useState('');
    const [showPasswordInput, setShowPasswordInput] = useState(false);

    const fetchData = async () => {
        try {
            setLoading(true);
            const myPasswords = await PasswordService.getPasswords();
            const allUsers = await UserService.getAllUsers();
            setPasswords(myPasswords);
            setUsers(allUsers);
        } catch (error) {
            const errorMessage = (error instanceof Error && error.message) ? error.message : 'Unknown error';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const handleDecrypt = (password: StoredPassword) => {
        setDecryptTarget(password);
        setShowDecryptModal(true);
        setDecryptFile(null);
        setDecryptError('');
    };

    const handleDecryptSubmit = async () => {
        if (!decryptFile || !decryptTarget) {
            setDecryptError('Select private key file.');
            return;
        }
        setShowPasswordInput(true);
    };


    const decryptPassword = async () => {
        if (!decryptFile || !decryptTarget || !decryptionPassword) {
            setDecryptError('Select private key file, target password and enter decryption password.');
            return;
        }
        setShowPasswordInput(false);
        setDecryptLoading(true);
        setDecryptError('');
        try {
            setLoading(true);
            const encrypted = decryptTarget.shares.find(share => share.userId === user?.id)?.encryptedPassword;
            if (!encrypted) throw new Error('No encrypted password found.');
            const decrypted = await PasswordService.decryptWithPrivateKeyFile(decryptFile, encrypted, decryptionPassword);
            setDecryptedPassword(decrypted);
            setShowDecryptModal(false);
        } catch (err) {
            setDecryptError('Failed to decrypt password.');
        } finally {
            setDecryptLoading(false);
            setLoading(false);
        }
    };

    const handleShowUsers = (password: StoredPassword) => {
        setSelectedPassword(password);
        setShowUsersModal(true);
    };

    const handleShare = (password: StoredPassword) => {

        setSelectedPassword(password);
        const filteredUsers = users.filter(u => !password.shares.some(share => share.userId === u.id));
        setUsersForSharing(filteredUsers);
        setShowShareModal(true);
    };

    const handleShareSubmit = async () => {
        // TODO: Encrypt password for selectedUserId using njegov javni ključ
        // TODO: Pozvati backend da doda u sharedList
        alert(`Podijeli lozinku sa korisnikom ${selectedUserId}`);
        setShowShareModal(false);
    };

    const handleAddNewPassword = async () => {
        if (!newSiteName || !newSiteUsername || !newPassword) {
            showSnackbar('All fields are required', 'warning');
            return;
        }
        try {
            setLoading(true);
            const encryptedPass = await PasswordService.encryptWithPublicKey(user?.publicKey || '', newPassword);
            if (!encryptedPass) {
                showSnackbar('Failed to encrypt password', 'error');
                setLoading(false);
                return;
            }
            const passwordShare: PasswordShare = {
                encryptedPassword: encryptedPass
            }

            const newPasswordData: StoredPassword = {
                siteName: newSiteName,
                username: newSiteUsername,
                shares: [passwordShare],
            };

            const result = await PasswordService.addPassword(newPasswordData);
            if (result) {
                showSnackbar('Password added successfully', 'success');
                await fetchData();
                setShowAddModal(false);
                setNewSiteName('');
                setNewSiteUsername('');
                setNewPassword('');
            } else {
                showSnackbar('Failed to add password', 'error');
            }
        } catch (error) {
            const errorMessage = (error instanceof Error && error.message) ? error.message : 'Unknown error';
            showSnackbar(errorMessage, 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleSubmitDecryptionPassword = async () => {
        if (!decryptionPassword) {
            showSnackbar('Enter decryption password', 'warning');
            return;
        }
        setShowPasswordInput(false);
        await decryptPassword();
    };

    return (
        <Box component="main" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Paper elevation={4} sx={{ width: '80%', p: 4, borderRadius: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="h5" sx={{ fontWeight: 'bold' }}>Saved passwords</Typography>
                    <Button variant="contained" startIcon={<AddCircleIcon />} disabled={loading} onClick={() => setShowAddModal(true)}>
                        {loading ? <CircularProgress size={24} /> : 'Add new'}
                    </Button>
                </Box>
                <TableContainer component={Paper} sx={{ mb: 2 }}>
                    <Table>
                        <TableHead>
                            <TableRow>
                                <TableCell>Site</TableCell>
                                <TableCell>Username</TableCell>
                                <TableCell align="center">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {passwords.map((pw) => (
                                <TableRow key={pw.id}>
                                    <TableCell>{pw.siteName}</TableCell>
                                    <TableCell>{pw.username}</TableCell>
                                    <TableCell align="center">
                                        <IconButton color="primary" onClick={() => handleDecrypt(pw)} title="Show password">
                                            <VisibilityIcon />
                                        </IconButton>
                                        <IconButton color="info" onClick={() => handleShowUsers(pw)} title="Users">
                                            <PeopleIcon />
                                        </IconButton>
                                        <IconButton color="success" disabled={pw.ownerId !== user?.id} onClick={() => handleShare(pw)} title="Share">
                                            <ShareIcon />
                                        </IconButton>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>

                {/* Modal za korisnike */}
                <Modal open={showUsersModal} onClose={() => setShowUsersModal(false)}>
                    <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '70%', bgcolor: 'background.paper', boxShadow: 24, p: 4, borderRadius: 2 }}>
                        <Typography variant="h6" sx={{ mb: 2 }}>Users with access</Typography>
                        <ul style={{ paddingLeft: 18 }}>
                            {selectedPassword?.shares.map((user) => {
                                const userInfo = users.find(u => u.id === user.userId);
                                return (
                                    <li key={user.userId} style={{ marginBottom: 4, transform: 'scale(0.9)' }}>{userInfo?.firstName} {userInfo?.lastName} &nbsp; {userInfo?.email}</li>
                                );
                            })}
                        </ul>
                        <Button variant="contained" sx={{ mt: 2 }} onClick={() => setShowUsersModal(false)}>Close</Button>
                    </Box>
                </Modal>

                {/* Modal za dijeljenje */}
                <Modal open={showShareModal} onClose={() => setShowShareModal(false)}>
                    <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '70%', bgcolor: 'background.paper', boxShadow: 24, p: 4, borderRadius: 2 }}>
                        <Typography variant="h6" sx={{ mb: 2 }}>Share password</Typography>
                        <TextField
                            label="Search users"
                            value={searchTerm}
                            onChange={e => setSearchTerm(e.target.value)}
                            fullWidth
                            sx={{ mb: 2 }}
                        />
                        <ul style={{ paddingLeft: 0, maxHeight: 180, overflowY: 'auto', marginBottom: 16 }}>
                            {usersForSharing
                                .filter(user =>
                                    user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                                    (user.firstName?.toLowerCase().includes(searchTerm.toLowerCase()) ?? false) ||
                                    (user.lastName?.toLowerCase().includes(searchTerm.toLowerCase()) ?? false)
                                )
                                .map(user => (
                                    <li key={user.id} style={{ listStyle: 'none', marginBottom: 4 }}>
                                        <Button
                                            variant={selectedUserId === user.id ? 'contained' : 'text'}
                                            color="primary"
                                            fullWidth
                                            sx={{ textTransform: 'none', justifyContent: 'flex-start' }}
                                            onClick={() => user.id !== undefined && setSelectedUserId(user.id)}
                                        >
                                            {user.firstName} {user.lastName} &nbsp; <span style={{ color: '#555' }}>{user.email}</span>
                                        </Button>
                                    </li>
                                ))}
                        </ul>
                        <Button variant="contained" color="success" sx={{ mr: 1 }} onClick={handleShareSubmit} disabled={!selectedUserId}>Share</Button>
                        <Button variant="outlined" onClick={() => setShowShareModal(false)}>Close</Button>
                    </Box>
                </Modal>

                {/* Modal za dodavanje nove lozinke */}
                <Modal open={showAddModal} onClose={() => setShowAddModal(false)}>
                    <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '50%', bgcolor: 'background.paper', boxShadow: 24, p: 4, borderRadius: 2 }}>
                        <Typography variant="h6" sx={{ mb: 2 }}>Add new password</Typography>
                        <TextField
                            label="Site name"
                            value={newSiteName}
                            onChange={e => setNewSiteName(e.target.value)}
                            fullWidth
                            sx={{ mb: 2 }}
                        />
                        <TextField
                            label="Site username"
                            value={newSiteUsername}
                            onChange={e => setNewSiteUsername(e.target.value)}
                            fullWidth
                            sx={{ mb: 2 }}
                        />
                        <TextField
                            label="Password"
                            type={showNewPassword ? 'text' : 'password'}
                            value={newPassword}
                            onChange={e => setNewPassword(e.target.value)}
                            fullWidth
                            sx={{ mb: 1 }}
                        />
                        <Button
                            variant="text"
                            size="small"
                            sx={{ mb: 2, float: 'right' }}
                            onClick={() => setShowNewPassword((prev) => !prev)}
                        >
                            {showNewPassword ? 'Hide password' : 'Show password'}
                        </Button>
                        <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                            <Button
                                variant="contained"
                                color="primary"
                                disabled={loading}
                                onClick={() => {
                                    handleAddNewPassword();
                                }}
                            >{loading ? <CircularProgress size={24} /> : 'Add'}</Button>
                            <Button variant="outlined" onClick={() => setShowAddModal(false)}>Cancel</Button>
                        </Box>
                    </Box>
                </Modal>

                {/* Modal za izbor privatnog ključa i dešifrovanje */}
                <Modal open={showDecryptModal} onClose={() => setShowDecryptModal(false)}>
                    <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '80%', bgcolor: 'background.paper', boxShadow: 24, p: 4, borderRadius: 2 }}>
                        <Typography variant="h6" sx={{ mb: 2 }}>Choose private key file</Typography>
                        <input
                            type="file"
                            accept=".enc,.pem,.key,.txt"
                            onChange={e => setDecryptFile(e.target.files?.[0] || null)}
                            style={{ marginBottom: 16 }}
                        />
                        {decryptError && <Typography color="error" sx={{ mb: 2 }}>{decryptError}</Typography>}
                        <Button variant="contained" color="primary" onClick={handleDecryptSubmit} disabled={decryptLoading || !decryptFile}>
                            {decryptLoading ? 'Decrypting...' : 'Decrypt'}
                        </Button>
                        <Button variant="outlined" sx={{ ml: 2 }} onClick={() => setShowDecryptModal(false)}>Cancel</Button>
                    </Box>
                </Modal>

                {/* Prikaz dešifrovane lozinke */}
                <Modal open={!!decryptedPassword} onClose={() => setDecryptedPassword(null)}>
                    <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '30%', bgcolor: 'background.paper', boxShadow: 24, p: 4, borderRadius: 2, textAlign: 'center' }}>
                        <Typography variant="h6" sx={{ mb: 2 }}>Decrypted data</Typography>

                        <Typography variant="body1" sx={{ mb: 2,textAlign: 'left' }}><span style={{ minWidth: '100px', display: 'inline-block', alignSelf: 'flex-start' }}><strong>Site:</strong></span> <span style={{ color: '#2e7d32' }}>{decryptTarget?.siteName}</span></Typography>
                        <Typography variant="body1" sx={{ mb: 2,textAlign: 'left' }}><span style={{ minWidth: '100px', display: 'inline-block', alignSelf: 'flex-start' }}><strong>Username:</strong></span> <span style={{ color: '#2e7d32' }}>{decryptTarget?.username}</span></Typography>
                        <Typography variant="body1" sx={{ mb: 2,textAlign: 'left' }}><span style={{ minWidth: '100px', display: 'inline-block', alignSelf: 'flex-start' }}><strong>Password:</strong></span> <span style={{ color: '#2e7d32' }}>{decryptedPassword}</span></Typography>
                        <Button variant="contained" onClick={() => setDecryptedPassword(null)}>Close</Button>
                    </Box>
                </Modal>
                {/* Prikaz unosa lozinke */}
                <Modal open={!!showPasswordInput} onClose={() => setShowPasswordInput(false)}>
                    <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: 350, bgcolor: 'background.paper', boxShadow: 24, p: 4, borderRadius: 2, textAlign: 'center' }}>
                        <Typography variant="body1" align="center" sx={{ mb: 2 }}>
                            Enter a password to decrypt your private key.
                        </Typography>
                        <TextField
                            label="Password for Key Encryption"
                            type={showPassword ? 'text' : 'password'}
                            value={decryptionPassword}
                            onChange={e => setDecryptionPassword(e.target.value)}
                            fullWidth
                            sx={{ mb: 2 }}
                        />
                        <Button
                            variant="text"
                            size="small"
                            sx={{ alignSelf: 'flex-end', mb: 1 }}
                            onClick={() => setShowPassword((prev) => !prev)}
                        >
                            {showPassword ? 'Hide password' : 'Show password'}
                        </Button>
                        <Button variant="contained" color="primary" onClick={handleSubmitDecryptionPassword} disabled={loading}>
                            {loading ? <CircularProgress size={24} /> : 'Submit password'}
                        </Button>
                    </Box>
                </Modal>
            </Paper>
        </Box>
    );
};

export default SavedPasswords;
