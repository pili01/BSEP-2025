import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Alert,
  Card,
  CardContent,
  Grid,
  Chip,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  Divider,
  TextField,
} from '@mui/material';
import { 
  Security, 
  Person, 
  CalendarToday, 
  Fingerprint, 
  CheckCircle, 
  Schedule,
  Description,
  Key,
  Email,
  Cancel
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

interface CsrResponseDto {
  id: number;
  commonName: string;
  organization: string;
  status: string;
  targetUserEmail: string;
  uploadingUserEmail: string;
  uploadDate: string;
  approvalDate?: string;
  rejectionReason?: string;
  publicKeyAlgorithm: string;
  keyLength?: number;
  keyUsage: string;
  extendedKeyUsage: string;
  validityInDays: number;
  caIssuerSerialNumber: string;
}

const CSRRequests: React.FC = () => {
  const navigate = useNavigate();
  const [csrRequests, setCsrRequests] = useState<CsrResponseDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [signingLoading, setSigningLoading] = useState<number | null>(null);
  const [rejectingLoading, setRejectingLoading] = useState<number | null>(null);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [selectedCsr, setSelectedCsr] = useState<CsrResponseDto | null>(null);
  const [signDialogOpen, setSignDialogOpen] = useState(false);
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [rejectReason, setRejectReason] = useState<string>('');

  useEffect(() => {
    fetchPendingCsrRequests();
  }, []);

  const fetchPendingCsrRequests = async () => {
    try {
      const token = localStorage.getItem('jwt');
      if (!token) {
        setError('Authorization token is missing');
        return;
      }

      const response = await fetch('https://localhost:8443/api/certificates/csr/pending', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch pending CSR requests');
      }

      const requests = await response.json();
      setCsrRequests(requests);
    } catch (err) {
      setError('Error fetching CSR requests: ' + (err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const fetchCsrDetails = async (id: number): Promise<CsrResponseDto | null> => {
    try {
      const token = localStorage.getItem('jwt');
      if (!token) {
        setError('Authorization token is missing');
        return null;
      }

      const response = await fetch(`https://localhost:8443/api/certificates/csr/${id}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch CSR details');
      }

      return await response.json();
    } catch (err) {
      setError('Error fetching CSR details: ' + (err as Error).message);
      return null;
    }
  };

  const handleSignCsr = async (csr: CsrResponseDto) => {
    setSelectedCsr(csr);
    setSignDialogOpen(true);
  };

  const handleRejectCsr = async (csr: CsrResponseDto) => {
    setSelectedCsr(csr);
    setRejectReason('');
    setRejectDialogOpen(true);
  };

  const confirmSignCsr = async () => {
    if (!selectedCsr) return;

    setSigningLoading(selectedCsr.id);
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('jwt');
      if (!token) {
        throw new Error('Authorization token is missing');
      }

      // Fetch full CSR details
      const fullCsrDetails = await fetchCsrDetails(selectedCsr.id);
      if (!fullCsrDetails) {
        throw new Error('Failed to fetch CSR details');
      }

      const signRequest = {
        csrPemContent: fullCsrDetails.csrPemContent,
        commonName: fullCsrDetails.commonName,
        targetUserEmail: fullCsrDetails.targetUserEmail,
        validityInDays: fullCsrDetails.validityInDays,
        organization: fullCsrDetails.organization,
        caIssuerSerialNumber: fullCsrDetails.caIssuerSerialNumber,
        keyUsage: fullCsrDetails.keyUsage,
        extendedKeyUsage: fullCsrDetails.extendedKeyUsage
      };

      const response = await fetch('https://localhost:8443/api/certificates/csr/sign', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(signRequest),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Failed to sign CSR');
      }

      const result = await response.text();
      setSuccess('CSR successfully signed and certificate issued!');
      
      // Refresh the list
      await fetchPendingCsrRequests();
      
    } catch (err) {
      setError('Error signing CSR: ' + (err as Error).message);
    } finally {
      setSigningLoading(null);
      setSignDialogOpen(false);
      setSelectedCsr(null);
    }
  };

  const confirmRejectCsr = async () => {
    if (!selectedCsr || !rejectReason.trim()) {
      setError('Please provide a reason for rejection');
      return;
    }

    setRejectingLoading(selectedCsr.id);
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('jwt');
      if (!token) {
        throw new Error('Authorization token is missing');
      }

      const response = await fetch(`https://localhost:8443/api/certificates/csr/${selectedCsr.id}/reject`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(rejectReason.trim()),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Failed to reject CSR');
      }

      const result = await response.text();
      setSuccess('CSR request rejected successfully!');
      
      // Refresh the list
      await fetchPendingCsrRequests();
      
    } catch (err) {
      setError('Error rejecting CSR: ' + (err as Error).message);
    } finally {
      setRejectingLoading(null);
      setRejectDialogOpen(false);
      setSelectedCsr(null);
      setRejectReason('');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'pending':
        return 'warning';
      case 'approved':
        return 'success';
      case 'rejected':
        return 'error';
      default:
        return 'default';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4, mb: 4, textAlign: 'center' }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 2 }}>
          Loading CSR requests...
        </Typography>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Box display="flex" alignItems="center" mb={3}>
          <Security sx={{ mr: 2, fontSize: 32 }} />
          <Box>
            <Typography variant="h4" component="h1">
              CSR Requests
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Manage and sign pending Certificate Signing Requests
            </Typography>
          </Box>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {success}
          </Alert>
        )}

        {csrRequests.length === 0 ? (
          <Box textAlign="center" py={4}>
            <Typography variant="h6" color="text.secondary">
              No pending CSR requests found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              All CSR requests have been processed or there are no requests in your organization
            </Typography>
          </Box>
        ) : (
          <Grid container spacing={3}>
            {csrRequests.map((csr) => (
              <Grid item xs={12} md={6} lg={4} key={csr.id}>
                <Card variant="outlined" sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                  <CardContent sx={{ flexGrow: 1 }}>
                    <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={2}>
                      <Typography variant="h6" component="h2" noWrap>
                        {csr.commonName}
                      </Typography>
                      <Chip 
                        label={csr.status.toUpperCase()} 
                        color={getStatusColor(csr.status) as any}
                        size="small"
                      />
                    </Box>

                    <Box mb={2}>
                      <Box display="flex" alignItems="center" mb={1}>
                        <Email sx={{ mr: 1, fontSize: 16, color: 'text.secondary' }} />
                        <Typography variant="body2" color="text.secondary" noWrap>
                          {csr.targetUserEmail}
                        </Typography>
                      </Box>
                      
                      <Box display="flex" alignItems="center" mb={1}>
                        <Person sx={{ mr: 1, fontSize: 16, color: 'text.secondary' }} />
                        <Typography variant="body2" color="text.secondary" noWrap>
                          Uploaded by: {csr.uploadingUserEmail}
                        </Typography>
                      </Box>

                      <Box display="flex" alignItems="center" mb={1}>
                        <CalendarToday sx={{ mr: 1, fontSize: 16, color: 'text.secondary' }} />
                        <Typography variant="body2" color="text.secondary">
                          {formatDate(csr.uploadDate)}
                        </Typography>
                      </Box>

                      <Box display="flex" alignItems="center" mb={1}>
                        <Schedule sx={{ mr: 1, fontSize: 16, color: 'text.secondary' }} />
                        <Typography variant="body2" color="text.secondary">
                          Validity: {csr.validityInDays} days
                        </Typography>
                      </Box>

                      <Box display="flex" alignItems="center" mb={1}>
                        <Fingerprint sx={{ mr: 1, fontSize: 16, color: 'text.secondary' }} />
                        <Typography variant="body2" color="text.secondary">
                          {csr.publicKeyAlgorithm} {csr.keyLength ? `(${csr.keyLength} bits)` : ''}
                        </Typography>
                      </Box>
                    </Box>

                    <Box mb={2}>
                      <Typography variant="caption" color="text.secondary" display="block">
                        Key Usage:
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        {csr.keyUsage || 'Not specified'}
                      </Typography>
                      
                      <Typography variant="caption" color="text.secondary" display="block">
                        Extended Key Usage:
                      </Typography>
                      <Typography variant="body2">
                        {csr.extendedKeyUsage || 'Not specified'}
                      </Typography>
                    </Box>
                  </CardContent>

                  <Box p={2} pt={0}>
                    <Box display="flex" gap={1}>
                      <Button
                        variant="contained"
                        fullWidth
                        startIcon={signingLoading === csr.id ? <CircularProgress size={20} /> : <CheckCircle />}
                        onClick={() => handleSignCsr(csr)}
                        disabled={signingLoading === csr.id || rejectingLoading === csr.id || csr.status.toLowerCase() !== 'pending'}
                        color="success"
                        size="small"
                      >
                        {signingLoading === csr.id ? 'Signing...' : 'Sign'}
                      </Button>
                      <Button
                        variant="contained"
                        fullWidth
                        startIcon={rejectingLoading === csr.id ? <CircularProgress size={20} /> : <Cancel />}
                        onClick={() => handleRejectCsr(csr)}
                        disabled={signingLoading === csr.id || rejectingLoading === csr.id || csr.status.toLowerCase() !== 'pending'}
                        color="error"
                        size="small"
                      >
                        {rejectingLoading === csr.id ? 'Rejecting...' : 'Reject'}
                      </Button>
                    </Box>
                  </Box>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </Paper>

      {/* Sign Confirmation Dialog */}
      <Dialog open={signDialogOpen} onClose={() => setSignDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          <Box display="flex" alignItems="center">
            <CheckCircle sx={{ mr: 1, color: 'success.main' }} />
            Confirm CSR Signing
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedCsr && (
            <Box>
              <Typography variant="body1" paragraph>
                Are you sure you want to sign this Certificate Signing Request?
              </Typography>
              
              <List dense>
                <ListItem>
                  <ListItemText 
                    primary="Common Name" 
                    secondary={selectedCsr.commonName}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Target User" 
                    secondary={selectedCsr.targetUserEmail}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Organization" 
                    secondary={selectedCsr.organization}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Validity Period" 
                    secondary={`${selectedCsr.validityInDays} days`}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Key Usage" 
                    secondary={selectedCsr.keyUsage || 'Not specified'}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Extended Key Usage" 
                    secondary={selectedCsr.extendedKeyUsage || 'Not specified'}
                  />
                </ListItem>
              </List>
              
              <Alert severity="warning" sx={{ mt: 2 }}>
                This action will issue a new certificate. Please ensure all information is correct before proceeding.
              </Alert>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSignDialogOpen(false)}>
            Cancel
          </Button>
          <Button 
            onClick={confirmSignCsr} 
            variant="contained" 
            color="success"
            disabled={signingLoading !== null}
          >
            {signingLoading !== null ? 'Signing...' : 'Sign CSR'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Reject Confirmation Dialog */}
      <Dialog open={rejectDialogOpen} onClose={() => setRejectDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box display="flex" alignItems="center">
            <Cancel sx={{ mr: 1, color: 'error.main' }} />
            Reject CSR Request
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedCsr && (
            <Box>
              <Typography variant="body1" paragraph>
                Are you sure you want to reject this Certificate Signing Request?
              </Typography>
              
              <Box mb={2}>
                <Typography variant="subtitle2" gutterBottom>
                  Request Details:
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  <strong>Common Name:</strong> {selectedCsr.commonName}<br/>
                  <strong>Target User:</strong> {selectedCsr.targetUserEmail}<br/>
                  <strong>Organization:</strong> {selectedCsr.organization}
                </Typography>
              </Box>

              <TextField
                fullWidth
                multiline
                rows={4}
                label="Reason for rejection"
                placeholder="Please provide a reason for rejecting this CSR request..."
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                required
                error={!rejectReason.trim() && rejectReason.length > 0}
                helperText={!rejectReason.trim() && rejectReason.length > 0 ? "Please provide a reason" : ""}
              />
              
              <Alert severity="warning" sx={{ mt: 2 }}>
                This action cannot be undone. The CSR request will be permanently rejected.
              </Alert>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRejectDialogOpen(false)}>
            Cancel
          </Button>
          <Button 
            onClick={confirmRejectCsr} 
            variant="contained" 
            color="error"
            disabled={rejectingLoading !== null || !rejectReason.trim()}
          >
            {rejectingLoading !== null ? 'Rejecting...' : 'Reject CSR'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default CSRRequests;
