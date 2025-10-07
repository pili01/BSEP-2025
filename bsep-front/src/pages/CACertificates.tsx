import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Card,
  CardContent,
  CircularProgress,
  Alert,
  Box,
  Chip,
  Divider,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  SelectChangeEvent
} from '@mui/material';
import Assignment from '@mui/icons-material/Assignment';
import Download from '@mui/icons-material/Download';
import Block from '@mui/icons-material/Block';
import CertificateService from '../services/CertificateService';

interface CertificateData {
  serialNumber: string;
  subjectName: string;
  organization: string;
  type: string;
  issuerSerialNumber: string | null;
  startDate: string;
  endDate: string;
  revoked: boolean;
  keyUsage: string;
  extendedKeyUsage: string;
  issuerName: string;
}

// X.509 revocation reasons
const REVOCATION_REASONS = [
  { value: 'UNSPECIFIED', label: 'Unspecified' },
  { value: 'KEY_COMPROMISE', label: 'Key Compromise' },
  { value: 'CA_COMPROMISE', label: 'CA Compromise' },
  { value: 'AFFILIATION_CHANGED', label: 'Affiliation Changed' },
  { value: 'SUPERSEDED', label: 'Superseded' },
  { value: 'CESSATION_OF_OPERATION', label: 'Cessation of Operation' },
  { value: 'CERTIFICATE_HOLD', label: 'Certificate Hold' },
  { value: 'PRIVILEGE_WITHDRAWN', label: 'Privilege Withdrawn' },
  { value: 'AA_COMPROMISE', label: 'AA Compromise' }
];

const CACertificates: React.FC = () => {
  const [certificates, setCertificates] = useState<CertificateData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const [selectedCertificate, setSelectedCertificate] = useState<string | null>(null);
  const [revocationReason, setRevocationReason] = useState<string>('');
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    fetchCertificateChain();
  }, []);

  const fetchCertificateChain = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('jwt');

      if (!token) {
        setError('No authentication token found');
        return;
      }

      const response = await fetch('https://localhost:8443/api/certificates/ca/chain', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch certificate chain: ${errorText}`);
      }

      const data = await response.json();
      setCertificates(data);
    } catch (err) {
      console.error('Error fetching certificate chain:', err);
      setError(err instanceof Error ? err.message : 'An error occurred while fetching certificate chain');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (isRevoked: boolean, endDate: string) => {
    if (isRevoked) return 'warning';
    const now = new Date();
    const validUntil = new Date(endDate);
    if (validUntil < now) return 'error';
    return 'success';
  };

  const getStatusText = (isRevoked: boolean, endDate: string) => {
    if (isRevoked) return 'Revoked';
    const now = new Date();
    const validUntil = new Date(endDate);
    if (validUntil < now) return 'Expired';
    return 'Valid';
  };

  const getCertificateTypeColor = (type: string) => {
    if (!type) return 'default';
    switch (type.toLowerCase()) {
      case 'root':
        return 'primary';
      case 'intermediate':
        return 'secondary';
      case 'end_entity':
        return 'info';
      default:
        return 'default';
    }
  };

  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('sr-RS') + ' ' + date.toLocaleTimeString('sr-RS');
    } catch {
      return dateString;
    }
  };

  const parseSubjectName = (subjectName: string) => {
    if (!subjectName) return 'Unknown';

    // If it contains OID format, try to extract readable parts
    if (subjectName.includes('1.2.840.113549.1.9.1')) {
      // Extract CN if available
      const cnMatch = subjectName.match(/CN=([^,]+)/);
      if (cnMatch) return cnMatch[1];

      // Extract O if available  
      const oMatch = subjectName.match(/O=([^,]+)/);
      if (oMatch) return oMatch[1];

      return 'Email Certificate';
    }

    // Extract CN from normal format
    const cnMatch = subjectName.match(/CN=([^,]+)/);
    if (cnMatch) return cnMatch[1];

    return subjectName;
  };

  const handleRevokeClick = (serialNumber: string) => {
    setSelectedCertificate(serialNumber);
    setRevokeModalOpen(true);
    setRevocationReason('');
  };

  const handleRevokeConfirm = async () => {
    if (!selectedCertificate || !revocationReason) {
      alert('Please select a revocation reason');
      return;
    }

    try {
      setRevoking(true);
      await CertificateService.revokeCertificate(selectedCertificate, revocationReason);

      // Refresh certificates list
      await fetchCertificateChain();

      setRevokeModalOpen(false);
      setSelectedCertificate(null);
      setRevocationReason('');
      alert('Certificate revoked successfully');
    } catch (error) {
      console.error('Error revoking certificate:', error);
      alert('Failed to revoke certificate: ' + (error as Error).message);
    } finally {
      setRevoking(false);
    }
  };

  const handleRevokeCancel = () => {
    setRevokeModalOpen(false);
    setSelectedCertificate(null);
    setRevocationReason('');
  };

  const handleReasonChange = (event: SelectChangeEvent<string>) => {
    setRevocationReason(event.target.value);
  };

  const handleDownload = async (serialNumber: string) => {
    try {
      const token = localStorage.getItem('jwt');
      if (!token) {
        alert('No authentication token found');
        return;
      }

      const response = await fetch(`https://localhost:8443/api/certificates/download/${serialNumber}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        const errorText = await response.text();

        // Handle specific error for CA users trying to download Root certificates
        if (errorText.includes('CA users cannot download Root certificates')) {
          alert('CA users cannot download Root certificates from their organization chain.');
          return;
        }

        throw new Error(`Download failed: ${errorText}`);
      }

      // Get filename from Content-Disposition header or use default
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = `certificate_${serialNumber}`;

      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Get content type to determine file extension
      const contentType = response.headers.get('Content-Type') || 'application/octet-stream';

      // Add proper extension based on content type
      if (contentType.includes('application/zip')) {
        if (!filename.endsWith('.zip')) {
          filename += '.zip';
        }
      } else if (contentType.includes('application/octet-stream') || contentType.includes('text/plain')) {
        // For PEM files, add .pem extension if not already present
        if (!filename.endsWith('.pem') && !filename.endsWith('.zip')) {
          filename += '.pem';
        }
      }

      // Create blob with proper MIME type
      const blob = new Blob([await response.arrayBuffer()], { type: contentType });

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

    } catch (error) {
      console.error('Download error:', error);
      alert(`Failed to download certificate: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4, display: 'flex', justifyContent: 'center' }}>
        <CircularProgress />
      </Container>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Alert severity="error">{error}</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ mb: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Assignment sx={{ fontSize: 40, color: 'secondary.main' }} />
        <Typography variant="h4" component="h1" gutterBottom>
          Certificate Chain
        </Typography>
      </Box>

      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        View certificates from your organization's certificate chain
      </Typography>

      {certificates.length === 0 ? (
        <Alert severity="info">No certificates found in your certificate chain.</Alert>
      ) : (
        <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 3 }}>
          {certificates.map((cert) => (
            <Card key={cert.serialNumber} sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flexGrow: 1 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                  <Typography variant="h6" component="h2" gutterBottom>
                    {parseSubjectName(cert.subjectName)}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <Chip
                      label={getStatusText(cert.revoked, cert.endDate)}
                      color={getStatusColor(cert.revoked, cert.endDate) as any}
                      size="small"
                    />
                    {cert.type === 'ROOT' ? (
                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={<Download />}
                        disabled={true}
                        title="CA users cannot download Root certificates from their organization chain"
                      >
                        DOWNLOAD
                      </Button>
                    ) : (
                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={<Download />}
                        onClick={() => handleDownload(cert.serialNumber)}
                        disabled={cert.revoked}
                      >
                        Download
                      </Button>
                    )}
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'flex-start', mb: 2 }}>
                  <Button
                    variant="contained"
                    color="error"
                    size="small"
                    startIcon={<Block />}
                    onClick={() => handleRevokeClick(cert.serialNumber)}
                    disabled={cert.revoked}
                  >
                    Revoke
                  </Button>
                </Box>

                <Typography variant="body2" color="text.secondary" gutterBottom>
                  <strong>Organization:</strong> {cert.organization}
                </Typography>

                <Typography variant="body2" color="text.secondary" gutterBottom>
                  <strong>Serial Number:</strong> {cert.serialNumber}
                </Typography>

                <Typography variant="body2" color="text.secondary" gutterBottom>
                  <strong>Type:</strong>
                  <Chip
                    label={cert.type}
                    color={getCertificateTypeColor(cert.type) as any}
                    size="small"
                    sx={{ ml: 1 }}
                  />
                </Typography>

                {cert.issuerSerialNumber && (
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    <strong>Issuer Serial:</strong> {cert.issuerSerialNumber}
                  </Typography>
                )}

                <Typography variant="body2" color="text.secondary" gutterBottom>
                  <strong>Issuer:</strong> {cert.issuerName}
                </Typography>

                <Divider sx={{ my: 2 }} />

                <Typography variant="body2" color="text.secondary" gutterBottom>
                  <strong>Valid From:</strong> {formatDate(cert.startDate)}
                </Typography>

                <Typography variant="body2" color="text.secondary" gutterBottom>
                  <strong>Valid Until:</strong> {formatDate(cert.endDate)}
                </Typography>

                {cert.keyUsage && (
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    <strong>Key Usage:</strong> {cert.keyUsage}
                  </Typography>
                )}

                {cert.extendedKeyUsage && (
                  <Typography variant="body2" color="text.secondary">
                    <strong>Extended Key Usage:</strong> {cert.extendedKeyUsage}
                  </Typography>
                )}
              </CardContent>
            </Card>
          ))}
        </Box>
      )}

      {/* Revoke Certificate Modal */}
      <Dialog open={revokeModalOpen} onClose={handleRevokeCancel} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Block color="error" />
            Revoke Certificate
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            Are you sure you want to revoke certificate <strong>{selectedCertificate}</strong>?
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mb: 3 }}>
            This action cannot be undone. Please select a revocation reason.
          </Typography>

          <FormControl fullWidth>
            <InputLabel id="revocation-reason-label">Revocation Reason</InputLabel>
            <Select
              labelId="revocation-reason-label"
              value={revocationReason}
              onChange={handleReasonChange}
              label="Revocation Reason"
            >
              {REVOCATION_REASONS.map((reason) => (
                <MenuItem key={reason.value} value={reason.value}>
                  {reason.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleRevokeCancel} disabled={revoking}>
            Cancel
          </Button>
          <Button
            onClick={handleRevokeConfirm}
            color="error"
            variant="contained"
            disabled={!revocationReason || revoking}
          >
            {revoking ? <CircularProgress size={20} /> : 'Revoke Certificate'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default CACertificates;
