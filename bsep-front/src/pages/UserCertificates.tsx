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
  Divider
} from '@mui/material';
import Assignment from '@mui/icons-material/Assignment';

interface CertificateData {
  serialNumber: string;
  subjectName: string;
  organization: string;
  type: string;
  issuerSerialNumber: string | null;
  startDate: string;
  endDate: string;
  isRevoked: boolean;
  keyUsage: string;
  extendedKeyUsage: string;
  issuerName: string;
}

const UserCertificates: React.FC = () => {
  const [certificates, setCertificates] = useState<CertificateData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMyCertificates();
  }, []);

  const fetchMyCertificates = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('jwt');
      
      if (!token) {
        setError('No authentication token found');
        return;
      }

      const response = await fetch('https://localhost:8443/api/certificates/user/my', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch my certificates: ${errorText}`);
      }

      const data = await response.json();
      setCertificates(data);
    } catch (err) {
      console.error('Error fetching my certificates:', err);
      setError(err instanceof Error ? err.message : 'An error occurred while fetching my certificates');
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
        <Assignment sx={{ fontSize: 40, color: 'primary.main' }} />
        <Typography variant="h4" component="h1" gutterBottom>
          My Certificates
        </Typography>
      </Box>

      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        View and manage your End-Entity certificates
      </Typography>

      {certificates.length === 0 ? (
        <Alert severity="info">You don't have any certificates yet. Create a CSR request to get your first certificate.</Alert>
      ) : (
        <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 3 }}>
          {certificates.map((cert) => (
            <Card key={cert.id} sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flexGrow: 1 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                  <Typography variant="h6" component="h2" gutterBottom>
                    {parseSubjectName(cert.subjectName)}
                  </Typography>
                  <Chip
                    label={getStatusText(cert.isRevoked, cert.endDate)}
                    color={getStatusColor(cert.isRevoked, cert.endDate) as any}
                    size="small"
                  />
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
    </Container>
  );
};

export default UserCertificates;
