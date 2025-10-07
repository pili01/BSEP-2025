import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Alert,
  Card,
  CardContent,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  CircularProgress,
  Chip,
} from '@mui/material';
import { CloudUpload, Description, Security, Schedule } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

interface Certificate {
  serialNumber: string;
  subjectName: string;
  organization: string;
  type: string;
  revoked: boolean;
  startDate: string;
  endDate: string;
  keyUsage: string;
  extendedKeyUsage: string;
}

const CreateCSR: React.FC = () => {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [validityInDays, setValidityInDays] = useState<string>('');
  const [selectedCA, setSelectedCA] = useState<Certificate | null>(null);
  const [intermediateCertificates, setIntermediateCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [maxValidityDays, setMaxValidityDays] = useState<number>(365);

  useEffect(() => {
    fetchIntermediateCertificates();
  }, []);

  const fetchIntermediateCertificates = async () => {
    try {
      const token = localStorage.getItem('jwt');
      if (!token) {
        setError('Authorization token is missing');
        return;
      }

      const response = await fetch('https://localhost:8443/api/certificates/intermediate/organization', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch intermediate certificates');
      }

      const certificates = await response.json();
      const filteredCertificates = certificates.filter((cert: Certificate) => !cert.revoked);
      setIntermediateCertificates(filteredCertificates);
    } catch (err) {
      setError('Error fetching intermediate certificates: ' + (err as Error).message);
    }
  };

  const calculateMaxValidityDays = (certificate: Certificate) => {
    const startDate = new Date(certificate.startDate);
    const endDate = new Date(certificate.endDate);
    const daysDiff = Math.floor((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));
    return Math.max(1, daysDiff);
  };

  const handleCAChange = (serialNumber: string) => {
    const certificate = intermediateCertificates.find(cert => cert.serialNumber === serialNumber);
    setSelectedCA(certificate || null);
    if (certificate) {
      const maxDays = calculateMaxValidityDays(certificate);
      setMaxValidityDays(maxDays);
      // Reset validity days if it exceeds the new maximum
      if (parseInt(validityInDays) > maxDays) {
        setValidityInDays(maxDays.toString());
      }
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      if (file.name.toLowerCase().endsWith('.pem')) {
        setSelectedFile(file);
        setError('');
      } else {
        setError('Please select a .pem file');
      }
    }
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    
    if (!selectedFile || !selectedCA || !validityInDays) {
      setError('Please fill in all fields');
      return;
    }

    const validityDaysNum = parseInt(validityInDays);
    if (validityDaysNum <= 0 || validityDaysNum > maxValidityDays) {
      setError(`Validity days must be between 1 and ${maxValidityDays}`);
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('jwt');
      if (!token) {
        throw new Error('Authorization token is missing');
      }

      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('validityInDays', validityInDays);
      formData.append('caIssuerSerialNumber', selectedCA.serialNumber);

      const response = await fetch('https://localhost:8443/api/certificates/csr/upload-file', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Failed to upload CSR');
      }

      const result = await response.text();
      setSuccess('CSR successfully uploaded and pending approval!');
      
      // Reset form
      setSelectedFile(null);
      setValidityInDays('');
      setSelectedCA(null);
      setMaxValidityDays(365);
      
      // Clear file input
      const fileInput = document.getElementById('file-upload') as HTMLInputElement;
      if (fileInput) {
        fileInput.value = '';
      }

    } catch (err) {
      setError('Error uploading CSR: ' + (err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4, mb: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center">
          Create CSR Request
        </Typography>
        <Typography variant="body1" color="text.secondary" align="center" sx={{ mb: 4 }}>
          Upload your Certificate Signing Request and select a CA to sign it
        </Typography>

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

        <Box component="form" onSubmit={handleSubmit}>
          <Grid container spacing={3}>
            {/* File Upload */}
            <Grid item xs={12}>
              <Card variant="outlined">
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <CloudUpload sx={{ mr: 1 }} />
                    <Typography variant="h6">Upload PEM File</Typography>
                  </Box>
                  <input
                    id="file-upload"
                    type="file"
                    accept=".pem"
                    onChange={handleFileChange}
                    style={{ display: 'none' }}
                  />
                  <Button
                    variant="outlined"
                    component="label"
                    startIcon={<Description />}
                    fullWidth
                    sx={{ mb: 2 }}
                  >
                    {selectedFile ? selectedFile.name : 'Choose PEM File'}
                    <input
                      type="file"
                      accept=".pem"
                      onChange={handleFileChange}
                      style={{ display: 'none' }}
                    />
                  </Button>
                  <Typography variant="caption" color="text.secondary">
                    Select your .pem certificate signing request file
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* CA Selection */}
            <Grid item xs={12}>
              <Card variant="outlined">
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <Security sx={{ mr: 1 }} />
                    <Typography variant="h6">Select Certificate Authority</Typography>
                  </Box>
                  <FormControl fullWidth>
                    <InputLabel>Choose CA</InputLabel>
                    <Select
                      value={selectedCA?.serialNumber || ''}
                      onChange={(e) => handleCAChange(e.target.value)}
                      label="Choose CA"
                    >
                      {intermediateCertificates.map((cert) => (
                        <MenuItem key={cert.serialNumber} value={cert.serialNumber}>
                          <Box>
                            <Typography variant="body1" fontWeight="bold">
                              {cert.subjectName}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              Serial: {cert.serialNumber}
                            </Typography>
                          </Box>
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  {selectedCA && (
                    <Box mt={2}>
                      <Typography variant="body2" color="text.secondary">
                        Selected CA: {selectedCA.subjectName}
                      </Typography>
                      <Box mt={1}>
                        <Chip label={selectedCA.type} size="small" sx={{ mr: 1 }} />
                        <Chip 
                          label={`Valid until: ${new Date(selectedCA.endDate).toLocaleDateString()}`} 
                          size="small" 
                          color="primary" 
                        />
                      </Box>
                      <Typography variant="caption" color="text.secondary" display="block" mt={1}>
                        Max validity: {maxValidityDays} days
                      </Typography>
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>

            {/* Validity Days */}
            <Grid item xs={12}>
              <Card variant="outlined">
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <Schedule sx={{ mr: 1 }} />
                    <Typography variant="h6">Certificate Validity</Typography>
                  </Box>
                  <TextField
                    fullWidth
                    label="Validity in Days"
                    type="number"
                    value={validityInDays}
                    onChange={(e) => setValidityInDays(e.target.value)}
                    inputProps={{ 
                      min: 1, 
                      max: maxValidityDays,
                      step: 1 
                    }}
                    helperText={`Enter validity period (1-${maxValidityDays} days based on selected CA)`}
                    disabled={!selectedCA}
                  />
                </CardContent>
              </Card>
            </Grid>

            {/* Submit Button */}
            <Grid item xs={12}>
              <Button
                type="submit"
                variant="contained"
                fullWidth
                size="large"
                disabled={loading || !selectedFile || !selectedCA || !validityInDays}
                startIcon={loading ? <CircularProgress size={20} /> : <CloudUpload />}
                sx={{ py: 2 }}
              >
                {loading ? 'Uploading...' : 'Upload CSR Request'}
              </Button>
            </Grid>
          </Grid>
        </Box>
      </Paper>
    </Container>
  );
};

export default CreateCSR;
