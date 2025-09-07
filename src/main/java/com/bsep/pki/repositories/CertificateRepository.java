package com.bsep.pki.repositories;

import com.bsep.pki.models.Certificate;
import com.bsep.pki.models.CertificateType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    Optional<Certificate> findBySerialNumber(String serialNumber);
    Optional<Certificate> findByKeystorePath(String keystorePath);
    List<Certificate> findByOrganization(String organization);
    List<Certificate> findByOrganizationAndType(String organization, CertificateType type);
    List<Certificate> findByIssuerSerialNumber(String issuerSerialNumber);

    List<Certificate> findByIsRevokedTrue();
}