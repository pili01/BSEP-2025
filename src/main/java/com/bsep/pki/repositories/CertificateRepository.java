package com.bsep.pki.repositories;

import com.bsep.pki.models.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    Optional<Certificate> findBySerialNumber(String serialNumber);
    Optional<Certificate> findByKeystorePath(String keystorePath);
}