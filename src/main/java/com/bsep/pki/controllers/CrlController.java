package com.bsep.pki.controllers;

import com.bsep.pki.services.CertificateService;
import com.bsep.pki.services.RevocationService;
import jakarta.servlet.http.HttpServletRequest; // DODATO: Import za HttpServletRequest
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;

@RestController
@RequestMapping("/api/crl")
public class CrlController {

    private final Logger log = LogManager.getLogger(CrlController.class);

    @Autowired
    private RevocationService revocationService;
    @Autowired
    private CertificateService certificateService;

    @GetMapping(produces = "application/pkix-crl")
    public ResponseEntity<byte[]> getCrl(HttpServletRequest request) throws Exception {
        String ipAddress = request.getRemoteAddr();

        log.info("CRL generation and retrieval request received from IP: {}", ipAddress);
        log.debug("Attempting to retrieve Root CA Certificate and Private Key (Requested by IP: {}).", ipAddress);

        try {
            AbstractMap.SimpleEntry<X509Certificate, PrivateKey> caCertWithPk = certificateService.getRootCertificateWithPk();

            log.debug("Root CA Certificate retrieved. Generating CRL (Requested by IP: {}).", ipAddress);
            X509CRL crl = revocationService.generateCRL(caCertWithPk.getValue(), caCertWithPk.getKey());

            log.info("CRL successfully generated. Number of revoked entries: {} (Sent to IP: {}).",
                    crl.getRevokedCertificates() != null ? crl.getRevokedCertificates().size() : 0,
                    ipAddress);

            return ResponseEntity.ok()
                    .header("Content-Type", "application/pkix-crl")
                    .header("Content-Disposition", "attachment; filename=\"ca.crl\"")
                    .body(crl.getEncoded());
        } catch (Exception e) {
            log.error("CRL generation error for request from IP: {} - {}", ipAddress, e.getMessage(), e);
            throw e;
        }
    }
}