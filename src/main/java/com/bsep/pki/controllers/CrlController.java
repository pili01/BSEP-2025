package com.bsep.pki.controllers;

import com.bsep.pki.services.CertificateService;
import com.bsep.pki.services.RevocationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
    @Autowired
    private RevocationService revocationService;
    @Autowired
    private CertificateService certificateService;

    @GetMapping(produces = "application/pkix-crl")
    public ResponseEntity<byte[]> getCrl() throws Exception {
        AbstractMap.SimpleEntry<X509Certificate, PrivateKey> caCertWithPk = certificateService.getRootCertificateWithPk();
        X509CRL crl = revocationService.generateCRL(caCertWithPk.getValue(), caCertWithPk.getKey());

        return ResponseEntity.ok()
                .header("Content-Type", "application/pkix-crl")
                .header("Content-Disposition", "attachment; filename=\"ca.crl\"")
                .body(crl.getEncoded());
    }
}
