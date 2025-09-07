package com.bsep.pki.services;

import com.bsep.pki.models.Certificate;
import com.bsep.pki.repositories.CertificateRepository;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

@Service
public class RevocationService {
    @Autowired
    private CertificateRepository certificateRepository;

    public X509CRL generateCRL(PrivateKey caPrivateKey, X509Certificate caCert) throws Exception {
        List<Certificate> revokedCerts = certificateRepository.findByIsRevokedTrue();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                new JcaX509CertificateHolder(caCert).getSubject(), new Date()
        );
        crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000));
        for (Certificate cert : revokedCerts) {
            crlBuilder.addCRLEntry(
                    new BigInteger(cert.getSerialNumber()),
                    Date.from(cert.getRevokedAt().atZone(ZoneId.systemDefault()).toInstant()),
                    Integer.parseInt(cert.getRevokedReason().toString())
            );
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
        return new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
    }
}
