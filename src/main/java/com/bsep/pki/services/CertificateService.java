package com.bsep.pki.services;

import com.bsep.pki.models.Certificate;
import com.bsep.pki.models.CertificateType;
import com.bsep.pki.repositories.CertificateRepository;
import jakarta.transaction.Transactional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Service
public class CertificateService {

    private static final String KEYSTORE_PATH = "src/main/resources/keystore/";
    private final CertificateRepository certificateRepository;

    @Value("${pki.keystore.password}")
    private String keystorePassword;

    @Autowired
    public CertificateService(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Transactional
    public X509Certificate issueCertificate(String commonName, String organization, long validityInDays, CertificateType type, Optional<String> issuerSerialNumber) throws Exception {

        KeyPair keyPair = generateKeyPair();

        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(validityInDays).atZone(ZoneId.systemDefault()).toInstant());

        if (type == CertificateType.ROOT) {
            return generateRootCertificate(keyPair, commonName, organization, validityInDays);
        } else {
            if (issuerSerialNumber.isEmpty()) {
                throw new IllegalArgumentException("Issuer serial number is required for non-root certificates.");
            }
            Optional<Certificate> issuerInfo = certificateRepository.findBySerialNumber(issuerSerialNumber.get());
            if (issuerInfo.isEmpty()) {
                throw new IllegalArgumentException("Issuer certificate not found.");
            }
            if (!isCertificateValid(issuerInfo.get())) {
                throw new IllegalArgumentException("Issuer certificate is not valid.");
            }
            if (isCertificateRevoked(issuerInfo.get())) {
                throw new IllegalArgumentException("Issuer certificate has been revoked.");
            }

            return generateSignedCertificate(keyPair, commonName, organization, validityInDays, type, issuerInfo.get());
        }
    }

    private X509Certificate generateRootCertificate(KeyPair keyPair, String commonName, String organization, long validityInDays) throws Exception {
        X500Name subjectName = new X500Name("CN=" + commonName + ", O=" + organization);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(validityInDays).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subjectName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                keyPair.getPublic()
        );

        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        saveToKeystore(certificate, keyPair.getPrivate(), organization, commonName, CertificateType.ROOT, new java.security.cert.Certificate[0]);

        Certificate certInfo = new Certificate();
        certInfo.setSerialNumber(certificate.getSerialNumber().toString());
        certInfo.setSubjectName(certificate.getSubjectX500Principal().getName());
        certInfo.setIssuerName(certificate.getIssuerX500Principal().getName());
        certInfo.setStartDate(now);
        certInfo.setEndDate(now.plusDays(validityInDays));
        certInfo.setRevoked(false);
        certInfo.setType(CertificateType.ROOT);
        certInfo.setOrganization(organization);
        certInfo.setKeystorePath(KEYSTORE_PATH + organization.replace(" ", "_") + ".jks");
        certInfo.setAlias(commonName);
        certInfo.setKeyUsage("keyCertSign, cRLSign");

        certificateRepository.save(certInfo);

        return certificate;
    }

    private X509Certificate generateSignedCertificate(KeyPair keyPair, String commonName, String organization, long validityInDays, CertificateType type, Certificate issuerInfo) throws Exception {

        KeyStore issuerKeystore = KeyStore.getInstance("JKS");
        issuerKeystore.load(new FileInputStream(issuerInfo.getKeystorePath()), keystorePassword.toCharArray());

        PrivateKey issuerPrivateKey = (PrivateKey) issuerKeystore.getKey(issuerInfo.getAlias(), keystorePassword.toCharArray());
        X509Certificate issuerCertificate = (X509Certificate) issuerKeystore.getCertificate(issuerInfo.getAlias());

        X500Name subjectName = new X500Name("CN=" + commonName + ", O=" + organization);
        X500Name issuerName = new X500Name(issuerInfo.getSubjectName());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(validityInDays).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                keyPair.getPublic()
        );

        if (type == CertificateType.INTERMEDIATE) {
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } else if (type == CertificateType.END_ENTITY) {
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerPrivateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));

        java.security.cert.Certificate[] issuerChain = issuerKeystore.getCertificateChain(issuerInfo.getAlias());
        saveToKeystore(certificate, keyPair.getPrivate(), organization, commonName, type, issuerChain);

        Certificate certInfo = new Certificate();
        certInfo.setSerialNumber(certificate.getSerialNumber().toString());
        certInfo.setSubjectName(certificate.getSubjectX500Principal().getName());
        certInfo.setIssuerName(certificate.getIssuerX500Principal().getName());
        certInfo.setStartDate(now);
        certInfo.setEndDate(now.plusDays(validityInDays));
        certInfo.setRevoked(false);
        certInfo.setType(type);
        certInfo.setOrganization(organization);
        certInfo.setKeystorePath(KEYSTORE_PATH + organization.replace(" ", "_") + ".jks");
        certInfo.setAlias(commonName);
        certInfo.setKeyUsage("keyCertSign, cRLSign");

        certificateRepository.save(certInfo);

        return certificate;
    }

    private void saveToKeystore(X509Certificate certificate, PrivateKey privateKey, String keystoreName, String alias, CertificateType type, java.security.cert.Certificate[] issuerChain) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        char[] passwordChars = keystorePassword.toCharArray();

        try {
            keyStore.load(new FileInputStream(KEYSTORE_PATH + keystoreName.replace(" ", "_") + ".jks"), passwordChars);
        } catch (IOException e) {
            keyStore.load(null, passwordChars);
        }

        java.security.cert.Certificate[] chain;
        if (type == CertificateType.ROOT) {
            chain = new java.security.cert.Certificate[1];
            chain[0] = certificate;
        } else {
            chain = new java.security.cert.Certificate[issuerChain.length + 1];
            chain[0] = certificate;
            System.arraycopy(issuerChain, 0, chain, 1, issuerChain.length);
        }

        keyStore.setKeyEntry(alias, privateKey, passwordChars, chain);

        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH + keystoreName.replace(" ", "_") + ".jks")) {
            keyStore.store(fos, passwordChars);
        }
    }

    private boolean isCertificateValid(Certificate certificateInfo) {
        LocalDateTime now = LocalDateTime.now();
        return !now.isBefore(certificateInfo.getStartDate()) && !now.isAfter(certificateInfo.getEndDate());
    }

    private boolean isCertificateRevoked(Certificate certificateInfo) {
        return certificateInfo.isRevoked();
    }
}