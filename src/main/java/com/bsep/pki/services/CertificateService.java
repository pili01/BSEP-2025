package com.bsep.pki.services;

import com.bsep.pki.dtos.CertificateRequestDto;
import com.bsep.pki.dtos.CsrRequestDto;
import com.bsep.pki.dtos.CsrResponseDto;
import com.bsep.pki.models.Certificate;
import com.bsep.pki.models.*;
import com.bsep.pki.repositories.CertificateRepository;
import com.bsep.pki.repositories.CertificateTemplateRepository;
import com.bsep.pki.repositories.CsrRequestRepository;
import jakarta.transaction.Transactional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class CertificateService {

    private static final String KEYSTORE_PATH = "src/main/resources/keystore/";
    private final CertificateRepository certificateRepository;
    private final CertificateTemplateRepository certificateTemplateRepository;
    private final KeystoreEncryptionService encryptionService;
    private final CsrRequestRepository csrRequestRepository;
    private final UserService userService;

    @Autowired
    public CertificateService(CertificateRepository certificateRepository,
                              CertificateTemplateRepository certificateTemplateRepository,
                              KeystoreEncryptionService encryptionService,
                              CsrRequestRepository csrRequestRepository,
                              UserService userService) {
        this.certificateRepository = certificateRepository;
        this.certificateTemplateRepository = certificateTemplateRepository;
        this.encryptionService = encryptionService;
        this.csrRequestRepository = csrRequestRepository;
        this.userService = userService;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Transactional
    public X509Certificate issueCertificate(CertificateRequestDto requestDto, User issuingUser, User targetUser) throws Exception {
        Optional<CertificateTemplate> optionalTemplate = Optional.empty();
        if (requestDto.getTemplateId().isPresent()) {
            optionalTemplate = certificateTemplateRepository.findById(requestDto.getTemplateId().get());
            if (optionalTemplate.isEmpty()) {
                throw new IllegalArgumentException("Template with provided ID not found.");
            }
        }

        if (optionalTemplate.isPresent()) {
            CertificateTemplate template = optionalTemplate.get();
            if (template.getCommonNameRegex() != null && !template.getCommonNameRegex().isEmpty()
                    && !Pattern.matches(template.getCommonNameRegex(), requestDto.getCommonName())) {
                throw new IllegalArgumentException("Common Name does not match template regex.");
            }
            if (requestDto.getValidityInDays() > template.getMaxValidityDays()) {
                throw new IllegalArgumentException("Validity period exceeds template maximum of "
                        + template.getMaxValidityDays() + " days.");
            }
        }

        if (requestDto.getType() == CertificateType.ROOT) {
            return generateRootCertificate(requestDto, optionalTemplate, targetUser);
        } else {
            if (requestDto.getIssuerSerialNumber().isEmpty()) {
                throw new IllegalArgumentException("Issuer serial number is required for non-root certificates.");
            }
            Optional<Certificate> issuerInfo = certificateRepository.findBySerialNumber(
                    requestDto.getIssuerSerialNumber().get());
            if (issuerInfo.isEmpty()) {
                throw new IllegalArgumentException("Issuer certificate not found.");
            }
            if (issuerInfo.get().getKeystorePassword() == null) {
                throw new IllegalArgumentException("Cannot issue a certificate from a non-CA certificate.");
            }

            validateCertificateChain(issuerInfo.get(), 1);

            if (!isCertificateValid(issuerInfo.get())) {
                throw new IllegalArgumentException("Issuer certificate is not valid.");
            }
            if (isCertificateRevoked(issuerInfo.get())) {
                throw new IllegalArgumentException("Issuer certificate has been revoked.");
            }

            Certificate issuerCertificate = issuerInfo.get();
            if (!issuerCertificate.getUser().equals(issuingUser) && issuingUser.getRole() != UserRole.ADMIN) {
                throw new SecurityException("You are not authorized to use this certificate as an issuer.");
            }

            checkIssuerPolicy(requestDto, optionalTemplate, issuerInfo.get());

            if (requestDto.getType() == CertificateType.INTERMEDIATE) {
                return generateIntermediateCertificate(requestDto, issuerInfo.get(), optionalTemplate, targetUser);
            } else {
                return generateEndEntityCertificate(requestDto, issuerInfo.get(), optionalTemplate, targetUser);
            }
        }
    }

    private X509Certificate generateRootCertificate(CertificateRequestDto requestDto,
                                                    Optional<CertificateTemplate> optionalTemplate,
                                                    User targetUser) throws Exception {
        KeyPair keyPair = generateKeyPair();
        X500Name subjectName = new X500Name("CN=" + requestDto.getCommonName()
                + ", O=" + requestDto.getOrganization());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(requestDto.getValidityInDays())
                .atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subjectName, serialNumber, startDate, endDate, subjectName, keyPair.getPublic()
        );

        addExtensionsToBuilder(certBuilder, requestDto, optionalTemplate, true);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(signer));

        String keystorePassword = generateRandomPassword();
        String encryptedPassword = encryptionService.encrypt(keystorePassword, targetUser.getEncryptionKey());

        // Root sertifikat - samo on sa privatnim ključem
        java.security.cert.Certificate[] rootChain = new java.security.cert.Certificate[1];
        rootChain[0] = certificate;

        String keystorePath = KEYSTORE_PATH + serialNumber.toString() + ".jks";
        saveToKeystore(certificate, keyPair.getPrivate(), requestDto.getCommonName(),
                rootChain, keystorePath, keystorePassword);

        List<String> keyUsageListFromTemplate = optionalTemplate.map(CertificateTemplate::getKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(new ArrayList<>());
        List<String> keyUsageListFromDto = requestDto.getKeyUsage();
        List<String> finalKeyUsageList = new ArrayList<>(keyUsageListFromTemplate);
        finalKeyUsageList.addAll(keyUsageListFromDto);
        finalKeyUsageList.add("keyCertSign");
        finalKeyUsageList.add("cRLSign");

        String keyUsageString = finalKeyUsageList.stream()
                .map(String::trim).distinct().collect(Collectors.joining(", "));
        String extendedKeyUsageString = optionalTemplate.map(CertificateTemplate::getExtendedKeyUsage)
                .orElse(requestDto.getExtendedKeyUsage().stream().collect(Collectors.joining(", ")));
        String sansRegexString = optionalTemplate.map(CertificateTemplate::getSansRegex).orElse(null);

        Certificate certInfo = new Certificate();
        certInfo.setSerialNumber(certificate.getSerialNumber().toString());
        certInfo.setSubjectName(certificate.getSubjectX500Principal().getName());
        certInfo.setIssuerName(certificate.getIssuerX500Principal().getName());
        certInfo.setStartDate(now);
        certInfo.setEndDate(now.plusDays(requestDto.getValidityInDays()));
        certInfo.setRevoked(false);
        certInfo.setType(CertificateType.ROOT);
        certInfo.setOrganization(requestDto.getOrganization());
        certInfo.setKeystorePath(keystorePath);
        certInfo.setAlias(requestDto.getCommonName());
        certInfo.setKeyUsage(keyUsageString);
        certInfo.setExtendedKeyUsage(extendedKeyUsageString);
        certInfo.setSansRegex(sansRegexString);
        certInfo.setIssuerSerialNumber(null);
        certInfo.setUser(targetUser);
        certInfo.setKeystorePassword(encryptedPassword);

        certificateRepository.save(certInfo);
        return certificate;
    }

    private X509Certificate generateIntermediateCertificate(CertificateRequestDto requestDto,
                                                            Certificate issuerInfo,
                                                            Optional<CertificateTemplate> optionalTemplate,
                                                            User targetUser) throws Exception {
        KeyPair keyPair = generateKeyPair();

        // Učitaj issuer keystore da potpišeš novi sertifikat
        String issuerKeystorePassword = encryptionService.decrypt(issuerInfo.getKeystorePassword(),
                issuerInfo.getUser().getEncryptionKey());
        KeyStore issuerKeystore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(issuerInfo.getKeystorePath())) {
            issuerKeystore.load(fis, issuerKeystorePassword.toCharArray());
        }

        PrivateKey issuerPrivateKey = (PrivateKey) issuerKeystore.getKey(issuerInfo.getAlias(),
                issuerKeystorePassword.toCharArray());
        java.security.cert.Certificate[] issuerChain = issuerKeystore.getCertificateChain(issuerInfo.getAlias());

        X500Name subjectName = new X500Name("CN=" + requestDto.getCommonName()
                + ", O=" + requestDto.getOrganization());
        X500Name issuerName = new X500Name(issuerInfo.getSubjectName());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(requestDto.getValidityInDays())
                .atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serialNumber, startDate, endDate, subjectName, keyPair.getPublic()
        );

        List<String> finalKeyUsageList = new ArrayList<>(optionalTemplate
                .map(CertificateTemplate::getKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(new ArrayList<>()));
        finalKeyUsageList.addAll(requestDto.getKeyUsage());
        finalKeyUsageList.add("keyCertSign");
        finalKeyUsageList.add("cRLSign");
        finalKeyUsageList.add("digitalSignature");
        finalKeyUsageList.add("nonRepudiation");
        finalKeyUsageList.add("keyEncipherment");
        finalKeyUsageList.add("dataEncipherment");
        finalKeyUsageList.add("keyAgreement");

        String keyUsageString = finalKeyUsageList.stream()
                .map(String::trim).distinct().collect(Collectors.joining(", "));

        List<String> finalExtendedKeyUsageList = new ArrayList<>(optionalTemplate
                .map(CertificateTemplate::getExtendedKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getExtendedKeyUsage()));
        finalExtendedKeyUsageList.add("serverAuth");
        finalExtendedKeyUsageList.add("clientAuth");
        finalExtendedKeyUsageList.add("codeSigning");
        finalExtendedKeyUsageList.add("emailProtection");
        finalExtendedKeyUsageList.add("timeStamping");
        finalExtendedKeyUsageList.add("ocspSigning");

        String extendedKeyUsageString = finalExtendedKeyUsageList.stream()
                .map(String::trim).distinct().collect(Collectors.joining(", "));
        String sansRegexString = optionalTemplate.map(CertificateTemplate::getSansRegex).orElse(null);

        addExtensionsToBuilder(certBuilder, requestDto, optionalTemplate, true);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(signer));

        // Kreiraj lanac: novi intermediate + ceo issuer lanac (bez privatnih ključeva za issuer deo)
        java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
        newChain[0] = certificate;
        System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length);

        // Novi keystore samo za ovaj intermediate - sa privatnim ključem samo za njega
        String keystorePassword = generateRandomPassword();
        String keystorePath = KEYSTORE_PATH + serialNumber.toString() + ".jks";
        saveToKeystore(certificate, keyPair.getPrivate(), requestDto.getCommonName(),
                newChain, keystorePath, keystorePassword);

        Certificate certInfo = new Certificate();
        certInfo.setSerialNumber(certificate.getSerialNumber().toString());
        certInfo.setSubjectName(certificate.getSubjectX500Principal().getName());
        certInfo.setIssuerName(certificate.getIssuerX500Principal().getName());
        certInfo.setStartDate(now);
        certInfo.setEndDate(now.plusDays(requestDto.getValidityInDays()));
        certInfo.setRevoked(false);
        certInfo.setType(CertificateType.INTERMEDIATE);
        certInfo.setOrganization(requestDto.getOrganization());
        certInfo.setKeystorePath(keystorePath);
        certInfo.setAlias(requestDto.getCommonName());
        certInfo.setKeyUsage(keyUsageString);
        certInfo.setExtendedKeyUsage(extendedKeyUsageString);
        certInfo.setSansRegex(sansRegexString);
        certInfo.setIssuerSerialNumber(issuerInfo.getSerialNumber());
        certInfo.setUser(targetUser);
        certInfo.setKeystorePassword(encryptionService.encrypt(keystorePassword, targetUser.getEncryptionKey()));

        certificateRepository.save(certInfo);
        return certificate;
    }

    private X509Certificate generateEndEntityCertificate(CertificateRequestDto requestDto,
                                                         Certificate issuerInfo,
                                                         Optional<CertificateTemplate> optionalTemplate,
                                                         User targetUser) throws Exception {
        KeyPair keyPair = generateKeyPair();

        String issuerKeystorePassword = encryptionService.decrypt(issuerInfo.getKeystorePassword(),
                issuerInfo.getUser().getEncryptionKey());
        KeyStore issuerKeystore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(issuerInfo.getKeystorePath())) {
            issuerKeystore.load(fis, issuerKeystorePassword.toCharArray());
        }

        PrivateKey issuerPrivateKey = (PrivateKey) issuerKeystore.getKey(issuerInfo.getAlias(),
                issuerKeystorePassword.toCharArray());
        java.security.cert.Certificate[] issuerChain = issuerKeystore.getCertificateChain(issuerInfo.getAlias());

        X500Name subjectName = new X500Name("CN=" + requestDto.getCommonName()
                + ", O=" + requestDto.getOrganization());
        X500Name issuerName = new X500Name(issuerInfo.getSubjectName());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(requestDto.getValidityInDays())
                .atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serialNumber, startDate, endDate, subjectName, keyPair.getPublic()
        );

        addExtensionsToBuilder(certBuilder, requestDto, optionalTemplate, false);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(signer));

        // End-entity: kreiraj lanac bez privatnog ključa - samo trusted certificates
        java.security.cert.Certificate[] endEntityChain = new java.security.cert.Certificate[issuerChain.length + 1];
        endEntityChain[0] = certificate;
        System.arraycopy(issuerChain, 0, endEntityChain, 1, issuerChain.length);

        String keystorePassword = generateRandomPassword();
        String keystorePath = KEYSTORE_PATH + serialNumber.toString() + ".jks";

        // Čuvaj end-entity kao trusted certificate store (bez privatnog ključa)
        saveTrustedCertificateChain(endEntityChain, keystorePath, keystorePassword);

        List<String> keyUsageList = optionalTemplate.map(CertificateTemplate::getKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getKeyUsage());
        String keyUsageString = keyUsageList.stream()
                .map(String::trim).distinct().collect(Collectors.joining(", "));
        String extendedKeyUsageString = optionalTemplate.map(CertificateTemplate::getExtendedKeyUsage)
                .orElse(requestDto.getExtendedKeyUsage().stream().collect(Collectors.joining(", ")));
        String sansRegexString = optionalTemplate.map(CertificateTemplate::getSansRegex).orElse(null);

        Certificate certInfo = new Certificate();
        certInfo.setSerialNumber(certificate.getSerialNumber().toString());
        certInfo.setSubjectName(certificate.getSubjectX500Principal().getName());
        certInfo.setIssuerName(certificate.getIssuerX500Principal().getName());
        certInfo.setStartDate(now);
        certInfo.setEndDate(now.plusDays(requestDto.getValidityInDays()));
        certInfo.setRevoked(false);
        certInfo.setType(CertificateType.END_ENTITY);
        certInfo.setOrganization(requestDto.getOrganization());
        certInfo.setKeystorePath(keystorePath);
        certInfo.setAlias(requestDto.getCommonName());
        certInfo.setKeyUsage(keyUsageString);
        certInfo.setExtendedKeyUsage(extendedKeyUsageString);
        certInfo.setSansRegex(sansRegexString);
        certInfo.setIssuerSerialNumber(issuerInfo.getSerialNumber());
        certInfo.setUser(targetUser);
        certInfo.setKeystorePassword(encryptionService.encrypt(keystorePassword, targetUser.getEncryptionKey()));

        certificateRepository.save(certInfo);
        return certificate;
    }

    private void addExtensionsToBuilder(X509v3CertificateBuilder certBuilder,
                                        CertificateRequestDto requestDto,
                                        Optional<CertificateTemplate> optionalTemplate,
                                        boolean isCA) throws Exception {
        List<String> keyUsageList = optionalTemplate.map(CertificateTemplate::getKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getKeyUsage());
        List<String> extendedKeyUsageList = optionalTemplate.map(CertificateTemplate::getExtendedKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getExtendedKeyUsage());
        Optional<String> sansRegex = optionalTemplate.map(CertificateTemplate::getSansRegex);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));

        if (keyUsageList != null && !keyUsageList.isEmpty()) {
            int keyUsageValue = 0;
            for (String usage : keyUsageList) {
                switch (usage.trim()) {
                    case "digitalSignature": keyUsageValue |= KeyUsage.digitalSignature; break;
                    case "nonRepudiation": keyUsageValue |= KeyUsage.nonRepudiation; break;
                    case "keyEncipherment": keyUsageValue |= KeyUsage.keyEncipherment; break;
                    case "dataEncipherment": keyUsageValue |= KeyUsage.dataEncipherment; break;
                    case "keyAgreement": keyUsageValue |= KeyUsage.keyAgreement; break;
                    case "keyCertSign": keyUsageValue |= KeyUsage.keyCertSign; break;
                    case "cRLSign": keyUsageValue |= KeyUsage.cRLSign; break;
                    case "encipherOnly": keyUsageValue |= KeyUsage.encipherOnly; break;
                    case "decipherOnly": keyUsageValue |= KeyUsage.decipherOnly; break;
                }
            }
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageValue));
        }

        if (extendedKeyUsageList != null && !extendedKeyUsageList.isEmpty()) {
            List<KeyPurposeId> purposes = new ArrayList<>();
            for (String usage : extendedKeyUsageList) {
                switch (usage.trim()) {
                    case "serverAuth": purposes.add(KeyPurposeId.id_kp_serverAuth); break;
                    case "clientAuth": purposes.add(KeyPurposeId.id_kp_clientAuth); break;
                    case "codeSigning": purposes.add(KeyPurposeId.id_kp_codeSigning); break;
                    case "emailProtection": purposes.add(KeyPurposeId.id_kp_emailProtection); break;
                    case "timeStamping": purposes.add(KeyPurposeId.id_kp_timeStamping); break;
                    case "ocspSigning": purposes.add(KeyPurposeId.id_kp_OCSPSigning); break;
                }
            }
            certBuilder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(purposes.toArray(new KeyPurposeId[0])));
        }

        certBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(
                new DistributionPoint[]{new DistributionPoint(
                        new DistributionPointName(
                                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                                        "https://localhost:8443/api/crl"))
                        ), null, null
                )}
        ));

        if (sansRegex.isPresent() && !sansRegex.get().isEmpty()) {
            List<GeneralName> sanNames = new ArrayList<>();
            sanNames.add(new GeneralName(GeneralName.dNSName, "www.example.com"));
            sanNames.add(new GeneralName(GeneralName.dNSName, "sub.example.com"));
            certBuilder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(sanNames.toArray(new GeneralName[0])));
        }
    }

    private void checkIssuerPolicy(CertificateRequestDto requestDto,
                                   Optional<CertificateTemplate> optionalTemplate,
                                   Certificate issuerInfo) {
        List<String> requestedKeyUsage = optionalTemplate.map(CertificateTemplate::getKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getKeyUsage());

        if (issuerInfo.getKeyUsage() != null) {
            String[] issuerUsages = issuerInfo.getKeyUsage().split(", ");
            for (String usage : requestedKeyUsage) {
                boolean found = false;
                for (String issuerUsage : issuerUsages) {
                    if (issuerUsage.trim().equals(usage.trim())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    throw new IllegalArgumentException("Requested key usage '" + usage
                            + "' is not permitted by the issuer.");
                }
            }
        }
    }

    private void saveToKeystore(X509Certificate certificate, PrivateKey privateKey, String alias,
                                java.security.cert.Certificate[] chain, String keystorePath,
                                String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] passwordChars = keystorePassword.toCharArray();

        // Kreiraj novi keystore
        keyStore.load(null, passwordChars);

        // Dodaj privatni ključ sa lancem (samo prvi u lancu ima privatni ključ)
        keyStore.setKeyEntry(alias, privateKey, passwordChars, chain);

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, passwordChars);
        }
    }

    private void saveTrustedCertificateChain(java.security.cert.Certificate[] chain,
                                             String keystorePath,
                                             String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] passwordChars = keystorePassword.toCharArray();

        // Kreiraj novi keystore
        keyStore.load(null, passwordChars);

        // Dodaj sve sertifikate kao trusted (bez privatnih ključeva)
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = (X509Certificate) chain[i];
            String alias = "cert-" + i + "-" + cert.getSerialNumber().toString();
            keyStore.setCertificateEntry(alias, cert);
        }

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, passwordChars);
        }
    }

    private String generateRandomPassword() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean isCertificateValid(Certificate certificateInfo) {
        LocalDateTime now = LocalDateTime.now();
        return !now.isBefore(certificateInfo.getStartDate())
                && !now.isAfter(certificateInfo.getEndDate());
    }

    private boolean isCertificateRevoked(Certificate certificateInfo) {
        return certificateInfo.isRevoked();
    }

    private void validateCertificateChain(Certificate issuerInfo, int currentDepth) throws Exception {
        if (currentDepth > 20) {
            throw new IllegalArgumentException("Certificate chain depth exceeds maximum allowed (20 levels)");
        }

        if (!isCertificateValid(issuerInfo)) {
            throw new IllegalArgumentException("Issuer certificate is not valid in chain validation");
        }

        if (isCertificateRevoked(issuerInfo)) {
            throw new IllegalArgumentException("Issuer certificate is revoked in chain validation");
        }

        // NOVO: Kriptografska validacija potpisa
        if (issuerInfo.getType() != CertificateType.ROOT) {
            String parentSerialNumber = issuerInfo.getIssuerSerialNumber();
            if (parentSerialNumber != null && !parentSerialNumber.isEmpty()) {
                Optional<Certificate> parentIssuer = certificateRepository
                        .findBySerialNumber(parentSerialNumber);
                if (parentIssuer.isPresent()) {
                    // Validacija potpisa
                    validateCertificateSignature(issuerInfo, parentIssuer.get());

                    // Rekurzivna validacija gore
                    validateCertificateChain(parentIssuer.get(), currentDepth + 1);
                } else {
                    throw new IllegalArgumentException("Parent issuer certificate not found in database");
                }
            } else {
                throw new IllegalArgumentException("Non-root certificate must have an issuer");
            }
        }
    }

    private void validateCertificateSignature(Certificate childCert, Certificate issuerCert) throws Exception {
        // Učitaj issuer keystore
        String issuerPassword = encryptionService.decrypt(
                issuerCert.getKeystorePassword(),
                issuerCert.getUser().getEncryptionKey()
        );

        KeyStore issuerKeystore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(issuerCert.getKeystorePath())) {
            issuerKeystore.load(fis, issuerPassword.toCharArray());
        }

        // Uzmi issuer public key
        X509Certificate issuerX509 = (X509Certificate) issuerKeystore.getCertificate(issuerCert.getAlias());
        PublicKey issuerPublicKey = issuerX509.getPublicKey();

        // Učitaj child sertifikat
        String childPassword = encryptionService.decrypt(
                childCert.getKeystorePassword(),
                childCert.getUser().getEncryptionKey()
        );

        KeyStore childKeystore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(childCert.getKeystorePath())) {
            childKeystore.load(fis, childPassword.toCharArray());
        }

        X509Certificate childX509 = (X509Certificate) childKeystore.getCertificate(childCert.getAlias());

        // Validacija potpisa
        try {
            childX509.verify(issuerPublicKey);
        } catch (Exception e) {
            throw new IllegalArgumentException("Certificate signature validation failed: "
                    + childCert.getSerialNumber() + " was not signed by " + issuerCert.getSerialNumber(), e);
        }
    }

    public List<Certificate> getAllCertificates() {
        return certificateRepository.findAll();
    }

    public List<Certificate> getCertificatesByOrganization(String organization) {
        return certificateRepository.findByOrganization(organization);
    }

    public List<Certificate> getEndEntityCertificatesByUserEmail(String userEmail) {
        Optional<User> userOptional = userService.getUserByEmail(userEmail);
        if (userOptional.isEmpty()) {
            return new ArrayList<>();
        }

        User user = userOptional.get();
        return certificateRepository.findByOrganizationAndType(user.getOrganization(), CertificateType.END_ENTITY);
    }


    public List<Certificate> getCertificatesByOrganizationAndUser(String userEmail) {
        Optional<User> userOptional = userService.getUserByEmail(userEmail);
        if (userOptional.isEmpty()) {
            return new ArrayList<>();
        }

        User user = userOptional.get();
        return certificateRepository.findByTypeAndOrganizationAndUser_Id(CertificateType.INTERMEDIATE, user.getOrganization(), user.getId());
    }

    public List<Certificate> getCertificatesFromChain(String rootSerialNumber) {
        List<Certificate> chain = new ArrayList<>();
        Optional<Certificate> rootCert = certificateRepository.findBySerialNumber(rootSerialNumber);

        if (rootCert.isEmpty()) {
            return chain;
        }

        chain.add(rootCert.get());

        findChildCertificatesWithValidation(rootSerialNumber, chain);

        return chain;
    }

    private void findChildCertificatesWithValidation(String issuerSerialNumber, List<Certificate> chain) {
        List<Certificate> children = certificateRepository.findByIssuerSerialNumber(issuerSerialNumber);

        for (Certificate child : children) {

            Optional<Certificate> actualIssuer = certificateRepository.findBySerialNumber(child.getIssuerSerialNumber());
            if (actualIssuer.isPresent()) {
                chain.add(child);
                findChildCertificatesWithValidation(child.getSerialNumber(), chain);
            }

        }
    }


    /// ////////////////////////////////////    CSR       ///////////////////////////////////////////////////

    @Transactional
    public CsrRequest uploadCsr(CsrRequestDto csrDto, User uploadingUser, User targetUser) throws Exception {

        PKCS10CertificationRequest csr = parseCsrFromPem(csrDto.getCsrPemContent());


        validateCsrContent(csr, csrDto);
        validateCaCompatibilityForUpload(csrDto, uploadingUser);

        CsrRequest csrRequest = new CsrRequest();
        String normalizedCsrContent = normalizePemContent((csrDto.getCsrPemContent()));
        csrRequest.setCsrPemContent(normalizedCsrContent);
        csrRequest.setCommonName(csrDto.getCommonName());
        csrRequest.setOrganization(csrDto.getOrganization());
        csrRequest.setStatus("PENDING");
        csrRequest.setTargetUser(targetUser);
        csrRequest.setUploadingUser(uploadingUser);
        csrRequest.setUploadDate(LocalDateTime.now());
        csrRequest.setValidityInDays(csrDto.getValidityInDays());
        csrRequest.setCaIssuerSerialNumber(csrDto.getCaIssuerSerialNumber());
        csrRequest.setKeyUsage(csrDto.getKeyUsage() != null ? csrDto.getKeyUsage() : "");
        csrRequest.setExtendedKeyUsage(csrDto.getExtendedKeyUsage() != null ? csrDto.getExtendedKeyUsage() : "");


        PublicKey publicKey = getPublicKeyFromCsr(csr);
        csrRequest.setPublicKeyAlgorithm(publicKey.getAlgorithm());
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) publicKey;
            csrRequest.setKeyLength(rsaKey.getModulus().bitLength());
        }

        CsrRequest savedRequest = csrRequestRepository.save(csrRequest);

        System.out.println("CSR saved to database with ID: " + savedRequest.getId());
        return savedRequest;
    }



    @Transactional
    public X509Certificate signCsrAndIssueCertificate(CsrRequestDto csrDto, User issuingUser, User targetUser) throws Exception {

        PKCS10CertificationRequest csr = parseCsrFromDB(csrDto.getCsrPemContent());

        validateCsrContent(csr, csrDto);

        Certificate caCertificate = getCaCertificate(csrDto.getCaIssuerSerialNumber());

        validateCaCompatibility(caCertificate, csrDto, issuingUser);


        LocalDate today = LocalDate.now();
        LocalDate requestedEndDate = today.plusDays(csrDto.getValidityInDays());


        LocalDate caEndDate = caCertificate.getEndDate().toLocalDate();

        if (requestedEndDate.isAfter(caEndDate)) {
            throw new IllegalArgumentException(
                    "Traženi period važenja (" + requestedEndDate +
                            ") prelazi rok važenja CA sertifikata (" + caEndDate + ")."
            );
        }

        X509Certificate certificate = issueCertificateFromCsr(csr, csrDto, caCertificate, issuingUser, targetUser);

        updateCsrRequestStatus(csrDto, issuingUser);

        return certificate;
    }


    private PKCS10CertificationRequest parseCsrFromPem(String pemContent) throws Exception {
        try (StringReader stringReader = new StringReader(pemContent);
             PemReader pemReader = new PemReader(stringReader)) {

            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("Invalid PEM content: no PEM object found");
            }

            if (!pemObject.getType().equals("CERTIFICATE REQUEST")) {
                throw new IllegalArgumentException("Invalid PEM content: expected CERTIFICATE REQUEST, got " + pemObject.getType());
            }

            return new PKCS10CertificationRequest(pemObject.getContent());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse CSR from PEM: " + e.getMessage(), e);
        }
    }

    private void validateCsrContent(PKCS10CertificationRequest csr, CsrRequestDto csrDto) throws Exception {
        // Simplified validation - just check public key
        PublicKey csrPublicKey = getPublicKeyFromCsr(csr);
        if (csrPublicKey == null) {
            throw new IllegalArgumentException("CSR does not contain a valid public key");
        }

        if (!csrPublicKey.getAlgorithm().equals("RSA")) {
            throw new IllegalArgumentException("Only RSA public keys are supported, got: " + csrPublicKey.getAlgorithm());
        }

        if (csrPublicKey instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) csrPublicKey;
            if (rsaKey.getModulus().bitLength() < 2048) {
                throw new IllegalArgumentException("RSA key length must be at least 2048 bits, got: " + rsaKey.getModulus().bitLength());
            }
        }
    }

    private Certificate getCaCertificate(String caSerialNumber) throws Exception {
        Optional<Certificate> caOptional = certificateRepository.findBySerialNumber(caSerialNumber);
        if (caOptional.isEmpty()) {
            throw new IllegalArgumentException("CA certificate with serial number " + caSerialNumber + " not found");
        }

        Certificate caCertificate = caOptional.get();

        if (!isCertificateValid(caCertificate)) {
            throw new IllegalArgumentException("CA certificate is not valid");
        }

        if (isCertificateRevoked(caCertificate)) {
            throw new IllegalArgumentException("CA certificate has been revoked");
        }

        if (caCertificate.getType() == CertificateType.END_ENTITY) {
            throw new IllegalArgumentException("Cannot issue certificate from END_ENTITY certificate");
        }

        return caCertificate;
    }

    private void validateCaCompatibility(Certificate caCertificate, CsrRequestDto csrDto, User issuingUser) throws Exception {

        if (!caCertificate.getUser().equals(issuingUser) && issuingUser.getRole() != UserRole.ADMIN) {
            throw new SecurityException("You are not authorized to use this certificate as an issuer");
        }


        if (!caCertificate.getOrganization().equals(csrDto.getOrganization())) {
            throw new IllegalArgumentException("CA organization '" + caCertificate.getOrganization() + "' does not match CSR organization '" + csrDto.getOrganization() + "'");
        }


        validateCertificateChain(caCertificate, 1);
    }


    private void validateCaCompatibilityForUpload(CsrRequestDto csrDto, User uploadingUser) throws Exception {


        Optional<Certificate> caOptional = certificateRepository.findBySerialNumber(csrDto.getCaIssuerSerialNumber());
        if (caOptional.isEmpty()) {
            throw new IllegalArgumentException("CA certificate with serial number " + csrDto.getCaIssuerSerialNumber() + " not found");
        }

        Certificate caCertificate = caOptional.get();


        if (!caCertificate.getOrganization().equals(uploadingUser.getOrganization())) {
            throw new IllegalArgumentException("You can only use CA from your own organization. Your org: " +
                    uploadingUser.getOrganization() + ", CA org: " + caCertificate.getOrganization());
        }

        if (!isCertificateValid(caCertificate)) {
            throw new IllegalArgumentException("CA certificate is not valid (expired or not yet active)");
        }

        if (isCertificateRevoked(caCertificate)) {
            throw new IllegalArgumentException("CA certificate has been revoked");
        }

        if (caCertificate.getType() == CertificateType.END_ENTITY) {
            throw new IllegalArgumentException("Cannot use END_ENTITY certificate as CA. Only ROOT and INTERMEDIATE certificates can be used.");
        }


        long caValidityDays = java.time.Duration.between(caCertificate.getStartDate(), caCertificate.getEndDate()).toDays();
        if (csrDto.getValidityInDays() > caValidityDays) {
            throw new IllegalArgumentException("Certificate validity (" + csrDto.getValidityInDays() +
                    " days) cannot exceed CA validity (" + caValidityDays + " days). Please choose a shorter validity period.");
        }

        System.out.println("CA compatibility validation passed for CA: " + caCertificate.getSubjectName() +
                " with validity: " + caValidityDays + " days");
    }

    private X509Certificate issueCertificateFromCsr(PKCS10CertificationRequest csr, CsrRequestDto csrDto,
                                                    Certificate caCertificate, User issuingUser, User targetUser) throws Exception {


        String caKeystorePassword = encryptionService.decrypt(caCertificate.getKeystorePassword(), caCertificate.getUser().getEncryptionKey());
        KeyStore caKeystore = KeyStore.getInstance("JKS");

        try (FileInputStream fis = new FileInputStream(caCertificate.getKeystorePath())) {
            caKeystore.load(fis, caKeystorePassword.toCharArray());
        }

        PrivateKey caPrivateKey = (PrivateKey) caKeystore.getKey(caCertificate.getAlias(), caKeystorePassword.toCharArray());
        java.security.cert.Certificate[] caChain = caKeystore.getCertificateChain(caCertificate.getAlias());


        X500Name subjectName = csr.getSubject();
        X500Name issuerName = new X500Name(caCertificate.getSubjectName());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());


        PublicKey csrPublicKey = getPublicKeyFromCsr(csr);


        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(csrDto.getValidityInDays()).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                csrPublicKey
        );


        Optional<CertificateTemplate> optionalTemplate = csrDto.getTemplateId().isPresent() ?
                certificateTemplateRepository.findById(csrDto.getTemplateId().get()) : Optional.empty();

        addExtensionsToBuilderForCsr(certBuilder, csrDto, optionalTemplate, false);


        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));


        String keystorePath = caCertificate.getKeystorePath();
        //saveAsTrustedCertificate(certificate, keystorePath, caKeystorePassword);

        List<String> keyUsageList = optionalTemplate.map(CertificateTemplate::getKeyUsage)
                .map(s -> Arrays.asList(s.split(",")))
                .orElse(csrDto.getKeyUsage() != null ? Arrays.asList(csrDto.getKeyUsage().split(",")) : new ArrayList<>());
        String keyUsageString = keyUsageList.stream().map(String::trim).distinct().collect(Collectors.joining(", "));

        String extendedKeyUsageString = optionalTemplate.map(CertificateTemplate::getExtendedKeyUsage)
                .orElse(csrDto.getExtendedKeyUsage() != null ? csrDto.getExtendedKeyUsage() : "");

        String sansRegexString = optionalTemplate.map(CertificateTemplate::getSansRegex).orElse(null);

        Certificate certInfo = new Certificate();
        certInfo.setSerialNumber(certificate.getSerialNumber().toString());
        certInfo.setSubjectName(certificate.getSubjectX500Principal().getName());
        certInfo.setIssuerName(certificate.getIssuerX500Principal().getName());
        certInfo.setStartDate(now);
        certInfo.setEndDate(now.plusDays(csrDto.getValidityInDays()));
        certInfo.setRevoked(false);
        certInfo.setType(CertificateType.END_ENTITY);
        certInfo.setOrganization(csrDto.getOrganization());
        certInfo.setKeystorePath(keystorePath);
        certInfo.setAlias(csrDto.getCommonName());
        certInfo.setKeyUsage(keyUsageString);
        certInfo.setExtendedKeyUsage(extendedKeyUsageString);
        certInfo.setSansRegex(sansRegexString);
        certInfo.setIssuerSerialNumber(caCertificate.getSerialNumber());
        certInfo.setUser(targetUser);
        certInfo.setKeystorePassword(null); // End entity nema keystore password

        certificateRepository.save(certInfo);
        return certificate;
    }

    public List<Map<String, String>> getAvailableCaCertificates() {
        List<Certificate> allCertificates = certificateRepository.findAll();
        List<Map<String, String>> caList = new ArrayList<>();

        for (Certificate cert : allCertificates) {
            if ((cert.getType() == CertificateType.ROOT || cert.getType() == CertificateType.INTERMEDIATE)
                    && !cert.isRevoked() && isCertificateValid(cert)) {

                Map<String, String> caInfo = new HashMap<>();
                caInfo.put("serialNumber", cert.getSerialNumber());
                caInfo.put("subjectName", cert.getSubjectName());
                caInfo.put("organization", cert.getOrganization());
                caInfo.put("type", cert.getType().name());
                caInfo.put("validityDays", String.valueOf(java.time.Duration.between(cert.getStartDate(), cert.getEndDate()).toDays()));

                caList.add(caInfo);
            }
        }

        return caList;
    }


    public List<CsrResponseDto> getPendingCsrRequests(String organization) {
        List<CsrRequest> pendingRequests = csrRequestRepository.findByStatusAndOrganizationOrderByUploadDateDesc("PENDING", organization);

        return pendingRequests.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }

    public List<CsrResponseDto> getCsrRequestsByUser(User user) {
        List<CsrRequest> userRequests = csrRequestRepository.findByUploadingUser(user);

        return userRequests.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }

    public CsrResponseDto getCsrRequestById(Long id) {
        Optional<CsrRequest> optionalRequest = csrRequestRepository.findById(id);
        if (optionalRequest.isPresent()) {
            return convertToResponseDto(optionalRequest.get());
        }
        throw new IllegalArgumentException("CSR request with ID " + id + " not found");
    }

    @Transactional
    public void rejectCsrRequest(Long csrId, String reason, User rejectingUser) {
        Optional<CsrRequest> optionalRequest = csrRequestRepository.findById(csrId);
        if (optionalRequest.isPresent()) {
            CsrRequest csrRequest = optionalRequest.get();


            if (!rejectingUser.getRole().equals(UserRole.ADMIN) &&
                    !rejectingUser.getRole().equals(UserRole.CA_USER)) {
                throw new SecurityException("Only ADMIN or CA_USER can reject CSR requests");
            }


            if (!csrRequest.getOrganization().equals(rejectingUser.getOrganization())) {
                throw new SecurityException("You can only reject CSR requests from your own organization");
            }

            if (csrRequest.getStatus().equals("APPROVED")) {
                throw new SecurityException("Cannot reject an approved CSR request");
            }

            csrRequest.setStatus("REJECTED");
            csrRequest.setRejectionReason(reason);
            csrRequest.setApprovalDate(LocalDateTime.now());

            csrRequestRepository.save(csrRequest);
        } else {
            throw new IllegalArgumentException("CSR request with ID " + csrId + " not found");
        }
    }

    private CsrResponseDto convertToResponseDto(CsrRequest csrRequest) {
        CsrResponseDto dto = new CsrResponseDto();
        dto.setId(csrRequest.getId());
        dto.setCommonName(csrRequest.getCommonName());
        dto.setOrganization(csrRequest.getOrganization());
        dto.setStatus(csrRequest.getStatus());
        dto.setTargetUserEmail(csrRequest.getTargetUser().getEmail());
        dto.setUploadingUserEmail(csrRequest.getUploadingUser().getEmail());
        dto.setUploadDate(csrRequest.getUploadDate());
        dto.setApprovalDate(csrRequest.getApprovalDate());
        dto.setRejectionReason(csrRequest.getRejectionReason());
        dto.setPublicKeyAlgorithm(csrRequest.getPublicKeyAlgorithm());
        dto.setKeyLength(csrRequest.getKeyLength());
        dto.setKeyUsage(csrRequest.getKeyUsage() != null ? csrRequest.getKeyUsage() : "");
        dto.setExtendedKeyUsage(csrRequest.getExtendedKeyUsage() != null ? csrRequest.getExtendedKeyUsage() : "");
        dto.setValidityInDays(csrRequest.getValidityInDays());
        dto.setCaIssuerSerialNumber(csrRequest.getCaIssuerSerialNumber());
        dto.setCsrPemContent(csrRequest.getCsrPemContent());
        return dto;
    }


    private void updateCsrRequestStatus(CsrRequestDto csrDto, User issuingUser) {
        try {
            String normalizedPemContent = normalizePemContent(csrDto.getCsrPemContent());

            List<CsrRequest> matchingRequests = csrRequestRepository.findByCsrPemContent(normalizedPemContent);

            if (!matchingRequests.isEmpty()) {
                CsrRequest csrRequest = matchingRequests.get(0);
                csrRequest.setStatus("APPROVED");
                csrRequest.setApprovalDate(LocalDateTime.now());
                csrRequestRepository.save(csrRequest);

                System.out.println("CSR request status updated to APPROVED for ID: " + csrRequest.getId());
            } else {
                System.out.println("Warning: No matching CSR request found to update status");
            }
        } catch (Exception e) {
            System.out.println("Error updating CSR request status: " + e.getMessage());

        }
    }

    private PublicKey getPublicKeyFromCsr(PKCS10CertificationRequest csr) throws Exception {
        try {

            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki = csr.getSubjectPublicKeyInfo();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to extract public key from CSR: " + e.getMessage(), e);
        }
    }


    private String normalizePemContent(String pemContent) {
        if (pemContent == null) return "";

        // Ukloni sve whitespace karaktere
        return pemContent.replaceAll("\\s+", "");
    }

    private void addExtensionsToBuilderForCsr(X509v3CertificateBuilder certBuilder, CsrRequestDto csrDto, Optional<CertificateTemplate> optionalTemplate, boolean isCA) throws Exception {
        List<String> keyUsageList = optionalTemplate.map(CertificateTemplate::getKeyUsage).map(s -> Arrays.asList(s.split(","))).orElse(csrDto.getKeyUsage() != null ? Arrays.asList(csrDto.getKeyUsage().split(",")) : new ArrayList<>());
        List<String> extendedKeyUsageList = optionalTemplate.map(CertificateTemplate::getExtendedKeyUsage).map(s -> Arrays.asList(s.split(","))).orElse(csrDto.getExtendedKeyUsage() != null ? Arrays.asList(csrDto.getExtendedKeyUsage().split(",")) : new ArrayList<>());
        Optional<String> sansRegex = optionalTemplate.map(CertificateTemplate::getSansRegex);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));

        if (keyUsageList != null && !keyUsageList.isEmpty()) {
            int keyUsageValue = 0;
            for (String usage : keyUsageList) {
                switch (usage.trim()) {
                    case "digitalSignature":
                        keyUsageValue |= KeyUsage.digitalSignature;
                        break;
                    case "nonRepudiation":
                        keyUsageValue |= KeyUsage.nonRepudiation;
                        break;
                    case "keyEncipherment":
                        keyUsageValue |= KeyUsage.keyEncipherment;
                        break;
                    case "dataEncipherment":
                        keyUsageValue |= KeyUsage.dataEncipherment;
                        break;
                    case "keyAgreement":
                        keyUsageValue |= KeyUsage.keyAgreement;
                        break;
                    case "keyCertSign":
                        keyUsageValue |= KeyUsage.keyCertSign;
                        break;
                    case "cRLSign":
                        keyUsageValue |= KeyUsage.cRLSign;
                        break;
                    case "encipherOnly":
                        keyUsageValue |= KeyUsage.encipherOnly;
                        break;
                    case "decipherOnly":
                        keyUsageValue |= KeyUsage.decipherOnly;
                        break;
                }
            }
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageValue));
        }

        if (extendedKeyUsageList != null && !extendedKeyUsageList.isEmpty()) {
            List<KeyPurposeId> purposes = new ArrayList<>();
            for (String usage : extendedKeyUsageList) {
                switch (usage.trim()) {
                    case "serverAuth":
                        purposes.add(KeyPurposeId.id_kp_serverAuth);
                        break;
                    case "clientAuth":
                        purposes.add(KeyPurposeId.id_kp_clientAuth);
                        break;
                    case "codeSigning":
                        purposes.add(KeyPurposeId.id_kp_codeSigning);
                        break;
                    case "emailProtection":
                        purposes.add(KeyPurposeId.id_kp_emailProtection);
                        break;
                    case "timeStamping":
                        purposes.add(KeyPurposeId.id_kp_timeStamping);
                        break;
                    case "ocspSigning":
                        purposes.add(KeyPurposeId.id_kp_OCSPSigning);
                        break;
                }
            }
            certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes.toArray(new KeyPurposeId[0])));
        }

        certBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(
                new DistributionPoint[]{new DistributionPoint(
                        new DistributionPointName(
                                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "https://localhost:8443/api/crl"))
                        ), null, null
                )}
        ));

        if (sansRegex.isPresent() && !sansRegex.get().isEmpty()) {
            List<GeneralName> sanNames = new ArrayList<>();
            sanNames.add(new GeneralName(GeneralName.dNSName, "www.example.com"));
            sanNames.add(new GeneralName(GeneralName.dNSName, "sub.example.com"));
            certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanNames.toArray(new GeneralName[0])));
        }
    }

    @Transactional
    public void revokeCertificate(String serialNumber, RevokedReason reason) {
        Optional<Certificate> certOptional = certificateRepository.findBySerialNumber(serialNumber);
        if (certOptional.isEmpty()) {
            throw new IllegalArgumentException("Certificate with serial number " + serialNumber + " not found");
        }
        Certificate certificate = certOptional.get();
        certificate.setRevoked(true);
        certificate.setRevokedReason(reason);
        certificate.setRevokedAt(LocalDateTime.now());
        certificateRepository.save(certificate);
    }

    @Transactional
    public AbstractMap.SimpleEntry<X509Certificate, PrivateKey> getRootCertificateWithPk() {
        Optional<Certificate> rootCertOpt = certificateRepository.findAll().stream()
                .filter(cert -> cert.getType() == CertificateType.ROOT)
                .findFirst();
        if (rootCertOpt.isEmpty()) {
            return null;
        }
        Certificate rootCert = rootCertOpt.get();
        try {
            String keystorePassword = encryptionService.decrypt(rootCert.getKeystorePassword(), rootCert.getUser().getEncryptionKey());
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(rootCert.getKeystorePath())) {
                keyStore.load(fis, keystorePassword.toCharArray());
            }
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(rootCert.getAlias(), keystorePassword.toCharArray());
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(rootCert.getAlias());
            return new AbstractMap.SimpleEntry<>(cert, privateKey);
        } catch (Exception e) {
            throw new IllegalArgumentException("Root certificate not found");
        }
    }

    public List<Certificate> getIntermediateCertificatesByOrganization(String organization) {
        return certificateRepository.findByOrganizationAndType(organization, CertificateType.INTERMEDIATE);
    }

    public String extractCommonName(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            X500Name subject = csr.getSubject();
            String subjectString = subject.toString();
            
            // Parse CN from subject string like "CN=NoviCA, O=Security Inc., E=papovicognjen59@gmail.com"
            int cnIndex = subjectString.indexOf("CN=");
            if (cnIndex != -1) {
                int start = cnIndex + 3;
                int end = subjectString.indexOf(",", start);
                if (end == -1) end = subjectString.length();
                return subjectString.substring(start, end).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public String extractOrganization(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            X500Name subject = csr.getSubject();
            String subjectString = subject.toString();
            
            // Parse O from subject string like "CN=NoviCA, O=Security Inc., E=papovicognjen59@gmail.com"
            int oIndex = subjectString.indexOf("O=");
            if (oIndex != -1) {
                int start = oIndex + 2;
                int end = subjectString.indexOf(",", start);
                if (end == -1) end = subjectString.length();
                return subjectString.substring(start, end).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public String extractEmail(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            X500Name subject = csr.getSubject();
            String subjectString = subject.toString();
            
            // Parse E from subject string like "CN=NoviCA, O=Security Inc., E=papovicognjen59@gmail.com"
            int eIndex = subjectString.indexOf("E=");
            if (eIndex != -1) {
                int start = eIndex + 2;
                int end = subjectString.indexOf(",", start);
                if (end == -1) end = subjectString.length();
                return subjectString.substring(start, end).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public String extractKeyUsage(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            
            // Look for keyUsage extension in attributes
            org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();
            for (org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
                if (attr.getAttrType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    org.bouncycastle.asn1.ASN1Set attrValues = attr.getAttrValues();
                    for (int i = 0; i < attrValues.size(); i++) {
                        org.bouncycastle.asn1.x509.Extensions extensions = org.bouncycastle.asn1.x509.Extensions.getInstance(attrValues.getObjectAt(i));
                        org.bouncycastle.asn1.x509.Extension keyUsageExt = extensions.getExtension(org.bouncycastle.asn1.x509.Extension.keyUsage);
                        if (keyUsageExt != null) {
                            org.bouncycastle.asn1.x509.KeyUsage keyUsage = org.bouncycastle.asn1.x509.KeyUsage.getInstance(keyUsageExt.getParsedValue());
                            return keyUsageToString(keyUsage);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public String extractExtendedKeyUsage(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            
            // Look for extendedKeyUsage extension in attributes
            org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();
            for (org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
                if (attr.getAttrType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    org.bouncycastle.asn1.ASN1Set attrValues = attr.getAttrValues();
                    for (int i = 0; i < attrValues.size(); i++) {
                        org.bouncycastle.asn1.x509.Extensions extensions = org.bouncycastle.asn1.x509.Extensions.getInstance(attrValues.getObjectAt(i));
                        org.bouncycastle.asn1.x509.Extension extendedKeyUsageExt = extensions.getExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage);
                        if (extendedKeyUsageExt != null) {
                            org.bouncycastle.asn1.x509.ExtendedKeyUsage extendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extendedKeyUsageExt.getParsedValue());
                            return extendedKeyUsageToString(extendedKeyUsage);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }


    private String keyUsageToString(org.bouncycastle.asn1.x509.KeyUsage keyUsage) {
        java.util.List<String> usages = new java.util.ArrayList<>();
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature)) usages.add("digitalSignature");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation)) usages.add("nonRepudiation");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment)) usages.add("keyEncipherment");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment)) usages.add("dataEncipherment");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.keyAgreement)) usages.add("keyAgreement");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign)) usages.add("keyCertSign");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.cRLSign)) usages.add("cRLSign");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.encipherOnly)) usages.add("encipherOnly");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.decipherOnly)) usages.add("decipherOnly");
        return String.join(",", usages);
    }

    private String extendedKeyUsageToString(org.bouncycastle.asn1.x509.ExtendedKeyUsage extendedKeyUsage) {
        java.util.List<String> usages = new java.util.ArrayList<>();
        for (org.bouncycastle.asn1.x509.KeyPurposeId oid : extendedKeyUsage.getUsages()) {
            if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth)) usages.add("serverAuth");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth)) usages.add("clientAuth");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_codeSigning)) usages.add("codeSigning");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_emailProtection)) usages.add("emailProtection");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_timeStamping)) usages.add("timeStamping");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning)) usages.add("ocspSigning");
        }
        return String.join(",", usages);
    }

    private PKCS10CertificationRequest parseCsrFromDB(String pemContentFromDb) throws Exception {
        if (pemContentFromDb == null) {
            throw new IllegalArgumentException("PEM content is null.");
        }


        String cleanedContent = pemContentFromDb.replaceAll("\\s+", "");


        String normalizedContent = cleanedContent
                // Markeri bez razmaka: umetanje novog reda i standardnih razmaka
                .replace("-----BEGINCERTIFICATEREQUEST-----", "-----BEGIN CERTIFICATE REQUEST-----\n")
                .replace("-----ENDCERTIFICATEREQUEST-----", "\n-----END CERTIFICATE REQUEST-----");


        try (StringReader stringReader = new StringReader(normalizedContent);
             PemReader pemReader = new PemReader(stringReader)) {

            PemObject pemObject = pemReader.readPemObject();

            if (pemObject == null) {
                throw new IllegalArgumentException("Invalid PEM structure after normalization. Check input string.");
            }

            if (!pemObject.getType().equals("CERTIFICATE REQUEST")) {
                throw new IllegalArgumentException("Invalid PEM type: expected CERTIFICATE REQUEST, got " + pemObject.getType());
            }

            return new PKCS10CertificationRequest(pemObject.getContent());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse CSR from PEM: " + e.getMessage(), e);
        }
    }
}