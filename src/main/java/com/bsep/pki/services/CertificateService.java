package com.bsep.pki.services;

import com.bsep.pki.dtos.CertificateRequestDto;
import com.bsep.pki.models.Certificate;
import com.bsep.pki.models.CertificateTemplate;
import com.bsep.pki.models.CertificateType;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.CertificateRepository;
import com.bsep.pki.repositories.CertificateTemplateRepository;
import jakarta.transaction.Transactional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
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

    @Autowired
    public CertificateService(CertificateRepository certificateRepository, CertificateTemplateRepository certificateTemplateRepository,
                              KeystoreEncryptionService encryptionService) {
        this.certificateRepository = certificateRepository;
        this.certificateTemplateRepository = certificateTemplateRepository;
        this.encryptionService = encryptionService;
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

            if (template.getCommonNameRegex() != null && !template.getCommonNameRegex().isEmpty() && !Pattern.matches(template.getCommonNameRegex(), requestDto.getCommonName())) {
                throw new IllegalArgumentException("Common Name does not match template regex.");
            }

            if (requestDto.getValidityInDays() > template.getMaxValidityDays()) {
                throw new IllegalArgumentException("Validity period exceeds template maximum of " + template.getMaxValidityDays() + " days.");
            }
        }

        if (requestDto.getType() == CertificateType.ROOT) {
            return generateRootCertificate(requestDto, optionalTemplate, targetUser);
        } else {
            if (requestDto.getIssuerSerialNumber().isEmpty()) {
                throw new IllegalArgumentException("Issuer serial number is required for non-root certificates.");
            }

            Optional<Certificate> issuerInfo = certificateRepository.findBySerialNumber(requestDto.getIssuerSerialNumber().get());
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

            checkIssuerPolicy(requestDto, optionalTemplate, issuerInfo.get());

            if (requestDto.getType() == CertificateType.INTERMEDIATE) {
                return generateIntermediateCertificate(requestDto, issuerInfo.get(), optionalTemplate, targetUser);
            } else { // END_ENTITY
                return generateEndEntityCertificate(requestDto, issuerInfo.get(), optionalTemplate, targetUser);
            }
        }
    }

    private X509Certificate generateRootCertificate(CertificateRequestDto requestDto, Optional<CertificateTemplate> optionalTemplate, User targetUser) throws Exception {
        KeyPair keyPair = generateKeyPair();

        X500Name subjectName = new X500Name("CN=" + requestDto.getCommonName() + ", O=" + requestDto.getOrganization());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(requestDto.getValidityInDays()).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subjectName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                keyPair.getPublic()
        );

        addExtensionsToBuilder(certBuilder, requestDto, optionalTemplate, true);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        String keystorePassword = generateRandomPassword();
        String encryptedPassword = encryptionService.encrypt(keystorePassword, targetUser.getEncryptionKey());

        java.security.cert.Certificate[] rootChain = new java.security.cert.Certificate[1];
        rootChain[0] = certificate;
        String keystorePath = KEYSTORE_PATH + requestDto.getOrganization().replace(" ", "_") + ".jks";

        saveToKeystore(certificate, keyPair.getPrivate(), requestDto.getCommonName(), rootChain, keystorePath, keystorePassword);

        List<String> keyUsageListFromTemplate = optionalTemplate.map(CertificateTemplate::getKeyUsage)
                .map(s -> Arrays.asList(s.split(","))).orElse(new ArrayList<>());
        List<String> keyUsageListFromDto = requestDto.getKeyUsage();
        List<String> finalKeyUsageList = new ArrayList<>(keyUsageListFromTemplate);
        finalKeyUsageList.addAll(keyUsageListFromDto);
        finalKeyUsageList.add("keyCertSign");
        finalKeyUsageList.add("cRLSign");
        String keyUsageString = finalKeyUsageList.stream().map(String::trim).distinct().collect(Collectors.joining(", "));
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

    private X509Certificate generateIntermediateCertificate(CertificateRequestDto requestDto, Certificate issuerInfo, Optional<CertificateTemplate> optionalTemplate, User targetUser) throws Exception {
        KeyPair keyPair = generateKeyPair();

        String issuerKeystorePassword = encryptionService.decrypt(issuerInfo.getKeystorePassword(), issuerInfo.getUser().getEncryptionKey());
        KeyStore issuerKeystore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(issuerInfo.getKeystorePath())) {
            issuerKeystore.load(fis, issuerKeystorePassword.toCharArray());
        }

        PrivateKey issuerPrivateKey = (PrivateKey) issuerKeystore.getKey(issuerInfo.getAlias(), issuerKeystorePassword.toCharArray());
        java.security.cert.Certificate[] issuerChain = issuerKeystore.getCertificateChain(issuerInfo.getAlias());

        X500Name subjectName = new X500Name("CN=" + requestDto.getCommonName() + ", O=" + requestDto.getOrganization());
        X500Name issuerName = new X500Name(issuerInfo.getSubjectName());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(requestDto.getValidityInDays()).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                keyPair.getPublic()
        );

        addExtensionsToBuilder(certBuilder, requestDto, optionalTemplate, true);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
        newChain[0] = certificate;
        System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length);

        // Keystore lozinka ostaje ista za celu organizaciju
        String keystorePassword = issuerKeystorePassword;

        String keystorePath = KEYSTORE_PATH + requestDto.getOrganization().replace(" ", "_") + ".jks";
        saveToKeystore(certificate, keyPair.getPrivate(), requestDto.getCommonName(), newChain, keystorePath, keystorePassword);

        List<String> finalKeyUsageList = new ArrayList<>(optionalTemplate.map(CertificateTemplate::getKeyUsage).map(s -> Arrays.asList(s.split(","))).orElse(new ArrayList<>()));
        finalKeyUsageList.addAll(requestDto.getKeyUsage());
        finalKeyUsageList.add("keyCertSign");
        finalKeyUsageList.add("cRLSign");
        String keyUsageString = finalKeyUsageList.stream().map(String::trim).distinct().collect(Collectors.joining(", "));
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

    private X509Certificate generateEndEntityCertificate(CertificateRequestDto requestDto, Certificate issuerInfo, Optional<CertificateTemplate> optionalTemplate, User targetUser) throws Exception {
        KeyPair keyPair = generateKeyPair();

        String issuerKeystorePassword = encryptionService.decrypt(issuerInfo.getKeystorePassword(), issuerInfo.getUser().getEncryptionKey());
        KeyStore issuerKeystore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(issuerInfo.getKeystorePath())) {
            issuerKeystore.load(fis, issuerKeystorePassword.toCharArray());
        }

        PrivateKey issuerPrivateKey = (PrivateKey) issuerKeystore.getKey(issuerInfo.getAlias(), issuerKeystorePassword.toCharArray());

        X500Name subjectName = new X500Name("CN=" + requestDto.getCommonName() + ", O=" + requestDto.getOrganization());
        X500Name issuerName = new X500Name(issuerInfo.getSubjectName());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        LocalDateTime now = LocalDateTime.now();
        Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
        Date endDate = Date.from(now.plusDays(requestDto.getValidityInDays()).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                keyPair.getPublic()
        );

        addExtensionsToBuilder(certBuilder, requestDto, optionalTemplate, false);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        String keystorePath = KEYSTORE_PATH + issuerInfo.getOrganization().replace(" ", "_") + ".jks";
        saveAsTrustedCertificate(certificate, keystorePath, issuerKeystorePassword);

        List<String> keyUsageList = optionalTemplate.map(CertificateTemplate::getKeyUsage).map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getKeyUsage());
        String keyUsageString = keyUsageList.stream().map(String::trim).distinct().collect(Collectors.joining(", "));
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
        certInfo.setKeystorePassword(null);

        certificateRepository.save(certInfo);
        return certificate;
    }

    private void addExtensionsToBuilder(X509v3CertificateBuilder certBuilder, CertificateRequestDto requestDto, Optional<CertificateTemplate> optionalTemplate, boolean isCA) throws Exception {
        List<String> keyUsageList = optionalTemplate.map(CertificateTemplate::getKeyUsage).map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getKeyUsage());
        List<String> extendedKeyUsageList = optionalTemplate.map(CertificateTemplate::getExtendedKeyUsage).map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getExtendedKeyUsage());
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
                                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "http://tvoj-domen/api/crl"))
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

    private void checkIssuerPolicy(CertificateRequestDto requestDto, Optional<CertificateTemplate> optionalTemplate, Certificate issuerInfo) {
        List<String> requestedKeyUsage = optionalTemplate.map(CertificateTemplate::getKeyUsage).map(s -> Arrays.asList(s.split(","))).orElse(requestDto.getKeyUsage());

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
                    throw new IllegalArgumentException("Requested key usage '" + usage + "' is not permitted by the issuer.");
                }
            }
        }
    }

    private void saveToKeystore(X509Certificate certificate, PrivateKey privateKey, String alias, java.security.cert.Certificate[] issuerChain, String keystorePath, String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] passwordChars = keystorePassword.toCharArray();

        File keystoreFile = new File(keystorePath);
        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, passwordChars);
            }
        } else {
            keyStore.load(null, passwordChars);
        }

        keyStore.setKeyEntry(alias, privateKey, passwordChars, issuerChain);

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keyStore.store(fos, passwordChars);
        }
    }

    private void saveAsTrustedCertificate(X509Certificate certificate, String keystorePath, String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        char[] passwordChars = keystorePassword.toCharArray();

        File keystoreFile = new File(keystorePath);
        if (!keystoreFile.exists()) {
            throw new IllegalArgumentException("Keystore for organization does not exist.");
        }

        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keyStore.load(fis, passwordChars);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid keystore password.", e);
        }

        keyStore.setCertificateEntry(certificate.getSerialNumber().toString(), certificate);

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
        return !now.isBefore(certificateInfo.getStartDate()) && !now.isAfter(certificateInfo.getEndDate());
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

        if (issuerInfo.getType() != CertificateType.ROOT) {
            String parentSerialNumber = issuerInfo.getIssuerSerialNumber();
            if (parentSerialNumber != null && !parentSerialNumber.isEmpty()) {
                Optional<Certificate> parentIssuer = certificateRepository.findBySerialNumber(parentSerialNumber);
                if (parentIssuer.isPresent()) {
                    validateCertificateChain(parentIssuer.get(), currentDepth + 1);
                }
            }
        }
    }
}