package com.bsep.pki.controllers;

import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.services.UserService;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserService userService;
    private final JwtProvider jwtProvider;

    @Value("${server.ssl.key-store-password}")
    private String keystorePassword;

    public AdminController(UserService userService, JwtProvider jwtProvider) {
        this.userService = userService;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/register-admin")
    public ResponseEntity<String> registerAdmin(@Valid @RequestBody RegistrationDto registrationDto, HttpServletRequest request) {
        if (!isAdmin(request)) {
            return new ResponseEntity<>("Only admins can register other admins.", HttpStatus.FORBIDDEN);
        }

        try {
            userService.registerAdmin(registrationDto);
            return new ResponseEntity<>("Admin successfully registered.", HttpStatus.CREATED);
        } catch (RuntimeException | NoSuchAlgorithmException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @PostMapping("/register-ca-user")
    public ResponseEntity<String> registerCAUser(@Valid @RequestBody RegistrationDto registrationDto, HttpServletRequest request) {
        if (!isAdmin(request)) {
            return new ResponseEntity<>("Only admins can register CA users.", HttpStatus.FORBIDDEN);
        }

        try {
            userService.registerCAUser(registrationDto);
            return new ResponseEntity<>("CA User successfully registered.", HttpStatus.CREATED);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("/create-ssl-keystore")
    public ResponseEntity<String> createSslKeystore(HttpServletRequest request) {
        if (!isAdmin(request)) {
            return new ResponseEntity<>("Only admins can create SSL keystore.", HttpStatus.FORBIDDEN);
        }

        try {
            KeyPair keyPair = generateKeyPair();

            X500Name subjectName = new X500Name("CN=localhost, O=BSEP, L=Novi Sad, ST=Vojvodina, C=RS");
            java.math.BigInteger serialNumber = java.math.BigInteger.valueOf(System.currentTimeMillis());

            LocalDateTime now = LocalDateTime.now();
            Date startDate = Date.from(now.atZone(ZoneId.systemDefault()).toInstant());
            Date endDate = Date.from(now.plusDays(365).atZone(ZoneId.systemDefault()).toInstant());

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subjectName,
                    serialNumber,
                    startDate,
                    endDate,
                    subjectName,
                    keyPair.getPublic()
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword.toCharArray());
            keyStore.setKeyEntry("server-alias", keyPair.getPrivate(), keystorePassword.toCharArray(), new Certificate[]{certificate});

            try (FileOutputStream fos = new FileOutputStream("src/main/resources/keystore/pki-system.jks")) {
                keyStore.store(fos, keystorePassword.toCharArray());
            }

            return new ResponseEntity<>("SSL keystore successfully created.", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Failed to create SSL keystore: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private boolean isAdmin(HttpServletRequest request) {
        String token = request.getHeader("Authorization").substring(7);
        UserRole role = jwtProvider.getRoleFromToken(token);
        System.out.println("Role from token: " + role);
        return role == UserRole.ADMIN;
    }
}