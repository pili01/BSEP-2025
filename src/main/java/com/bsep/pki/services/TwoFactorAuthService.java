package com.bsep.pki.services;

import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.utils.QRCodeGenerator;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class TwoFactorAuthService {

    @Value("${app.2fa.secret}")
    private String keyForEncoding2FASecret;

    private String userSecret;  // Originalni Base32 secret pre enkripcije
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
    private final KeystoreEncryptionService keystoreEncryptionService;
    private final QRCodeGenerator qrCodeGenerator;

    public TwoFactorAuthService(KeystoreEncryptionService keystoreEncryptionService, QRCodeGenerator qrCodeGenerator) {
        this.keystoreEncryptionService = keystoreEncryptionService;
        this.qrCodeGenerator = qrCodeGenerator;
    }

    public void generateSecretKey() { //Pozivamo pri omogucavanju 2FA za korisnika
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        userSecret = key.getKey(); // Base32 string koji sifrujem sa AFS i cuvam u bazi
    }

    public String getEncryptedSecret() throws Exception {  // Metoda koja vraca enkriptovani Base32 secret koji cuvam u bazi
        return keystoreEncryptionService.encrypt(userSecret, keyForEncoding2FASecret);
    }

    public String getQRBarkode(String userEmail) throws Exception {
        String otpAuthURL = "otpauth://totp/" + "BSEP" + ":" + userEmail
                + "?secret=" + userSecret + "&issuer=" + "BSEP2025";

        return qrCodeGenerator.generateQRCode(otpAuthURL, 200, 200);
    }

    public boolean verifyCode(String encryptedUserSecret, int code) throws Exception {
        String decryptedSecret = keystoreEncryptionService.decrypt(encryptedUserSecret, keyForEncoding2FASecret);
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        return gAuth.authorize(decryptedSecret, code);
    }

}
