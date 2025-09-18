package com.bsep.pki.services;

import com.bsep.pki.models.BackupCode;
import com.bsep.pki.repositories.BackupCodeRepository;
import com.bsep.pki.utils.QRCodeGenerator;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class TwoFactorAuthService {

    @Value("${app.2fa.secret}")
    private String keyForEncoding2FASecret;

    private String userSecret;  // Originalni Base32 secret pre enkripcije
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
    private final KeystoreEncryptionService keystoreEncryptionService;
    private final QRCodeGenerator qrCodeGenerator;
    private final BackupCodeService backupCodeService;

    public TwoFactorAuthService(KeystoreEncryptionService keystoreEncryptionService, QRCodeGenerator qrCodeGenerator, BackupCodeService backupCodeService) {
        this.keystoreEncryptionService = keystoreEncryptionService;
        this.qrCodeGenerator = qrCodeGenerator;
        this.backupCodeService = backupCodeService;
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

    public boolean verifyCode(String encryptedUserSecret, int code, String userEmail) throws Exception {
        String decryptedSecret = keystoreEncryptionService.decrypt(encryptedUserSecret, keyForEncoding2FASecret);
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        if (gAuth.authorize(decryptedSecret, code)) {
            return true;
        }
        return verifyBackupCode(userEmail, String.valueOf(code));
    }

    @Transactional
    public List<String> generateBackupCodes(String userEmail) throws Exception {
        List<BackupCode> backupCodes = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            int code = (int) (Math.random() * 900000) + 100000; // Generate a random 6-digit code
            String codeStr = String.valueOf(code);

            BackupCode backupCode = new BackupCode(keystoreEncryptionService.encrypt(codeStr, keyForEncoding2FASecret), userEmail);
            backupCodes.add(backupCode);
        }
        backupCodeService.saveBacupCodes(userEmail, backupCodes);
        return decryptBackupCodes(backupCodeService.getUserBackupCodes(userEmail));
    }

    public List<String> decryptBackupCodes(List<BackupCode> encryptedCodes) throws Exception {
        List<String> decryptedCodes = new ArrayList<>();
        for (BackupCode encryptedCode : encryptedCodes) {
            String decryptedCode = keystoreEncryptionService.decrypt(encryptedCode.getCode(), keyForEncoding2FASecret);
            decryptedCodes.add(decryptedCode);
        }
        return decryptedCodes;
    }

    @Transactional
    public boolean verifyBackupCode(String userEmail, String code) throws Exception {
        List<BackupCode> userCodes = backupCodeService.getUserBackupCodes(userEmail);
        String decryptedCode = keystoreEncryptionService.encrypt(code, keyForEncoding2FASecret);

        BackupCode backupCode = userCodes.stream()
                .filter(c -> c.getCode().equals(decryptedCode) && !c.isUsed())
                .findFirst()
                .orElse(null);
        if (backupCode != null) {
            // Ako je backup kod ispravan, označi ga kao iskorišćen
            backupCodeService.useBackupCode(backupCode);
            return true;
        } else {
            return false;
        }
    }

}
