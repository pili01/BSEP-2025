package com.bsep.pki.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class KeystoreEncryptionService {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGORITHM = "AES";

    private static final IvParameterSpec IV = new IvParameterSpec(new byte[16]);

    @Value("${master.encryption.key}")
    private String masterEncryptionKey;

    public String generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    public String encrypt(String data, String keyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV);

        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedData, String keyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IV);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts a user encryption key using the master encryption key from configuration.
     * This adds an additional layer of security by ensuring user encryption keys
     * are not stored in plain text in the database.
     *
     * @param userEncryptionKey The user's encryption key to encrypt
     * @return The encrypted user encryption key
     * @throws Exception if encryption fails
     */
    public String encryptUserKey(String userEncryptionKey) throws Exception {
        if (masterEncryptionKey == null || masterEncryptionKey.isEmpty()) {
            throw new IllegalStateException("Master encryption key is not configured in application.properties! Please set 'master.encryption.key' property.");
        }
        
        try {
            // Validate that master key is proper Base64
            byte[] keyBytes = Base64.getDecoder().decode(masterEncryptionKey);
            if (keyBytes.length != 16) {
                throw new IllegalStateException("Master encryption key must be exactly 16 bytes (128 bits) when decoded from Base64. Current size: " + keyBytes.length + " bytes");
            }
            return encrypt(userEncryptionKey, masterEncryptionKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Master encryption key is not valid Base64! Key value: " + masterEncryptionKey, e);
        }
    }

    /**
     * Decrypts a user encryption key that was encrypted with the master encryption key.
     * This is needed to retrieve the actual user encryption key for encrypting/decrypting
     * keystore passwords.
     *
     * @param encryptedUserKey The encrypted user encryption key from database
     * @return The decrypted user encryption key
     * @throws Exception if decryption fails
     */
    public String decryptUserKey(String encryptedUserKey) throws Exception {
        return decrypt(encryptedUserKey, masterEncryptionKey);
    }
}