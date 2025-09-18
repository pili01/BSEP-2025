package com.bsep.pki.utils;
import java.security.SecureRandom;
import java.util.Base64;

public class TokenGenerator {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static String generateToken() {
        byte[] randomBytes = new byte[32]; // 256-bit token
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}

