package com.bsep.pki.services;

import com.bsep.pki.models.VerificationToken;
import com.bsep.pki.repositories.VerificationRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class VerificationService {
    private final VerificationRepository verificationRepository;

    public VerificationService(VerificationRepository verificationRepository) {
        this.verificationRepository = verificationRepository;
    }

    public Optional<VerificationToken> getVerificationByToken(String token) {
        return verificationRepository.findByToken(token);
    }

    public VerificationToken save(VerificationToken token) {
        return verificationRepository.save(token);
    }

    @Transactional
    public void markTokenAsUsed(String token) {
        int updatedRows = verificationRepository.setUsedTrue(token);
        if (updatedRows == 1) {
            return;
        }
        throw new RuntimeException("Error marking token as used");
    }

    public String checkToken(String token) {
        VerificationToken savedToken = verificationRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));
        if (savedToken.isUsed()) {
            throw new RuntimeException("Token already used");
        }
        if (savedToken.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Token expired");
        }
        return savedToken.getUserEmail();
    }
}
