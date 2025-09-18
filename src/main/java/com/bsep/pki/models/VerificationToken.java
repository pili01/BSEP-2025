package com.bsep.pki.models;

import com.bsep.pki.utils.TokenGenerator;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name = "verification_tokens")
public class VerificationToken {
    @Id
    private String token;
    @Column(nullable = false)
    private String userEmail;
    @Column(nullable = false)
    private Instant expiryDate;
    @Column(nullable = false)
    private boolean used = false;

    public VerificationToken(String userEmail) {
        this.token = TokenGenerator.generateToken();
        this.userEmail = userEmail;
        this.expiryDate = Instant.now().plus(1, ChronoUnit.DAYS);
    }
}
