package com.bsep.pki.repositories;

import com.bsep.pki.models.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerificationRepository extends JpaRepository<VerificationToken, String> {
    Optional<VerificationToken> findByToken(String token);

    @Modifying
    @Query("UPDATE VerificationToken v SET v.used = true WHERE v.token = :token")
    int setUsedTrue(String token);

    Optional<VerificationToken> findByUserEmailAndUsedFalse(String userEmail);
}
