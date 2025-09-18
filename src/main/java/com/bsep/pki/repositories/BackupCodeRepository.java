package com.bsep.pki.repositories;

import com.bsep.pki.models.BackupCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BackupCodeRepository extends JpaRepository<BackupCode, String> {

    @Modifying
    @Query("DELETE FROM BackupCode bc WHERE bc.userEmail = ?1")
    void removeOldCodes(String userEmail);

    @Query("SELECT bc FROM BackupCode bc WHERE bc.userEmail = ?1")
    List<BackupCode> findUserCodes(String userEmail);
}
