package com.bsep.pki.services;

import com.bsep.pki.models.BackupCode;
import com.bsep.pki.repositories.BackupCodeRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class BackupCodeService {
    private final BackupCodeRepository backupCodeRepository;

    public BackupCodeService(BackupCodeRepository backupCodeRepository) {
        this.backupCodeRepository = backupCodeRepository;
    }

    @Transactional
    public void saveBacupCodes(String userEmail, List<BackupCode> codes) {
        if (codes == null || codes.size() != 5) {
            throw new IllegalArgumentException("There must be exactly 5 backup codes.");
        }
        backupCodeRepository.removeOldCodes(userEmail);
        backupCodeRepository.saveAll(codes);
    }

    public List<BackupCode> getUserBackupCodes(String userEmail) {
        return backupCodeRepository.findUserCodes(userEmail);
    }

    @Transactional
    public void useBackupCode(BackupCode code) {
        code.setUsed(true);
        backupCodeRepository.save(code);
    }
}
