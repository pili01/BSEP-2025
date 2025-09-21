package com.bsep.pki.services;

import com.bsep.pki.dtos.PasswordShareDto;
import com.bsep.pki.dtos.StoredPasswordDto;
import com.bsep.pki.models.PasswordShare;
import com.bsep.pki.models.StoredPassword;
import com.bsep.pki.repositories.StoredPasswordRepository;
import jakarta.validation.Valid;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeToken;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class StoredPasswordService {
    private final StoredPasswordRepository storedPasswordRepository;
    private final ModelMapper modelMapper;

    public StoredPasswordService(StoredPasswordRepository storedPasswordRepository, ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
        this.storedPasswordRepository = storedPasswordRepository;
    }

    public void savePassword(@Valid StoredPasswordDto storedPasswordDto) {
        storedPasswordDto.setUpMetadataForCreation();
        StoredPassword entity = modelMapper.map(storedPasswordDto, StoredPassword.class);
        storedPasswordRepository.save(entity);
    }

    public List<StoredPasswordDto> getMyPasswords(Long id) {
        return modelMapper.map(
                storedPasswordRepository.findAllMyPasswords(id),
                new TypeToken<List<StoredPasswordDto>>() {
                }.getType()
        );
    }

    public void sharePassword(Long ownerId, String storedPasswordId, PasswordShareDto sharedPasswordDto) {
        var storedPassword = storedPasswordRepository.findMyById(ownerId, storedPasswordId);
        if (storedPassword == null) {
            throw new RuntimeException("Stored password not found or you don't have permission to share it");
        }
        if(storedPassword.getShares().stream().anyMatch(share -> share.getUserId().equals(sharedPasswordDto.getUserId()))) {
            throw new RuntimeException("Password already shared with this user");
        }
        var now = Instant.now();
        sharedPasswordDto.setCreated_at(now);
        sharedPasswordDto.setCreated_by(ownerId);
        storedPassword.setUpdated_at(now);
        storedPassword.setUpdated_by(ownerId);

        var share = modelMapper.map(sharedPasswordDto, PasswordShare.class);
        storedPassword.getShares().add(share);
        storedPasswordRepository.save(storedPassword);
    }
}
