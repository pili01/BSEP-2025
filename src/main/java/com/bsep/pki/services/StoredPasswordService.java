package com.bsep.pki.services;

import com.bsep.pki.dtos.StoredPasswordDto;
import com.bsep.pki.models.StoredPassword;
import com.bsep.pki.repositories.StoredPasswordRepository;
import jakarta.validation.Valid;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeToken;
import org.springframework.stereotype.Service;

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
}
