package com.bsep.pki.dtos;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class StoredPasswordDto {
    private String id;
    @NotBlank
    private String username;
    @NotBlank
    private String siteName;
    private Long ownerId;

    @Size(min = 1, message = "Shares list must not be empty")
    private List<PasswordShareDto> shares;
}
