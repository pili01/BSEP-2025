package com.bsep.pki.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PasswordShareDto {
    private Long userId;
    @NotBlank(message = "Encrypted password must not be blank")
    private String encryptedPassword;
}
