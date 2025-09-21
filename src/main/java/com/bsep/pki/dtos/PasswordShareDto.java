package com.bsep.pki.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.time.Instant;

@Data
public class PasswordShareDto {
    private Long userId;
    @NotBlank(message = "Encrypted password must not be blank")
    private String encryptedPassword;
    private Instant created_at;
    private Long created_by;
}
