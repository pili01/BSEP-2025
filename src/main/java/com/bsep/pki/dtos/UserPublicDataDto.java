package com.bsep.pki.dtos;

import com.bsep.pki.models.UserRole;
import lombok.Data;

@Data
public class UserPublicDataDto {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String organization;
    private boolean twoFactorEnabled;
    private UserRole role;
    private String publicKey;
}
