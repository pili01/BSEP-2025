package com.bsep.pki.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordShare {
    private Long userId;
    private String encryptedPassword;
}
