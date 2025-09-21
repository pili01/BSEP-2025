package com.bsep.pki.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordShare {
    private Long userId;
    private String encryptedPassword;
    private Instant created_at;
    private Long created_by;
}
