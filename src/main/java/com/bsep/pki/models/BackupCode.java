package com.bsep.pki.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "backup_codes")
public class BackupCode {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String code;

    @Column(nullable = false)
    private String userEmail;

    @Column(nullable = false)
    private boolean used = false;

    public BackupCode(String code, String userEmail) {
        this.code = code;
        this.userEmail = userEmail;
    }
}
