package com.bsep.pki.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@Table(name = "certificates")
public class Certificate {
    @Id
    private String serialNumber;

    @Column(nullable = false)
    private String subjectName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @JsonIgnore
    private User user;

    @Column(nullable = false)
    private String issuerName;

    @Column(nullable = false)
    private LocalDateTime startDate;

    @Column(nullable = false)
    private LocalDateTime endDate;

    @Column(nullable = false)
    private boolean isRevoked;

    @Column
    @Enumerated(EnumType.STRING)
    private RevokedReason revokedReason;

    @Column
    private LocalDateTime revokedAt;

    @Enumerated(EnumType.STRING)
    private CertificateType type;

    @Column
    private String organization;

    @Column
    private String keystorePath;

    @Column
    private String alias;

    @Column
    private String keyUsage;

    @Column
    private String extendedKeyUsage;

    @Column
    private String sansRegex;

    @Column
    private String issuerSerialNumber;

    @Column(name = "keystore_password", nullable = true)
    private String keystorePassword;
}