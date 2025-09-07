package com.bsep.pki.models;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@Table(name = "certificate_templates")
public class CertificateTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String templateName;

    @Column
    private String caIssuerSerialNumber;

    @Column
    private String commonNameRegex;

    @Column
    private String sansRegex;

    @Column(nullable = false)
    private long maxValidityDays;

    @Column
    private String keyUsage;

    @Column
    private String extendedKeyUsage;

}