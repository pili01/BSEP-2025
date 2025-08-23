package com.bsep.pki.models;

import jakarta.persistence.*;

@Entity
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
    private String sansRegex; // Vraćeno

    @Column(nullable = false)
    private long maxValidityDays;

    @Column
    private String keyUsage;

    @Column
    private String extendedKeyUsage; // Vraćeno

    public CertificateTemplate() {
    }

    // Getteri i seteri

    public String getSansRegex() {
        return sansRegex;
    }

    public void setSansRegex(String sansRegex) {
        this.sansRegex = sansRegex;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public void setExtendedKeyUsage(String extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTemplateName() {
        return templateName;
    }

    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    public String getCaIssuerSerialNumber() {
        return caIssuerSerialNumber;
    }

    public void setCaIssuerSerialNumber(String caIssuerSerialNumber) {
        this.caIssuerSerialNumber = caIssuerSerialNumber;
    }

    public String getCommonNameRegex() {
        return commonNameRegex;
    }

    public void setCommonNameRegex(String commonNameRegex) {
        this.commonNameRegex = commonNameRegex;
    }

    public long getMaxValidityDays() {
        return maxValidityDays;
    }

    public void setMaxValidityDays(long maxValidityDays) {
        this.maxValidityDays = maxValidityDays;
    }
}