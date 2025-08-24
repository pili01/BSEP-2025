package com.bsep.pki.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import java.util.Optional;

public class CsrRequestDto {

    @NotBlank(message = "CSR PEM content must not be blank")
    private String csrPemContent;
    
    @NotBlank(message = "Common name must not be blank")
    private String commonName;
    
    @NotBlank(message = "Target user email must not be blank")
    @Email(message = "Target user email must be valid")
    private String targetUserEmail;
    
    private Optional<Long> templateId = Optional.empty();
    
    @Positive(message = "Validity in days must be a positive number")
    private long validityInDays;
    
    @NotBlank(message = "Organization must not be blank")
    private String organization;
    
    @NotBlank(message = "CA issuer serial number must not be blank")
    private String caIssuerSerialNumber;
    
    private String keyUsage;
    private String extendedKeyUsage;
    
    private String status = "PENDING"; // PENDING, APPROVED, REJECTED


    public CsrRequestDto() {}

    // Getters and Setters
    public String getCsrPemContent() {
        return csrPemContent;
    }

    public void setCsrPemContent(String csrPemContent) {
        this.csrPemContent = csrPemContent;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getTargetUserEmail() {
        return targetUserEmail;
    }

    public void setTargetUserEmail(String targetUserEmail) {
        this.targetUserEmail = targetUserEmail;
    }

    public Optional<Long> getTemplateId() {
        return templateId;
    }

    public void setTemplateId(Optional<Long> templateId) {
        this.templateId = templateId;
    }

    public long getValidityInDays() {
        return validityInDays;
    }

    public void setValidityInDays(long validityInDays) {
        this.validityInDays = validityInDays;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getCaIssuerSerialNumber() {
        return caIssuerSerialNumber;
    }

    public void setCaIssuerSerialNumber(String caIssuerSerialNumber) {
        this.caIssuerSerialNumber = caIssuerSerialNumber;
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
    
    public String getStatus() {
        return status;
    }
    
    public void setStatus(String status) {
        this.status = status;
    }

}
