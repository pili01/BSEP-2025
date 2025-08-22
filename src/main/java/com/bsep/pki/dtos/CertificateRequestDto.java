package com.bsep.pki.dtos;

import com.bsep.pki.models.CertificateType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.util.Optional;

public class CertificateRequestDto {

    @NotBlank(message = "Common name must not be blank")
    private String commonName;

    @NotBlank(message = "Organization must not be blank")
    private String organization;

    @Positive(message = "Validity in days must be a positive number")
    private long validityInDays;

    @NotNull(message = "Certificate type must not be null")
    private CertificateType type;

    private Optional<String> issuerSerialNumber = Optional.empty();

    public CertificateRequestDto() {}

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public long getValidityInDays() {
        return validityInDays;
    }

    public void setValidityInDays(long validityInDays) {
        this.validityInDays = validityInDays;
    }

    public CertificateType getType() {
        return type;
    }

    public void setType(CertificateType type) {
        this.type = type;
    }

    public Optional<String> getIssuerSerialNumber() {
        return issuerSerialNumber;
    }

    public void setIssuerSerialNumber(Optional<String> issuerSerialNumber) {
        this.issuerSerialNumber = issuerSerialNumber;
    }
}