package com.bsep.pki.dtos;

import java.time.LocalDateTime;

public class CsrResponseDto {
    
    private Long id;
    private String commonName;
    private String organization;
    private String status;
    private String targetUserEmail;
    private String uploadingUserEmail;
    private LocalDateTime uploadDate;
    private LocalDateTime approvalDate;
    private String rejectionReason;
    private String publicKeyAlgorithm;
    private int keyLength;
    private String keyUsage;
    private String extendedKeyUsage;
    private long validityInDays;
    private String caIssuerSerialNumber;


    public CsrResponseDto() {}


    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
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
    
    public String getStatus() {
        return status;
    }
    
    public void setStatus(String status) {
        this.status = status;
    }
    
    public String getTargetUserEmail() {
        return targetUserEmail;
    }
    
    public void setTargetUserEmail(String targetUserEmail) {
        this.targetUserEmail = targetUserEmail;
    }
    
    public String getUploadingUserEmail() {
        return uploadingUserEmail;
    }
    
    public void setUploadingUserEmail(String uploadingUserEmail) {
        this.uploadingUserEmail = uploadingUserEmail;
    }
    
    public LocalDateTime getUploadDate() {
        return uploadDate;
    }
    
    public void setUploadDate(LocalDateTime uploadDate) {
        this.uploadDate = uploadDate;
    }
    
    public LocalDateTime getApprovalDate() {
        return approvalDate;
    }
    
    public void setApprovalDate(LocalDateTime approvalDate) {
        this.approvalDate = approvalDate;
    }
    
    public String getRejectionReason() {
        return rejectionReason;
    }
    
    public void setRejectionReason(String rejectionReason) {
        this.rejectionReason = rejectionReason;
    }
    
    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }
    
    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }
    
    public int getKeyLength() {
        return keyLength;
    }
    
    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
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
    
    public long getValidityInDays() {
        return validityInDays;
    }
    
    public void setValidityInDays(long validityInDays) {
        this.validityInDays = validityInDays;
    }
    
    public String getCaIssuerSerialNumber() {
        return caIssuerSerialNumber;
    }
    
    public void setCaIssuerSerialNumber(String caIssuerSerialNumber) {
        this.caIssuerSerialNumber = caIssuerSerialNumber;
    }
}
