package com.bsep.pki.models;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "csr_requests")
public class CsrRequest {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(columnDefinition = "TEXT")
    private String csrPemContent;
    
    private String commonName;
    private String organization;
    private String status; // PENDING, APPROVED, REJECTED, EXPIRED
    
    @ManyToOne
    @JoinColumn(name = "target_user_id")
    private User targetUser;
    
    @ManyToOne
    @JoinColumn(name = "uploading_user_id")
    private User uploadingUser;
    
    private LocalDateTime uploadDate;
    private LocalDateTime approvalDate;
    private String rejectionReason;

    private String publicKeyAlgorithm;
    private int keyLength;
    
    @Column
    private String keyUsage;
    
    @Column
    private String extendedKeyUsage;
    
    private long validityInDays;
    private String caIssuerSerialNumber;
    

    public CsrRequest() {}
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
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
    
    public User getTargetUser() {
        return targetUser;
    }
    
    public void setTargetUser(User targetUser) {
        this.targetUser = targetUser;
    }
    
    public User getUploadingUser() {
        return uploadingUser;
    }
    
    public void setUploadingUser(User uploadingUser) {
        this.uploadingUser = uploadingUser;
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
