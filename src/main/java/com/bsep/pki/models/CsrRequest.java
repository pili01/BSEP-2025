package com.bsep.pki.models;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
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

}
