package com.bsep.pki.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
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

}
