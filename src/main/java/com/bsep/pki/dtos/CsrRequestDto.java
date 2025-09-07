package com.bsep.pki.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Optional;

@Data
@NoArgsConstructor
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
}
