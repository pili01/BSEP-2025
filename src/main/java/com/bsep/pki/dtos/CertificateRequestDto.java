package com.bsep.pki.dtos;

import com.bsep.pki.models.CertificateType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Data
@NoArgsConstructor
public class CertificateRequestDto {

    private Optional<String> targetUserEmail;

    @NotBlank(message = "Common name must not be blank")
    private String commonName;

    @NotBlank(message = "Organization must not be blank")
    private String organization;

    private Optional<Long> templateId = Optional.empty();

    @Positive(message = "Validity in days must be a positive number")
    private long validityInDays;

    @NotNull(message = "Certificate type must not be null")
    private CertificateType type;

    private Optional<String> issuerSerialNumber = Optional.empty();

    private List<String> keyUsage = new ArrayList<>();

    private List<String> extendedKeyUsage = new ArrayList<>();

}