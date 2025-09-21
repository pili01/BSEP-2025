package com.bsep.pki.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
public class StoredPasswordDto {
    private String id;
    @NotBlank
    private String username;
    @NotBlank
    private String siteName;
    private Long ownerId;

    private Instant created_at;
    private Instant updated_at;
    private Long created_by;
    private Long updated_by;

    @Size(min = 1, message = "Shares list must not be empty")
    private List<PasswordShareDto> shares;

    public void setUpMetadataForCreation() {
        Instant now = Instant.now();
        this.created_at = now;
        this.updated_at = now;
        this.created_by = ownerId;
        this.updated_by = ownerId;
        for (PasswordShareDto share : shares) {
            share.setCreated_at(now);
            share.setCreated_by(ownerId);
        }
    }
}
