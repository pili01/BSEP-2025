package com.bsep.pki.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegistrationDto {

    @NotBlank(message = "Email must not be blank.")
    @Email(message = "Email must be valid.")
    private String email;

    @NotBlank(message = "Password must not be blank.")
    @Size(min = 8, message = "Password must have at least 8 characters.")
    private String password;

    @NotBlank(message = "First name must not be blank.")
    private String firstName;

    @NotBlank(message = "Last name must not be blank.")
    private String lastName;

    @NotBlank(message = "Organization must not be blank.")
    private String organization;
}