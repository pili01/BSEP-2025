package com.bsep.pki.dtos;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.util.Pair;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetDto {

    @NotBlank(message = "Token must not be blank.")
    private String token;

    @NotBlank(message = "Email must not be blank.")
    @Email(message = "Email must be valid.")
    private String email;

    @NotBlank(message = "Password must not be blank.")
    @Size(min = 8, message = "Password must have at least 8 characters.")
    private String password;

    @NotBlank(message = "Repeated password must not be blank.")
    @Size(min = 8, message = "Repeated password must have at least 8 characters.")
    private String confirmPassword;

    public Pair<Boolean, String> isPasswordValid() {
        if (getPassword() == null) return Pair.of(false, "Password is null.");
        if (getConfirmPassword() == null) return Pair.of(false, "Confirm password is null.");
        if (!getPassword().equals(getConfirmPassword())) return Pair.of(false, "Passwords do not match.");
        if (password.length() < 8 || password.length() > 64)
            return Pair.of(false, "Password must be between 8 and 64 characters long.");
        // Uppercase (Unicode)
        if (!password.matches(".*\\p{Lu}.*"))
            return Pair.of(false, "Password must contain at least one uppercase letter.");

        // Lowercase (Unicode)
        if (!password.matches(".*\\p{Ll}.*"))
            return Pair.of(false, "Password must contain at least one lowercase letter.");

        // Number (digit, Unicode-aware)
        if (!password.matches(".*\\p{Nd}.*")) return Pair.of(false, "Password must contain at least one digit.");

        // Special char (sve što NIJE slovo ili cifra)
        if (!password.matches(".*[^\\p{L}\\p{Nd}].*"))
            return Pair.of(false, "Password must contain at least one special character.");

        Zxcvbn zxcvbn = new Zxcvbn();
        Strength strength = zxcvbn.measure(password);
        return strength.getScore() >= 2 ? Pair.of(true, "") : Pair.of(false, "Password is too weak.");  // Fair ili bolje
    }
}
