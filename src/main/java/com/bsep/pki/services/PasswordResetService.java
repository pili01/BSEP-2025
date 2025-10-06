package com.bsep.pki.services;

import com.bsep.pki.dtos.PasswordResetDto;
import com.bsep.pki.models.User;
import com.bsep.pki.models.VerificationToken;
import com.bsep.pki.repositories.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class PasswordResetService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private VerificationService verificationService;

    public void sendPasswordResetEmail(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();


            user.setPasswordResetRequested(LocalDateTime.now());
            userRepository.save(user);

            VerificationToken token = verificationService.save(new VerificationToken(user.getEmail()));
            if (token == null) throw new RuntimeException("Error creating verification token");
            String resetLink = "https://localhost:5173/reset-password?token=" + token.getToken() + "&email=" + user.getEmail();
            emailService.sendPasswordResetEmail(user, resetLink);
        }else{
            throw new RuntimeException("No user with that email");
        }
    }

    @Transactional
    public boolean resetPassword(PasswordResetDto passwordResetDto) {
        String token = passwordResetDto.getToken();
        String email = verificationService.checkToken(token);
        String newPassword = passwordResetDto.getPassword();
        if (!email.equals(passwordResetDto.getEmail())) {
            throw new RuntimeException("Token email and provided email do not match");
        }
        verificationService.markTokenAsUsed(token);

        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            User user = userOptional.get();


            if (!user.isVerified()) {
                throw new RuntimeException("User is not verified.");
            }

//            if (user.getCreatedAt().plusHours(24).isBefore(LocalDateTime.now())) {
//                throw new RuntimeException("Password-reset link has expired. Please sent new link.");
//            }

            if (user.getPasswordResetRequested() == null) {
                throw new RuntimeException("Password reset not requested");
            }

            user.setPassword(passwordEncoder.encode(newPassword));
            user.setPasswordResetRequested(null);
            user.setPasswordChanged(true);
            userRepository.save(user);
            return true;
        }

        return false;
    }
}
