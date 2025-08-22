package com.bsep.pki.services;

import com.bsep.pki.models.User;
import com.bsep.pki.repositories.UserRepository;
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
    
    public void sendPasswordResetEmail(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            

            user.setPasswordResetRequested(LocalDateTime.now());
            userRepository.save(user);
            

            String resetLink = "http://localhost:8080/api/auth/reset-password?email=" + user.getEmail();
            emailService.sendPasswordResetEmail(user, resetLink);
        }
    }
    
    public boolean resetPassword(String email, String newPassword) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            

            if (user.getPasswordResetRequested() == null) {
                throw new RuntimeException("Password reset not requested");
            }
            

            if (user.getPasswordResetRequested().plusHours(24).isBefore(LocalDateTime.now())) {
                throw new RuntimeException("Password reset link has expired");
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
