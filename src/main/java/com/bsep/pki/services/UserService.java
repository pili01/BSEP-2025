package com.bsep.pki.services;

import com.bsep.pki.dtos.LoginDto;
import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.models.User;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.services.EmailService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService=emailService;
    }

    public User registerUser(RegistrationDto registrationDto) {
        if (userRepository.findByEmail(registrationDto.getEmail()).isPresent()) {
            throw new RuntimeException("Email is already in use.");
        }

        User user = new User();
        user.setEmail(registrationDto.getEmail());
        user.setPassword(passwordEncoder.encode(registrationDto.getPassword()));
        user.setFirstName(registrationDto.getFirstName());
        user.setLastName(registrationDto.getLastName());
        user.setOrganization(registrationDto.getOrganization());
        user.setRole(UserRole.REGULAR_USER);
        user.setVerified(false);
        user.setPasswordChanged(false);


        user = userRepository.save(user);


        String verificationLink = "http://localhost:8080/api/auth/verify?email=" + user.getEmail();
        emailService.sendVerificationEmail(registrationDto, verificationLink);

        return user;
    }

    public Optional<User> loginUser(LoginDto loginDto) {
        Optional<User> userOptional = userRepository.findByEmail(loginDto.getEmail());

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (passwordEncoder.matches(loginDto.getPassword(), user.getPassword())) {
                return userOptional;
            }
        }
        return Optional.empty();
    }

    public boolean verifyUser(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            

            if (user.isVerified()) {
                throw new RuntimeException("User is already verified.");
            }
            
            // Provjera vremena za link 24 sata od reg
            if (user.getCreatedAt().plusHours(24).isBefore(LocalDateTime.now())) {
                throw new RuntimeException("Verification link has expired. Please register again.");
            }
            

            user.setVerified(true);
            userRepository.save(user);
            return true;
        }
        
        return false;
    }
}