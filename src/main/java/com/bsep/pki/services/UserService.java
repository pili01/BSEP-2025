package com.bsep.pki.services;

import com.bsep.pki.dtos.LoginDto;
import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.models.User;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
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


    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }



    public User registerAdmin(RegistrationDto registrationDto) throws NoSuchAlgorithmException {
        if (userRepository.findByEmail(registrationDto.getEmail()).isPresent()) {
            throw new RuntimeException("Email is already in use.");
        }

        User admin = new User();
        admin.setEmail(registrationDto.getEmail());
        admin.setPassword(passwordEncoder.encode(registrationDto.getPassword()));
        admin.setFirstName(registrationDto.getFirstName());
        admin.setLastName(registrationDto.getLastName());
        admin.setOrganization(registrationDto.getOrganization());
        admin.setRole(UserRole.ADMIN);
        admin.setVerified(true);
        admin.setPasswordChanged(false);
        generateAndSetEncryptionKey(admin);

        return userRepository.save(admin);
    }

    public User registerCAUser(RegistrationDto registrationDto) throws NoSuchAlgorithmException {
        if (userRepository.findByEmail(registrationDto.getEmail()).isPresent()) {
            throw new RuntimeException("Email is already in use.");
        }

        User caUser = new User();
        caUser.setEmail(registrationDto.getEmail());
        caUser.setPassword(passwordEncoder.encode(registrationDto.getPassword()));
        caUser.setFirstName(registrationDto.getFirstName());
        caUser.setLastName(registrationDto.getLastName());
        caUser.setOrganization(registrationDto.getOrganization());
        caUser.setRole(UserRole.CA_USER);
        caUser.setVerified(true);
        caUser.setPasswordChanged(false);
        generateAndSetEncryptionKey(caUser);

        return userRepository.save(caUser);
    }

    private void generateAndSetEncryptionKey(User user) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        user.setSalt(Base64.getEncoder().encodeToString(salt));

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        user.setEncryptionKey(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
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

            if (user.getCreatedAt().plusHours(24).isBefore(LocalDateTime.now())) {
                throw new RuntimeException("Verification link has expired. Please register again.");
            }


            user.setVerified(true);
            userRepository.save(user);
            return true;
        }

        return false;
    }

    public Optional<User> findByEmail(String userEmail) {
        return userRepository.findByEmail(userEmail);
    }
}