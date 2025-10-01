package com.bsep.pki.services;

import com.bsep.pki.dtos.LoginDto;
import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.dtos.UserPublicDataDto;
import com.bsep.pki.models.User;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.models.VerificationToken;
import com.bsep.pki.repositories.UserRepository;
import jakarta.transaction.Transactional;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final VerificationService verificationService;
    private final TwoFactorAuthService twoFactorAuthService;
    private final ModelMapper modelMapper;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailService emailService, VerificationService verificationService, TwoFactorAuthService twoFactorAuthService, ModelMapper modelMapper) {
        this.twoFactorAuthService = twoFactorAuthService;
        this.verificationService = verificationService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.modelMapper = modelMapper;
    }

    @Transactional
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

        VerificationToken token = verificationService.save(new VerificationToken(user.getEmail()));
        if (token == null) throw new RuntimeException("Error creating verification token");
        String verificationLink = "https://localhost:5173/verify-email?token=" + token.getToken();
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

    @Transactional
    public boolean verifyUser(String token) {
        String email = verificationService.checkToken(token);
        verificationService.markTokenAsUsed(token);

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

    @Transactional
    public String enableTwoFactorAuth(String email) throws Exception {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.isTwoFactorEnabled()) {
                throw new RuntimeException("Two-factor authentication is already enabled.");
            }
            twoFactorAuthService.generateSecretKey();
            user.setTwoFactorSecret(twoFactorAuthService.getEncryptedSecret());

            String image = twoFactorAuthService.getQRBarkode(user.getEmail());
            userRepository.save(user);
            return image;
        } else {
            throw new RuntimeException("User not found.");
        }
    }

    @Transactional
    public void verifyTwoFactorAuth(String email, int code) throws Exception {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (user.isTwoFactorEnabled()) {
                throw new RuntimeException("Two-factor authentication is already enabled.");
            }
            if (!twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), code, user.getEmail())) {
                throw new RuntimeException("Invalid 2FA code.");
            }

            user.setTwoFactorEnabled(true);
            userRepository.save(user);
        } else {
            throw new RuntimeException("User not found.");
        }
    }

    @Transactional
    public void disableTwoFactorAuth(String email) throws Exception {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (!user.isTwoFactorEnabled()) {
                throw new RuntimeException("Two-factor authentication is already disabled.");
            }
            user.setTwoFactorEnabled(false);
            user.setTwoFactorSecret(null);

            userRepository.save(user);
        } else {
            throw new RuntimeException("User not found.");
        }
    }

    public Optional<User> findByEmail(String userEmail) {
        return userRepository.findByEmail(userEmail);
    }

    public UserPublicDataDto getUserPublicData(Long userId) {
        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        return modelMapper.map(user.get(), UserPublicDataDto.class);
    }

    public List<UserPublicDataDto> getAllRegularUsers() {
        List<User> users = userRepository.findAll().stream()
                .filter(user -> user.getRole() == UserRole.REGULAR_USER)
                .toList();
        return users.stream()
                .map(user -> modelMapper.map(user, UserPublicDataDto.class))
                .toList();
    }

    public void savePublicKey(@NotBlank @Email String email, String publicKey) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if(user.getPublicKey()!=null)
                throw new RuntimeException("Public key is already set and cannot be changed.");
            user.setPublicKey(publicKey);
            userRepository.save(user);
        } else {
            throw new RuntimeException("User not found.");
        }
    }
}