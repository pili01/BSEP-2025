package com.bsep.pki.services;

import com.bsep.pki.dtos.LoginDto;
import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.models.User;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
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

        return userRepository.save(user);
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
}