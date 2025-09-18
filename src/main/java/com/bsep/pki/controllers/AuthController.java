package com.bsep.pki.controllers;

import com.bsep.pki.dtos.Code2FADto;
import com.bsep.pki.dtos.LoginDto;
import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.dtos.PasswordResetDto;
import com.bsep.pki.models.User;
import com.bsep.pki.services.*;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtProvider jwtProvider;
    private final UserSessionService userSessionService;
    private final PasswordResetService passwordResetService;
    private final Recaptcha recaptcha;
    private final TwoFactorAuthService twoFactorAuthService;

    public AuthController(UserService userService, JwtProvider jwtProvider, UserSessionService userSessionService, PasswordResetService passwordResetService, Recaptcha recaptcha, TwoFactorAuthService twoFactorAuthService) {
        this.twoFactorAuthService = twoFactorAuthService;
        this.userService = userService;
        this.jwtProvider = jwtProvider;
        this.userSessionService = userSessionService;
        this.passwordResetService = passwordResetService;
        this.recaptcha = recaptcha;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegistrationDto registrationDto) {
        try {
            var validationResult = registrationDto.isPasswordValid();
            if (!validationResult.getFirst()) {
                return new ResponseEntity<>(validationResult.getSecond(), HttpStatus.BAD_REQUEST);
            }
            userService.registerUser(registrationDto);
            return new ResponseEntity<>("User successfully registered.", HttpStatus.CREATED);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginDto loginDto, HttpServletRequest request) {
        try {
            if (!recaptcha.verifyRecaptcha(loginDto.getRecaptchaToken())) {
                return new ResponseEntity<>(Map.of("message", "Recaptcha verification failed."), HttpStatus.BAD_REQUEST);
            }
            Optional<User> userOptional = userService.loginUser(loginDto);

            if (userOptional.isPresent()) {
                User user = userOptional.get();


                if (!user.isVerified()) {
                    return new ResponseEntity<>(Map.of("message", "User not verified. Please check your email for verification link."), HttpStatus.UNAUTHORIZED);
                }

                if (user.isTwoFactorEnabled()) {
                    return new ResponseEntity<>(Map.of("twoFaEnabled", "2FA_REQUIRED"), HttpStatus.OK);
                }

                GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole().name());
                Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Collections.singletonList(authority));

                String token = jwtProvider.generateToken(authentication);

                String jti = jwtProvider.getJtiFromToken(token);
                String ipAddress = request.getRemoteAddr();
                String device = request.getHeader("User-Agent");

                userSessionService.createSession(user, jti, device, ipAddress);

                return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
            }

            return new ResponseEntity<>(Map.of("message", "Invalid credentials"), HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login-with-2fa")
    public ResponseEntity<Map<String, String>> loginWith2fa(@RequestBody LoginDto loginDto, HttpServletRequest request) {
        try {
            Optional<User> userOptional = userService.loginUser(loginDto);

            if (userOptional.isPresent()) {
                User user = userOptional.get();


                if (!user.isVerified()) {
                    return new ResponseEntity<>(Map.of("message", "User not verified. Please check your email for verification link."), HttpStatus.UNAUTHORIZED);
                }

                if (!twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), loginDto.getCode2fa(), user.getEmail())) {
                    return new ResponseEntity<>(Map.of("message", "Invalid 2FA code."), HttpStatus.BAD_REQUEST);
                }

                if (loginDto.isDisable2fa()) {
                    userService.disableTwoFactorAuth(user.getEmail());
                }

                GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole().name());
                Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Collections.singletonList(authority));

                String token = jwtProvider.generateToken(authentication);

                String jti = jwtProvider.getJtiFromToken(token);
                String ipAddress = request.getRemoteAddr();
                String device = request.getHeader("User-Agent");

                userSessionService.createSession(user, jti, device, ipAddress);

                return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
            }

            return new ResponseEntity<>(Map.of("message", "Invalid credentials"), HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        String token = getJwtFromRequest(request);

        if (!jwtProvider.validateToken(token)) {
            return new ResponseEntity<>("Invalid token.", HttpStatus.BAD_REQUEST);
        }

        if (StringUtils.hasText(token)) {
            try {
                String jti = jwtProvider.getJtiFromToken(token);
                userSessionService.deleteSessionByJti(jti);
                SecurityContextHolder.clearContext();
                return new ResponseEntity<>("Logged out successfully.", HttpStatus.OK);
            } catch (Exception e) {
                return new ResponseEntity<>("Invalid token or session.", HttpStatus.BAD_REQUEST);
            }
        }

        return new ResponseEntity<>("No token provided.", HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam String token) {
        try {
            boolean isVerified = userService.verifyUser(token);
            if (isVerified) {
                return new ResponseEntity<>("User successfully verified. You can now login.", HttpStatus.OK);
            } else {
                return new ResponseEntity<>("Verification failed. User not found or already verified.", HttpStatus.BAD_REQUEST);
            }
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/enable-2fa")
    @PreAuthorize("hasAuthority('REGULAR_USER') or hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> enableTwoFactorAuthentication() {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String qrCodeImage = userService.enableTwoFactorAuth(currentUser.getEmail());
            List<String> backupCodes = twoFactorAuthService.generateBackupCodes(currentUser.getEmail());
            if (backupCodes.size() != 5) {
                throw new ValidationException("Error generating backup codes for 2FA.");
            }
            if (qrCodeImage == null || qrCodeImage.isEmpty()) {
                throw new ValidationException("Error generating QR code for 2FA.");
            }

            Map<String, Object> response = new HashMap<>();
            response.put("qrCodeImage", qrCodeImage);
            response.put("backupCodes", backupCodes);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/verify-2fa")
    @PreAuthorize("hasAuthority('REGULAR_USER') or hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> verifyTwoFactorAuthentication(@RequestBody Code2FADto code2FADto) {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            userService.verifyTwoFactorAuth(currentUser.getEmail(), code2FADto.getCode2fa());

            return new ResponseEntity<>(Map.of("message", "2FA verified successfully"), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam String email) {
        try {
            passwordResetService.sendPasswordResetEmail(email);
            return new ResponseEntity<>("Password reset email sent successfully", HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetDto passwordResetDto) {
        try {
            boolean success = passwordResetService.resetPassword(
                    passwordResetDto.getEmail(),
                    passwordResetDto.getNewPassword()
            );
            if (success) {
                return new ResponseEntity<>("Password reset successfully", HttpStatus.OK);
            }
            return new ResponseEntity<>("Password reset failed", HttpStatus.BAD_REQUEST);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}