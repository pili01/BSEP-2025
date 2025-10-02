package com.bsep.pki.controllers;

import com.bsep.pki.dtos.Code2FADto;
import com.bsep.pki.dtos.LoginDto;
import com.bsep.pki.dtos.PasswordResetDto;
import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.models.User;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.services.*;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.http.HttpServletRequest; // Import
import jakarta.validation.Valid;
import jakarta.validation.ValidationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

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

    private final Logger log = LogManager.getLogger(AuthController.class);

    @PostMapping("/register")
    // DODATA PROMENA: Dodavanje HttpServletRequest za dohvat IP adrese
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegistrationDto registrationDto, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("Registration attempt for email: {} from IP: {}", registrationDto.getEmail(), ipAddress);

        var validationResult = registrationDto.isPasswordValid();
        if (!validationResult.getFirst()) {
            log.warn("Password validation failed for email: {} from IP: {}", registrationDto.getEmail(), ipAddress);
            return new ResponseEntity<>(validationResult.getSecond(), HttpStatus.BAD_REQUEST);
        }
        log.debug("Password validation passed for email: {}", registrationDto.getEmail());
        userService.registerUser(registrationDto);
        log.info("User successfully registered: {} from IP: {}", registrationDto.getEmail(), ipAddress);
        return new ResponseEntity<>("User successfully registered.", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginDto loginDto, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("Login attempt for user: {} from IP: {}", loginDto.getEmail(), ipAddress);

        try {
            if (!recaptcha.verifyRecaptcha(loginDto.getRecaptchaToken())) {
                log.warn("Recaptcha verification failed for user: {} from IP: {}", loginDto.getEmail(), ipAddress);
                return new ResponseEntity<>(Map.of("message", "Recaptcha verification failed."), HttpStatus.BAD_REQUEST);
            }
            
            Optional<User> userOptional = userService.loginUser(loginDto);

            if (userOptional.isPresent()) {
                User user = userOptional.get();
                if (!user.isVerified()) {
                    log.warn("Login attempt by unverified user: {} from IP: {}", loginDto.getEmail(), ipAddress);
                    return new ResponseEntity<>(Map.of("message", "User not verified. Please check your email for verification link."), HttpStatus.UNAUTHORIZED);
                }

                if (!user.isPasswordChanged() && user.getRole() == UserRole.CA_USER) {
                    GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole().name());
                    Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Collections.singletonList(authority));
                    String token = jwtProvider.generateToken(authentication);
                    log.info("Initial password required for CA_USER, issuing restricted token for user: {} from IP: {}", loginDto.getEmail(), ipAddress);
                    return new ResponseEntity<>(Map.of(
                            "requirePasswordChange", "INITIAL_PASSWORD",
                            "token", token
                    ), HttpStatus.OK);
                }

                if (user.isTwoFactorEnabled()) {
                    log.info("2FA required for user: {} from IP: {}", loginDto.getEmail(), ipAddress);
                    return new ResponseEntity<>(Map.of("twoFaEnabled", "2FA_REQUIRED"), HttpStatus.OK);
                }

                GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole().name());
                Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Collections.singletonList(authority));

                String token = jwtProvider.generateToken(authentication);

                String jti = jwtProvider.getJtiFromToken(token);
                String device = request.getHeader("User-Agent");
                userSessionService.createSession(user, jti, device, ipAddress);

                log.info("Login successful for user: {} from IP: {}", user.getEmail(), ipAddress);
                return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
            }

            log.warn("Login failed - Invalid credentials for email: {} from IP: {}", loginDto.getEmail(), ipAddress);
            return new ResponseEntity<>(Map.of("message", "Invalid credentials"), HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("Login error for user: {} from IP: {} - {}", loginDto.getEmail(), ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/change-initial-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> changeInitialPassword(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String email = user.getEmail();
        String newPassword = body.get("newPassword");

        log.info("Initial password change attempt for user: {} from IP: {}", email, ipAddress);

        if (newPassword == null || newPassword.isEmpty()) {
            log.warn("Initial password change failed for user: {} from IP: {}: New password missing.", email, ipAddress);
            return new ResponseEntity<>(Map.of("message", "New password is required."), HttpStatus.BAD_REQUEST);
        }

        if (!user.isPasswordChanged()) {
            try {
                userService.changeInitialPassword(user, newPassword);

                User updatedUser = userService.findByEmail(email)
                        .orElseThrow(() -> new RuntimeException("User not found after password change."));

                GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + updatedUser.getRole().name());
                Authentication authentication = new UsernamePasswordAuthenticationToken(updatedUser, null, Collections.singletonList(authority));
                String newToken = jwtProvider.generateToken(authentication);

                String oldToken = request.getHeader("Authorization").substring(7);
                String oldJti = jwtProvider.getJtiFromToken(oldToken);
                userSessionService.deleteSessionByJti(oldJti);

                String newJti = jwtProvider.getJtiFromToken(newToken);
                String device = request.getHeader("User-Agent");
                userSessionService.createSession(updatedUser, newJti, device, ipAddress);

                log.info("Initial password changed and NEW TOKEN issued for user: {} from IP: {}", email, ipAddress);

                return ResponseEntity.ok(Map.of("token", newToken));

            } catch (RuntimeException e) {
                log.error("Initial password change failed for user: {} from IP: {} - {}", email, ipAddress, e.getMessage(), e);
                return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
            }
        } else {
            log.warn("Unauthorized password change attempt for user: {} from IP: {}. Initial password already changed.", email, ipAddress);
            return new ResponseEntity<>(Map.of("message", "Initial password has already been changed."), HttpStatus.FORBIDDEN);
        }
    }

    @PostMapping("/login-with-2fa")
    public ResponseEntity<Map<String, String>> loginWith2fa(@RequestBody LoginDto loginDto, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("2FA login attempt for user: {} from IP: {}", loginDto.getEmail(), ipAddress);

        try {
            Optional<User> userOptional = userService.loginUser(loginDto);

            if (userOptional.isPresent()) {
                User user = userOptional.get();
                if (!user.isVerified()) {
                    log.warn("2FA login attempt by unverified user: {} from IP: {}", loginDto.getEmail(), ipAddress);
                    return new ResponseEntity<>(Map.of("message", "User not verified. Please check your email for verification link."), HttpStatus.UNAUTHORIZED);
                }
                if (!twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), loginDto.getCode2fa(), user.getEmail())) {
                    log.warn("Invalid 2FA code provided by user: {} from IP: {}", user.getEmail(), ipAddress);
                    return new ResponseEntity<>(Map.of("message", "Invalid 2FA code."), HttpStatus.BAD_REQUEST);
                }

                if (loginDto.isDisable2fa()) {
                    log.info("Disabling 2FA for user: {} from IP: {}", user.getEmail(), ipAddress);
                    userService.disableTwoFactorAuth(user.getEmail());
                }
                GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole().name());
                Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Collections.singletonList(authority));

                String token = jwtProvider.generateToken(authentication);

                String jti = jwtProvider.getJtiFromToken(token);
                String device = request.getHeader("User-Agent");
                userSessionService.createSession(user, jti, device, ipAddress);

                log.info("2FA login successful for user: {} from IP: {}", user.getEmail(), ipAddress);
                return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
            }

            log.warn("2FA login failed - Invalid credentials for email: {} from IP: {}", loginDto.getEmail(), ipAddress);
            return new ResponseEntity<>(Map.of("message", "Invalid credentials"), HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("2FA login error for user: {} from IP: {} - {}", loginDto.getEmail(), ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("Logout attempt from IP: {}", ipAddress);
        String token = getJwtFromRequest(request);

        if (!jwtProvider.validateToken(token)) {
            log.warn("Logout attempt with invalid token from IP: {}", ipAddress);
            return new ResponseEntity<>("Invalid token.", HttpStatus.BAD_REQUEST);
        }

        if (StringUtils.hasText(token)) {
            try {
                String jti = jwtProvider.getJtiFromToken(token);
                userSessionService.deleteSessionByJti(jti);
                SecurityContextHolder.clearContext();
                log.info("Logout successful - JTI: {} from IP: {}", jti, ipAddress);
                return new ResponseEntity<>("Logged out successfully.", HttpStatus.OK);
            } catch (Exception e) {
                log.error("Logout error from IP: {} - {}", ipAddress, e.getMessage(), e);
                return new ResponseEntity<>("Invalid token or session.", HttpStatus.BAD_REQUEST);
            }
        }

        log.warn("Logout attempt without token from IP: {}", ipAddress);
        return new ResponseEntity<>("No token provided.", HttpStatus.BAD_REQUEST);
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam String token, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("User verification attempt from IP: {}", ipAddress);

        try {
            boolean isVerified = userService.verifyUser(token);
            if (isVerified) {
                log.info("User successfully verified from IP: {}", ipAddress);
                return new ResponseEntity<>("User successfully verified. You can now login.", HttpStatus.OK);
            } else {
                log.warn("Verification failed from IP: {}", ipAddress);
                return new ResponseEntity<>("Verification failed. User not found or already verified.", HttpStatus.BAD_REQUEST);
            }
        } catch (RuntimeException e) {
            log.error("Verification error from IP: {} - {}", ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/enable-2fa")
    @PreAuthorize("hasAuthority('REGULAR_USER') or hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> enableTwoFactorAuthentication(HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();
        log.info("Enabling 2FA for user: {} from IP: {}", currentUser.getEmail(), ipAddress);

        try {
            String qrCodeImage = userService.enableTwoFactorAuth(currentUser.getEmail());
            List<String> backupCodes = twoFactorAuthService.generateBackupCodes(currentUser.getEmail());
            if (backupCodes.size() != 5) {
                log.error("Error generating backup codes for 2FA - Expected 5, got: {} for user: {} from IP: {}", backupCodes.size(), currentUser.getEmail(), ipAddress);
                throw new ValidationException("Error generating backup codes for 2FA.");
            }
            if (qrCodeImage == null || qrCodeImage.isEmpty()) {
                log.error("Error generating QR code for 2FA - User: {} from IP: {}", currentUser.getEmail(), ipAddress);
                throw new ValidationException("Error generating QR code for 2FA.");
            }

            Map<String, Object> response = new HashMap<>();
            response.put("qrCodeImage", qrCodeImage);
            response.put("backupCodes", backupCodes);

            log.info("2FA enabled successfully for user: {} from IP: {}", currentUser.getEmail(), ipAddress);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error enabling 2FA for user: {} from IP: {} - {}", currentUser.getEmail(), ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/verify-2fa")
    @PreAuthorize("hasAuthority('REGULAR_USER') or hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> verifyTwoFactorAuthentication(@RequestBody Code2FADto code2FADto, HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();
        log.info("Verifying 2FA code for user: {} from IP: {}", currentUser.getEmail(), ipAddress);

        try {
            userService.verifyTwoFactorAuth(currentUser.getEmail(), code2FADto.getCode2fa());
            log.info("2FA verified successfully for user: {} from IP: {}", currentUser.getEmail(), ipAddress);
            return new ResponseEntity<>(Map.of("message", "2FA verified successfully"), HttpStatus.OK);
        } catch (Exception e) {
            log.error("2FA verification failed for user: {} from IP: {} - {}", currentUser.getEmail(), ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam String email, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("Password reset request for email: {} from IP: {}", email, ipAddress);
        log.debug("Sending password reset email to: {}", email);

        try {
            passwordResetService.sendPasswordResetEmail(email);
            log.info("Password reset email sent successfully to: {} from IP: {}", email, ipAddress);
            return new ResponseEntity<>("Password reset email sent successfully", HttpStatus.OK);
        } catch (RuntimeException e) {
            log.error("Password reset request failed for email: {} from IP: {} - {}", email, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetDto passwordResetDto, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("Password reset attempt for email: {} from IP: {}", passwordResetDto.getEmail(), ipAddress);
        log.debug("Resetting password for email: {}, New password: {}", passwordResetDto.getEmail(), passwordResetDto.getNewPassword());

        try {
            boolean success = passwordResetService.resetPassword(
                    passwordResetDto.getEmail(),
                    passwordResetDto.getNewPassword()
            );
            if (success) {
                log.info("Password reset successfully for email: {} from IP: {}", passwordResetDto.getEmail(), ipAddress);
                return new ResponseEntity<>("Password reset successfully", HttpStatus.OK);
            }
            log.warn("Password reset failed for email: {} from IP: {}", passwordResetDto.getEmail(), ipAddress);
            return new ResponseEntity<>("Password reset failed", HttpStatus.BAD_REQUEST);
        } catch (RuntimeException e) {
            log.error("Password reset error for email: {} from IP: {} - {}", passwordResetDto.getEmail(), ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/me")
    @PreAuthorize("hasAuthority('REGULAR_USER') or hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> getMyInfo(HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();
        log.info("Fetching user info for: {} from IP: {}", currentUser.getEmail(), ipAddress);
        log.debug("Getting public data for user ID: {}", currentUser.getId());

        try {
            var response = userService.getUserPublicData(currentUser.getId());
            log.info("User info retrieved for: {} from IP: {}", currentUser.getEmail(), ipAddress);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error fetching user info for: {} from IP: {} - {}", currentUser.getEmail(), ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/allRegularUsers")
    @PreAuthorize("hasAuthority('REGULAR_USER') or hasAuthority('ADMIN') or hasAuthority('CA_USER')")
    public ResponseEntity<?> getAllRegularUsers(HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();
        log.info("Fetching all regular users - Requested by: {} from IP: {}", currentUser.getEmail(), ipAddress);

        try {
            var response = userService.getAllRegularUsers();
            log.info("All regular users fetched successfully by: {} from IP: {}", currentUser.getEmail(), ipAddress);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error fetching all regular users by {} from IP: {} - {}", currentUser.getEmail(), ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/savePublicKey")
    @PreAuthorize("hasAuthority('REGULAR_USER')")
    public ResponseEntity<String> savePublicKey(@RequestBody Map<String, String> body, HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();
        log.info("Saving public key for user: {} from IP: {}", currentUser.getEmail(), ipAddress);

        try {
            String publicKey = body.get("publicKey");

            userService.savePublicKey(currentUser.getEmail(), publicKey);
            log.info("Public key saved successfully for user: {} from IP: {}", currentUser.getEmail(), ipAddress);
            return new ResponseEntity<>("Public key saved successfully", HttpStatus.OK);
        } catch (RuntimeException e) {
            log.error("Error saving public key for user: {} from IP: {} - {}", currentUser.getEmail(), ipAddress, e.getMessage(), e);
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