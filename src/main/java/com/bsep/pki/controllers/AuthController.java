package com.bsep.pki.controllers;

import com.bsep.pki.dtos.LoginDto;
import com.bsep.pki.dtos.RegistrationDto;
import com.bsep.pki.dtos.PasswordResetDto;
import com.bsep.pki.models.User;
import com.bsep.pki.services.Recaptcha;
import com.bsep.pki.services.UserService;
import com.bsep.pki.services.UserSessionService;
import com.bsep.pki.services.PasswordResetService;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

import java.util.Collections;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtProvider jwtProvider;
    private final UserSessionService userSessionService;
    private final PasswordResetService passwordResetService;
    private final Recaptcha recaptcha;

    public AuthController(UserService userService, JwtProvider jwtProvider, UserSessionService userSessionService, PasswordResetService passwordResetService, Recaptcha recaptcha) {
        this.userService = userService;
        this.jwtProvider = jwtProvider;
        this.userSessionService = userSessionService;
        this.passwordResetService = passwordResetService;
        this.recaptcha = recaptcha;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegistrationDto registrationDto) {
        try {
            userService.registerUser(registrationDto);
            return new ResponseEntity<>("User successfully registered.", HttpStatus.CREATED);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDto loginDto, HttpServletRequest request) {
        if(!recaptcha.verifyRecaptcha(loginDto.getRecaptchaToken())) {
            return new ResponseEntity<>("Recaptcha verification failed.", HttpStatus.BAD_REQUEST);
        }
        Optional<User> userOptional = userService.loginUser(loginDto);

        if (userOptional.isPresent()) {
            User user = userOptional.get();


            if (!user.isVerified()) {
                return new ResponseEntity<>("User not verified. Please check your email for verification link.", HttpStatus.UNAUTHORIZED);
            }

            GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole().name());
            Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, Collections.singletonList(authority));

            String token = jwtProvider.generateToken(authentication);

            String jti = jwtProvider.getJtiFromToken(token);
            String ipAddress = request.getRemoteAddr();
            String device = request.getHeader("User-Agent");

            userSessionService.createSession(user, jti, device, ipAddress);

            return new ResponseEntity<>(token, HttpStatus.OK);
        }

        return new ResponseEntity<>("Invalid credentials", HttpStatus.UNAUTHORIZED);
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
    public ResponseEntity<String> verifyUser(@RequestParam String email) {
        try {
            boolean isVerified = userService.verifyUser(email);
            if (isVerified) {
                return new ResponseEntity<>("User successfully verified. You can now login.", HttpStatus.OK);
            } else {
                return new ResponseEntity<>("Verification failed. User not found or already verified.", HttpStatus.BAD_REQUEST);
            }
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
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