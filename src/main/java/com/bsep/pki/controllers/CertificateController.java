package com.bsep.pki.controllers;

import com.bsep.pki.dtos.CertificateRequestDto;
import com.bsep.pki.models.CertificateType;
import com.bsep.pki.models.User;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.services.CertificateService;
import com.bsep.pki.services.UserService;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    private final CertificateService certificateService;
    private final JwtProvider jwtProvider;
    private final UserService userService;

    public CertificateController(CertificateService certificateService, JwtProvider jwtProvider, UserService userService) {
        this.certificateService = certificateService;
        this.jwtProvider = jwtProvider;
        this.userService = userService;
    }

    @PostMapping("/issue")
    public ResponseEntity<String> issueCertificate(@Valid @RequestBody CertificateRequestDto requestDto, HttpServletRequest request) {
        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            String userEmail = jwtProvider.getEmailFromToken(token);

            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User issuingUser = optionalUser.get();

            User targetUser = null;
            if (requestDto.getType() != CertificateType.ROOT) {
                if (requestDto.getTargetUserEmail() == null || requestDto.getTargetUserEmail().isEmpty()) {
                    return new ResponseEntity<>("Target user email is required for non-ROOT certificates.", HttpStatus.BAD_REQUEST);
                }

                Optional<User> userFromDb = userService.findByEmail(requestDto.getTargetUserEmail().get());
                if (userFromDb.isEmpty()) {
                    return new ResponseEntity<>("Target user not found.", HttpStatus.BAD_REQUEST);
                }
                targetUser = userFromDb.get();
            } else {
                targetUser = issuingUser;
            }

            if (requestDto.getType() == CertificateType.ROOT) {
                if (userRole != UserRole.ADMIN) {
                    return new ResponseEntity<>("Only an ADMIN can issue ROOT certificates.", HttpStatus.FORBIDDEN);
                }
            } else if (requestDto.getType() == CertificateType.INTERMEDIATE) {
                if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                    return new ResponseEntity<>("Only an ADMIN or CA_USER can issue INTERMEDIATE certificates.", HttpStatus.FORBIDDEN);
                }
                if (targetUser.getRole() != UserRole.CA_USER) {
                    return new ResponseEntity<>("Intermediate certificates can only be issued for CA users.", HttpStatus.FORBIDDEN);
                }
                if (!requestDto.getOrganization().equals(userOrganization)) {
                    return new ResponseEntity<>("You can only issue certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
                }
            } else if (requestDto.getType() == CertificateType.END_ENTITY) {
                if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                    return new ResponseEntity<>("Only an ADMIN or CA_USER can issue END_ENTITY certificates.", HttpStatus.FORBIDDEN);
                }
                if (targetUser.getRole() != UserRole.REGULAR_USER) {
                    return new ResponseEntity<>("End entity certificates can only be issued for REGULAR users.", HttpStatus.FORBIDDEN);
                }
                if (!requestDto.getOrganization().equals(userOrganization)) {
                    return new ResponseEntity<>("You can only issue certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
                }
            } else {
                return new ResponseEntity<>("Invalid certificate type.", HttpStatus.BAD_REQUEST);
            }

            certificateService.issueCertificate(requestDto, issuingUser, targetUser);

            return new ResponseEntity<>("Certificate successfully issued.", HttpStatus.CREATED);

        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while issuing the certificate.", HttpStatus.INTERNAL_SERVER_ERROR);
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