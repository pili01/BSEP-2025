package com.bsep.pki.controllers;

import com.bsep.pki.dtos.CertificateRequestDto;
import com.bsep.pki.models.CertificateType;
import com.bsep.pki.models.UserRole;
import com.bsep.pki.services.CertificateService;
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

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    private final CertificateService certificateService;
    private final JwtProvider jwtProvider;

    public CertificateController(CertificateService certificateService, JwtProvider jwtProvider) {
        this.certificateService = certificateService;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/issue")
    public ResponseEntity<String> issueCertificate(@Valid @RequestBody CertificateRequestDto requestDto, HttpServletRequest request) {
        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);

            if (requestDto.getType() == CertificateType.ROOT) {
                if (userRole != UserRole.ADMIN) {
                    return new ResponseEntity<>("Only an ADMIN can issue ROOT certificates.", HttpStatus.FORBIDDEN);
                }
            } else if (requestDto.getType() == CertificateType.INTERMEDIATE || requestDto.getType() == CertificateType.END_ENTITY) {
                if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                    return new ResponseEntity<>("Only an ADMIN or CA_USER can issue INTERMEDIATE or END_ENTITY certificates.", HttpStatus.FORBIDDEN);
                }
            } else {
                return new ResponseEntity<>("Invalid certificate type.", HttpStatus.BAD_REQUEST);
            }

            certificateService.issueCertificate(
                    requestDto.getCommonName(),
                    requestDto.getOrganization(),
                    requestDto.getValidityInDays(),
                    requestDto.getType(),
                    requestDto.getIssuerSerialNumber()
            );

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