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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.bsep.pki.models.Certificate;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;

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
            String userOrganization = jwtProvider.getOrganizationFromToken(token);

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

            if (!requestDto.getOrganization().equals(userOrganization)) {
                return new ResponseEntity<>("You can only issue certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
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

    @GetMapping("/admin/all")
    public ResponseEntity<?> getAllCertificates(HttpServletRequest request) {
        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            if (userRole != UserRole.ADMIN) {
                return new ResponseEntity<>("Only ADMIN can view all certificates.", HttpStatus.FORBIDDEN);
            }

            return ResponseEntity.ok(certificateService.getAllCertificates());
        } catch (Exception e) {
            return new ResponseEntity<>("Error retrieving certificates: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/ca/chain")
    public ResponseEntity<?> getCertificateChain(HttpServletRequest request) {
        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                return new ResponseEntity<>("Only ADMIN or CA_USER can view certificate chain.", HttpStatus.FORBIDDEN);
            }

            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            

            List<Certificate> allCerts = certificateService.getCertificatesByOrganization(userOrganization);
            Optional<Certificate> rootCert = allCerts.stream()
                .filter(cert -> cert.getIssuerSerialNumber() == null)
                .findFirst();
            
            if (rootCert.isEmpty()) {
                return ResponseEntity.ok(new ArrayList<>());
            }
            

            return ResponseEntity.ok(certificateService.getCertificatesFromChain(rootCert.get().getSerialNumber()));
        } catch (Exception e) {
            return new ResponseEntity<>("Error retrieving certificate chain: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/user/my")
    public ResponseEntity<?> getMyEndEntityCertificates(HttpServletRequest request) {
        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            String userEmail = jwtProvider.getEmailFromToken(token);
            return ResponseEntity.ok(certificateService.getEndEntityCertificatesByUserEmail(userEmail));
        } catch (Exception e) {
            return new ResponseEntity<>("Error retrieving user certificates: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
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