package com.bsep.pki.controllers;

import com.bsep.pki.dtos.CertificateRequestDto;
import com.bsep.pki.dtos.CsrRequestDto;
import com.bsep.pki.dtos.CsrResponseDto;
import com.bsep.pki.models.*;
import com.bsep.pki.services.CertificateService;
import com.bsep.pki.services.UserService;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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




    @PostMapping("/csr/upload-file")
    public ResponseEntity<String> uploadCsrWithFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("commonName") String commonName,
            @RequestParam("targetUserEmail") String targetUserEmail,
            @RequestParam("validityInDays") long validityInDays,
            @RequestParam("organization") String organization,
            @RequestParam("caIssuerSerialNumber") String caIssuerSerialNumber,
            @RequestParam(value = "keyUsage", required = false) String keyUsage,
            @RequestParam(value = "extendedKeyUsage", required = false) String extendedKeyUsage,
            @RequestParam(value = "notes", required = false) String notes,
            HttpServletRequest request) {
        
        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }


            UserRole userRole = jwtProvider.getRoleFromToken(token);
            if (userRole != UserRole.REGULAR_USER) {
                return new ResponseEntity<>("Only REGULAR_USER can upload CSR.", HttpStatus.FORBIDDEN);
            }


            String userEmail = jwtProvider.getEmailFromToken(token);
            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User uploadingUser = optionalUser.get();


            Optional<User> targetUserOptional = userService.findByEmail(targetUserEmail);
            if (targetUserOptional.isEmpty()) {
                return new ResponseEntity<>("Target user not found.", HttpStatus.BAD_REQUEST);
            }

            User targetUser = targetUserOptional.get();


            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            if (!organization.equals(userOrganization)) {
                return new ResponseEntity<>("You can only issue certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
            }


            if (file.isEmpty()) {
                return new ResponseEntity<>("Please select a file to upload.", HttpStatus.BAD_REQUEST);
            }

            if (!file.getOriginalFilename().toLowerCase().endsWith(".pem")) {
                return new ResponseEntity<>("Only .pem files are allowed.", HttpStatus.BAD_REQUEST);
            }


            String pemContent = new String(file.getBytes());
            

            CsrRequestDto csrDto = new CsrRequestDto();
            csrDto.setCsrPemContent(pemContent);
            csrDto.setCommonName(commonName);
            csrDto.setTargetUserEmail(targetUserEmail);
            csrDto.setValidityInDays(validityInDays);
            csrDto.setOrganization(organization);
            csrDto.setCaIssuerSerialNumber(caIssuerSerialNumber);
            csrDto.setKeyUsage(keyUsage != null ? keyUsage : "");
            csrDto.setExtendedKeyUsage(extendedKeyUsage != null ? extendedKeyUsage : "");



            CsrRequest savedRequest = certificateService.uploadCsr(csrDto, uploadingUser, targetUser);

            return new ResponseEntity<>("CSR successfully uploaded from file and pending approval. ID: " + savedRequest.getId(), HttpStatus.CREATED);

        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (SecurityException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while processing CSR file: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/csr/sign")
    public ResponseEntity<String> signCsr(@Valid @RequestBody CsrRequestDto csrDto, HttpServletRequest request) {
        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                return new ResponseEntity<>("Only ADMIN or CA_USER can sign CSR requests.", HttpStatus.FORBIDDEN);
            }

            String userEmail = jwtProvider.getEmailFromToken(token);
            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User signingUser = optionalUser.get();

            Optional<User> targetUserOptional = userService.findByEmail(csrDto.getTargetUserEmail());
            if (targetUserOptional.isEmpty()) {
                return new ResponseEntity<>("Target user not found.", HttpStatus.BAD_REQUEST);
            }

            User targetUser = targetUserOptional.get();

            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            if (!csrDto.getOrganization().equals(userOrganization)) {
                return new ResponseEntity<>("You can only sign certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
            }

            certificateService.signCsrAndIssueCertificate(csrDto, signingUser, targetUser);

            return new ResponseEntity<>("CSR successfully signed and certificate issued.", HttpStatus.CREATED);

        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (SecurityException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while signing CSR: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/ca/list")
    public ResponseEntity<List<Map<String, String>>> getAvailableCaCertificates(HttpServletRequest request) {
        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }


            UserRole userRole = jwtProvider.getRoleFromToken(token);
            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }


            List<Map<String, String>> caList = certificateService.getAvailableCaCertificates();
            return new ResponseEntity<>(caList, HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    

    
    @GetMapping("/csr/pending")
    public ResponseEntity<List<CsrResponseDto>> getPendingCsrRequests(HttpServletRequest request) {
        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }


            UserRole userRole = jwtProvider.getRoleFromToken(token);
            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }

            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            List<CsrResponseDto> pendingRequests = certificateService.getPendingCsrRequests(userOrganization);
            
            return new ResponseEntity<>(pendingRequests, HttpStatus.OK);

        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
    @GetMapping("/csr/user")
    public ResponseEntity<List<CsrResponseDto>> getUserCsrRequests(HttpServletRequest request) {
        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }


            String userEmail = jwtProvider.getEmailFromToken(token);
            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            User user = optionalUser.get();
            List<CsrResponseDto> userRequests = certificateService.getCsrRequestsByUser(user);
            
            return new ResponseEntity<>(userRequests, HttpStatus.OK);

        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
    @GetMapping("/csr/{id}")
    public ResponseEntity<CsrResponseDto> getCsrRequestById(@PathVariable Long id, HttpServletRequest request) {
        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }


            CsrResponseDto csrRequest = certificateService.getCsrRequestById(id);
            return new ResponseEntity<>(csrRequest, HttpStatus.OK);

        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
    @PostMapping("/csr/{id}/reject")
    public ResponseEntity<String> rejectCsrRequest(@PathVariable Long id, @RequestBody String reason, HttpServletRequest request) {
        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }


            UserRole userRole = jwtProvider.getRoleFromToken(token);
            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                return new ResponseEntity<>("Only ADMIN or CA_USER can reject CSR requests.", HttpStatus.FORBIDDEN);
            }


            String userEmail = jwtProvider.getEmailFromToken(token);
            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User rejectingUser = optionalUser.get();
            

            certificateService.rejectCsrRequest(id, reason, rejectingUser);
            
            return new ResponseEntity<>("CSR request rejected successfully.", HttpStatus.OK);

        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (SecurityException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while rejecting CSR request: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
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