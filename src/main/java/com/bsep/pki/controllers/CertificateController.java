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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
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
    private final Logger log = LogManager.getLogger(CertificateController.class);

    public CertificateController(CertificateService certificateService, JwtProvider jwtProvider, UserService userService) {
        this.certificateService = certificateService;
        this.jwtProvider = jwtProvider;
        this.userService = userService;
    }

    @PostMapping("/issue")
    public ResponseEntity<String> issueCertificate(@RequestBody CertificateRequestDto requestDto, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Certificate issue request - Type: {}, Organization: {} from IP: {}", requestDto.getType(), requestDto.getOrganization(), ipAddress);
        log.debug("Certificate request details: {}", requestDto);

        try {
            String token = getJwtFromRequest(request);
            log.debug("Extracted JWT token from request");

            if (!StringUtils.hasText(token)) {
                log.warn("Certificate issue attempt without authorization token from IP: {}", ipAddress);
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            userEmail = jwtProvider.getEmailFromToken(token); // Ažuriranje userEmail
            log.debug("Token data - Email: {}, Role: {}, Organization: {}", userEmail, userRole, userOrganization);

            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                log.error("Authenticated user not found for email: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User issuingUser = optionalUser.get();
            log.debug("Issuing user found: {}", issuingUser.getEmail());

            User targetUser = null;
            if (requestDto.getType() != CertificateType.ROOT) {
                if (requestDto.getTargetUserEmail() == null || requestDto.getTargetUserEmail().isEmpty()) {
                    log.warn("Target user email missing for non-ROOT certificate request by: {} from IP: {}", userEmail, ipAddress);
                    return new ResponseEntity<>("Target user email is required for non-ROOT certificates.", HttpStatus.BAD_REQUEST);
                }

                log.debug("Looking up target user: {}", requestDto.getTargetUserEmail().get());
                Optional<User> userFromDb = userService.findByEmail(requestDto.getTargetUserEmail().get());
                if (userFromDb.isEmpty()) {
                    log.warn("Target user not found: {} (Requested by: {} from IP: {})", requestDto.getTargetUserEmail().get(), userEmail, ipAddress);
                    return new ResponseEntity<>("Target user not found.", HttpStatus.BAD_REQUEST);
                }
                targetUser = userFromDb.get();
                log.debug("Target user found: {}, Role: {}", targetUser.getEmail(), targetUser.getRole());
            } else {
                targetUser = issuingUser;
                log.debug("ROOT certificate - Target user is issuing user: {}", targetUser.getEmail());
            }

            if (requestDto.getType() == CertificateType.ROOT) {
                log.debug("Validating ROOT certificate issuance - User role: {}", userRole);
                if (userRole != UserRole.ADMIN) {
                    log.warn("Non-ADMIN user attempted to issue ROOT certificate: {} from IP: {}", userEmail, ipAddress);
                    return new ResponseEntity<>("Only an ADMIN can issue ROOT certificates.", HttpStatus.FORBIDDEN);
                }
            } else if (requestDto.getType() == CertificateType.INTERMEDIATE) {
                log.debug("Validating INTERMEDIATE certificate issuance - User role: {}, Target role: {}", userRole, targetUser.getRole());
                if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                    log.warn("Unauthorized user attempted to issue INTERMEDIATE certificate: {} from IP: {}", userEmail, ipAddress);
                    return new ResponseEntity<>("Only an ADMIN or CA_USER can issue INTERMEDIATE certificates.", HttpStatus.FORBIDDEN);
                }
                if (targetUser.getRole() != UserRole.CA_USER) {
                    log.warn("Attempt to issue INTERMEDIATE certificate for non-CA user: {} (Requested by: {})", targetUser.getEmail(), userEmail);
                    return new ResponseEntity<>("Intermediate certificates can only be issued for CA users.", HttpStatus.FORBIDDEN);
                }
                if (targetUser.getEmail().equals(userEmail)) {
                    log.warn("User attempted to issue INTERMEDIATE certificate for themselves: {} from IP: {}", userEmail, ipAddress);
                    return new ResponseEntity<>("You can't issue intermediate certificate for yourself!", HttpStatus.FORBIDDEN);
                }
                if (!requestDto.getOrganization().equals(userOrganization) && userRole != UserRole.ADMIN) {
                    log.warn("Organization mismatch - Request org: {}, User org: {} (Requested by: {} from IP: {})", requestDto.getOrganization(), userOrganization, userEmail, ipAddress);
                    return new ResponseEntity<>("You can only issue certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
                }
            } else if (requestDto.getType() == CertificateType.END_ENTITY) {
                log.debug("Validating END_ENTITY certificate issuance - User role: {}, Target role: {}", userRole, targetUser.getRole());
                if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                    log.warn("Unauthorized user attempted to issue END_ENTITY certificate: {} from IP: {}", userEmail, ipAddress);
                    return new ResponseEntity<>("Only an ADMIN or CA_USER can issue END_ENTITY certificates.", HttpStatus.FORBIDDEN);
                }
                if (targetUser.getRole() != UserRole.REGULAR_USER) {
                    log.warn("Attempt to issue END_ENTITY certificate for non-REGULAR user: {} (Requested by: {})", targetUser.getEmail(), userEmail);
                    return new ResponseEntity<>("End entity certificates can only be issued for REGULAR users.", HttpStatus.FORBIDDEN);
                }
                if (!requestDto.getOrganization().equals(userOrganization) && userRole != UserRole.ADMIN) {
                    log.warn("Organization mismatch - Request org: {}, User org: {} (Requested by: {} from IP: {})", requestDto.getOrganization(), userOrganization, userEmail, ipAddress);
                    return new ResponseEntity<>("You can only issue certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
                }
            } else {
                log.warn("Invalid certificate type requested: {} by {} from IP: {}", requestDto.getType(), userEmail, ipAddress);
                return new ResponseEntity<>("Invalid certificate type.", HttpStatus.BAD_REQUEST);
            }

            log.debug("Issuing certificate - Type: {}, Issuer: {}, Target: {}", requestDto.getType(), issuingUser.getEmail(), targetUser.getEmail());
            certificateService.issueCertificate(requestDto, issuingUser, targetUser);

            log.info("Certificate successfully issued - Type: {}, Issuer: {}, Target: {} from IP: {}", requestDto.getType(), issuingUser.getEmail(), targetUser.getEmail(), ipAddress);
            return new ResponseEntity<>("Certificate successfully issued.", HttpStatus.CREATED);

        } catch (IllegalArgumentException e) {
            log.error("Invalid argument while issuing certificate by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            log.error("Error occurred while issuing certificate by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while issuing the certificate.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @GetMapping("/admin/all")
    public ResponseEntity<?> getAllCertificates(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get all certificates from IP: {}", ipAddress);

        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("Get all certificates attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("Get all certificates - User: {}, Role: {}", userEmail, userRole);

            if (userRole != UserRole.ADMIN) {
                log.warn("Non-ADMIN user attempted to get all certificates: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Only ADMIN can view all certificates.", HttpStatus.FORBIDDEN);
            }

            log.debug("Retrieving all certificates");
            List<Certificate> certificates = certificateService.getAllCertificates();
            log.info("Retrieved {} certificates for admin: {} from IP: {}", certificates.size(), userEmail, ipAddress);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("Error retrieving all certificates by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>("Error retrieving certificates: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @GetMapping("/ca/chain")
    public ResponseEntity<?> getCertificateChain(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get certificate chain from IP: {}", ipAddress);

        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("Get certificate chain attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            userEmail = jwtProvider.getEmailFromToken(token);
            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            log.debug("Get certificate chain - User: {}, Role: {}, Organization: {}", userEmail, userRole, userOrganization);

            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                log.warn("Unauthorized user attempted to view certificate chain: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Only ADMIN or CA_USER can view certificate chain.", HttpStatus.FORBIDDEN);
            }

            log.debug("Retrieving certificates for organization: {}", userOrganization);
            List<Certificate> allCerts = certificateService.getCertificatesByOrganization(userOrganization);
            log.debug("Found {} certificates for organization: {}", allCerts.size(), userOrganization);

            Optional<Certificate> rootCert = allCerts.stream()
                    .filter(cert -> cert.getIssuerSerialNumber() == null)
                    .findFirst();

            if (rootCert.isEmpty()) {
                log.info("No root certificate found for organization: {} by {} from IP: {}", userOrganization, userEmail, ipAddress);
                return ResponseEntity.ok(new ArrayList<>());
            }

            log.debug("Root certificate found - Serial: {}", rootCert.get().getSerialNumber());
            List<Certificate> chain = certificateService.getCertificatesFromChain(rootCert.get().getSerialNumber());
            log.info("Certificate chain retrieved - {} certificates for organization: {} by {} from IP: {}", chain.size(), userOrganization, userEmail, ipAddress);
            return ResponseEntity.ok(chain);
        } catch (Exception e) {
            log.error("Error retrieving certificate chain by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>("Error retrieving certificate chain: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @GetMapping("/user/my")
    public ResponseEntity<?> getMyEndEntityCertificates(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get user's end entity certificates from IP: {}", ipAddress);

        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("Get user certificates attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("Retrieving end entity certificates for user: {}", userEmail);

            List<Certificate> certificates = certificateService.getEndEntityCertificatesByUserEmail(userEmail);
            log.info("Retrieved {} end entity certificates for user: {} from IP: {}", certificates.size(), userEmail, ipAddress);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("Error retrieving user certificates for {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>("Error retrieving user certificates: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/ca-user/my")
    public ResponseEntity<?> getMyIntermidiateCertificates(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get CA user's intermediate certificates from IP: {}", ipAddress);

        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("Get CA user certificates attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("Retrieving intermediate certificates for CA user: {}", userEmail);

            List<Certificate> certificates = certificateService.getCertificatesByOrganizationAndUser(userEmail);
            log.info("Retrieved {} intermediate certificates for CA user: {} from IP: {}", certificates.size(), userEmail, ipAddress);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("Error retrieving CA user certificates for {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>("Error retrieving user certificates: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PostMapping("/csr/upload-file")
    public ResponseEntity<String> uploadCsrWithFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("validityInDays") long validityInDays,
            @RequestParam("caIssuerSerialNumber") String caIssuerSerialNumber,
            HttpServletRequest request) {

        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("CSR file upload request - File: {}, Validity: {} days, CA Serial: {} from IP: {}",
                file != null ? file.getOriginalFilename() : "null", validityInDays, caIssuerSerialNumber, ipAddress);
        log.debug("CSR upload - File size: {} bytes", file != null ? file.getSize() : 0);

        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("CSR upload attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("CSR upload - User: {}, Role: {}", userEmail, userRole);

            if (userRole != UserRole.REGULAR_USER) {
                log.warn("Non-REGULAR_USER attempted CSR upload: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Only REGULAR_USER can upload CSR.", HttpStatus.FORBIDDEN);
            }

            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                log.error("Authenticated user not found for CSR upload: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User uploadingUser = optionalUser.get();
            log.debug("Uploading user found: {}", uploadingUser.getEmail());

            if (file.isEmpty()) {
                log.warn("Empty file uploaded by user: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Please select a file to upload.", HttpStatus.BAD_REQUEST);
            }

            if (!file.getOriginalFilename().toLowerCase().endsWith(".pem")) {
                log.warn("Invalid file format uploaded by user: {} from IP: {} - File: {}", userEmail, ipAddress, file.getOriginalFilename());
                return new ResponseEntity<>("Only .pem files are allowed.", HttpStatus.BAD_REQUEST);
            }

            log.debug("Reading PEM content from file: {}", file.getOriginalFilename());
            String pemContent = new String(file.getBytes());
            log.debug("PEM content length: {} characters", pemContent.length());

            log.debug("Extracting CSR information from PEM content");
            String commonName = certificateService.extractCommonName(pemContent);
            String organization = certificateService.extractOrganization(pemContent);
            String email = certificateService.extractEmail(pemContent);
            String keyUsage = certificateService.extractKeyUsage(pemContent);
            String extendedKeyUsage = certificateService.extractExtendedKeyUsage(pemContent);
            log.debug("Extracted CSR data - CN: {}, Org: {}, Email: {}, KeyUsage: {}, ExtKeyUsage: {}",
                    commonName, organization, email, keyUsage, extendedKeyUsage);

            CsrRequestDto csrDto = new CsrRequestDto();
            csrDto.setCsrPemContent(pemContent);
            csrDto.setCommonName(commonName);
            csrDto.setTargetUserEmail(email);
            csrDto.setValidityInDays(validityInDays);
            csrDto.setOrganization(organization);
            csrDto.setCaIssuerSerialNumber(caIssuerSerialNumber);
            csrDto.setKeyUsage(keyUsage);
            csrDto.setExtendedKeyUsage(extendedKeyUsage);

            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            log.debug("Validating organization - CSR org: {}, User org: {}", csrDto.getOrganization(), userOrganization);

            if (!csrDto.getOrganization().equals(userOrganization)) {
                log.warn("Organization mismatch in CSR upload by {} from IP: {} - CSR org: {}, User org: {}",
                        userEmail, ipAddress, csrDto.getOrganization(), userOrganization);
                return new ResponseEntity<>("CSR organization '" + csrDto.getOrganization() + "' does not match your organization: " + userOrganization, HttpStatus.FORBIDDEN);
            }

            log.debug("Looking up target user for CSR: {}", csrDto.getTargetUserEmail());
            Optional<User> targetUserOptional = userService.findByEmail(csrDto.getTargetUserEmail());
            if (targetUserOptional.isEmpty()) {
                log.warn("Target user not found for CSR: {} (Uploader: {})", csrDto.getTargetUserEmail(), userEmail);
                return new ResponseEntity<>("Target user with email '" + csrDto.getTargetUserEmail() + "' not found.", HttpStatus.BAD_REQUEST);
            }

            User targetUser = targetUserOptional.get();
            log.debug("Target user found for CSR: {}", targetUser.getEmail());

            log.debug("Uploading CSR - Uploader: {}, Target: {}", uploadingUser.getEmail(), targetUser.getEmail());
            CsrRequest savedRequest = certificateService.uploadCsr(csrDto, uploadingUser, targetUser);

            log.info("CSR successfully uploaded - ID: {}, Uploader: {}, Target: {} from IP: {}",
                    savedRequest.getId(), uploadingUser.getEmail(), targetUser.getEmail(), ipAddress);
            return new ResponseEntity<>("CSR successfully uploaded from file and pending approval. ID: " + savedRequest.getId(), HttpStatus.CREATED);

        } catch (IllegalArgumentException e) {
            log.error("Invalid argument in CSR upload by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (SecurityException e) {
            log.error("Security exception in CSR upload by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            log.error("Error processing CSR file by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while processing CSR file: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/csr/sign")
    public ResponseEntity<String> signCsr(@Valid @RequestBody CsrRequestDto csrDto, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("CSR signing request - Target user: {}, Organization: {} from IP: {}", csrDto.getTargetUserEmail(), csrDto.getOrganization(), ipAddress);
        log.debug("CSR sign request details: {}", csrDto);

        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("CSR signing attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("CSR signing - User: {}, Role: {}", userEmail, userRole);

            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                log.warn("Unauthorized user attempted to sign CSR: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Only ADMIN or CA_USER can sign CSR requests.", HttpStatus.FORBIDDEN);
            }

            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                log.error("Authenticated user not found for CSR signing: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User signingUser = optionalUser.get();
            log.debug("Signing user found: {}", signingUser.getEmail());

            log.debug("Looking up target user for CSR signing: {}", csrDto.getTargetUserEmail());
            Optional<User> targetUserOptional = userService.findByEmail(csrDto.getTargetUserEmail());
            if (targetUserOptional.isEmpty()) {
                log.warn("Target user not found for CSR signing: {} (Signer: {})", csrDto.getTargetUserEmail(), userEmail);
                return new ResponseEntity<>("Target user not found.", HttpStatus.BAD_REQUEST);
            }

            User targetUser = targetUserOptional.get();
            log.debug("Target user found for CSR signing: {}", targetUser.getEmail());

            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            log.debug("Validating organization for CSR signing - CSR org: {}, User org: {}", csrDto.getOrganization(), userOrganization);

            if (!csrDto.getOrganization().equals(userOrganization)) {
                log.warn("Organization mismatch in CSR signing by {} from IP: {} - CSR org: {}, User org: {}",
                        userEmail, ipAddress, csrDto.getOrganization(), userOrganization);
                return new ResponseEntity<>("You can only sign certificates for your own organization: " + userOrganization, HttpStatus.FORBIDDEN);
            }

            log.debug("Signing CSR and issuing certificate - Signer: {}, Target: {}", signingUser.getEmail(), targetUser.getEmail());
            certificateService.signCsrAndIssueCertificate(csrDto, signingUser, targetUser);

            log.info("CSR successfully signed and certificate issued - Signer: {}, Target: {} from IP: {}", signingUser.getEmail(), targetUser.getEmail(), ipAddress);
            return new ResponseEntity<>("CSR successfully signed and certificate issued.", HttpStatus.CREATED);

        } catch (IllegalArgumentException e) {
            log.error("Invalid argument in CSR signing by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (SecurityException e) {
            log.error("Security exception in CSR signing by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            log.error("Error signing CSR by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while signing CSR: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/ca/list")
    public ResponseEntity<List<Map<String, String>>> getAvailableCaCertificates(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get available CA certificates from IP: {}", ipAddress);

        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("Get CA list attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("Get CA list - User: {}, Role: {}", userEmail, userRole);

            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                log.warn("Unauthorized user attempted to get CA list: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }

            log.debug("Retrieving available CA certificates");
            List<Map<String, String>> caList = certificateService.getAvailableCaCertificates();
            log.info("Retrieved {} CA certificates for user: {} from IP: {}", caList.size(), userEmail, ipAddress);
            return new ResponseEntity<>(caList, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Error retrieving CA certificates by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @GetMapping("/csr/pending")
    public ResponseEntity<List<CsrResponseDto>> getPendingCsrRequests(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get pending CSR requests from IP: {}", ipAddress);

        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("Get pending CSR attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            userEmail = jwtProvider.getEmailFromToken(token);
            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            log.debug("Get pending CSR - User: {}, Role: {}, Organization: {}", userEmail, userRole, userOrganization);

            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                log.warn("Unauthorized user attempted to get pending CSR requests: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }

            log.debug("Retrieving pending CSR requests for organization: {}", userOrganization);
            List<CsrResponseDto> pendingRequests = certificateService.getPendingCsrRequests(userOrganization);
            log.info("Retrieved {} pending CSR requests for organization: {} by {} from IP: {}", pendingRequests.size(), userOrganization, userEmail, ipAddress);
            return new ResponseEntity<>(pendingRequests, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Error retrieving pending CSR requests by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/csr/user")
    public ResponseEntity<List<CsrResponseDto>> getUserCsrRequests(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get user's CSR requests from IP: {}", ipAddress);

        try {

            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                log.warn("Get user CSR attempt without token from IP: {}", ipAddress);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("Get user CSR requests for: {}", userEmail);

            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                log.error("User not found for CSR request retrieval: {} from IP: {}", userEmail, ipAddress);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            User user = optionalUser.get();
            log.debug("Retrieving CSR requests for user: {}", user.getEmail());

            List<CsrResponseDto> userRequests = certificateService.getCsrRequestsByUser(user);
            log.info("Retrieved {} CSR requests for user: {} from IP: {}", userRequests.size(), user.getEmail(), ipAddress);
            return new ResponseEntity<>(userRequests, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Error retrieving user CSR requests for {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/csr/{id}")
    public ResponseEntity<CsrResponseDto> getCsrRequestById(@PathVariable Long id, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get CSR request by ID: {} from IP: {}", id, ipAddress);

        try {
            String token = getJwtFromRequest(request);
            log.debug("Extracted JWT token for CSR ID: {}", id);

            if (!StringUtils.hasText(token)) {
                log.warn("Get CSR by ID {} attempt without token from IP: {}", id, ipAddress);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("Get CSR by ID {} requested by user: {}", id, userEmail);

            log.debug("Retrieving CSR request for ID: {}", id);
            CsrResponseDto csrRequest = certificateService.getCsrRequestById(id);

            log.info("CSR request successfully retrieved - ID: {} by {} from IP: {}", id, userEmail, ipAddress);
            return new ResponseEntity<>(csrRequest, HttpStatus.OK);

        } catch (IllegalArgumentException e) {
            log.warn("CSR request not found for ID {} (Requested by: {} from IP: {}): {}", id, userEmail, ipAddress, e.getMessage());
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            log.error("Error retrieving CSR request by ID {} by {} from IP: {}: {}", id, userEmail, ipAddress, e.getMessage(), e);
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/csr/{id}/reject")
    public ResponseEntity<String> rejectCsrRequest(@PathVariable Long id, @RequestBody String reason, HttpServletRequest request) {
        log.info("CSR rejection request - ID: {}, Reason length: {}", id, reason != null ? reason.length() : 0);
        log.debug("CSR rejection details - ID: {}, Reason: {}", id, reason);

        try {
            String token = getJwtFromRequest(request);
            log.debug("Extracted JWT token from request for CSR rejection ID: {}", id);

            if (!StringUtils.hasText(token)) {
                log.warn("CSR rejection attempt without token for ID {} from IP: {}", id, request.getRemoteAddr());
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            UserRole userRole = jwtProvider.getRoleFromToken(token);
            String userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("CSR rejection - User: {}, Role: {}", userEmail, userRole);

            if (userRole != UserRole.ADMIN && userRole != UserRole.CA_USER) {
                log.warn("Unauthorized user attempted to reject CSR ID {}: {}", id, userEmail);
                return new ResponseEntity<>("Only ADMIN or CA_USER can reject CSR requests.", HttpStatus.FORBIDDEN);
            }

            Optional<User> optionalUser = userService.findByEmail(userEmail);
            if (optionalUser.isEmpty()) {
                log.error("Authenticated user not found for CSR rejection: {}", userEmail);
                return new ResponseEntity<>("Authenticated user not found.", HttpStatus.UNAUTHORIZED);
            }

            User rejectingUser = optionalUser.get();
            log.debug("Rejecting user found: {}", rejectingUser.getEmail());

            log.debug("Calling service to reject CSR ID: {}", id);
            certificateService.rejectCsrRequest(id, reason, rejectingUser);

            log.info("CSR successfully rejected - ID: {}, Rejected by: {}", id, rejectingUser.getEmail());
            return new ResponseEntity<>("CSR request rejected successfully.", HttpStatus.OK);

        } catch (IllegalArgumentException e) {
            log.warn("CSR rejection error (Bad Request) for ID {}: {}", id, e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (SecurityException e) {
            log.error("Security exception while rejecting CSR ID {}: {}", id, e.getMessage(), e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            log.error("Error rejecting CSR ID {}: {}", id, e.getMessage(), e);
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while rejecting CSR request: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/revoke/{serialNumber}")
    public ResponseEntity<?> revoceCertificate(@PathVariable String serialNumber, HttpServletRequest request) {
        log.info("Certificate revoke request - Serial Number: {} from IP: {}", serialNumber, request.getRemoteAddr());

        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            log.debug("User found in SecurityContext for revoke: {}", currentUser.getEmail());

            log.debug("Calling service to revoke certificate with Serial: {}", serialNumber);
            certificateService.revokeCertificate(serialNumber, RevokedReason.KEY_COMPROMISE);

            log.info("Certificate successfully revoked - Serial Number: {}, Revoked by: {}", serialNumber, currentUser.getEmail());
            return ResponseEntity.ok("Certificate revoked successfully");

        } catch (Exception e) {
            log.error("Error revoking certificate Serial {}: {}", serialNumber, e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/intermediate/organization")
    public ResponseEntity<?> getIntermediateCertificatesByOrganization(HttpServletRequest request) {
        log.info("Request to get intermediate certificates by organization from IP: {}", request.getRemoteAddr());

        try {
            String token = getJwtFromRequest(request);
            log.debug("Extracted JWT token for intermediate certificate retrieval");

            if (!StringUtils.hasText(token)) {
                log.warn("Get intermediate certificates attempt without token from IP: {}", request.getRemoteAddr());
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            String userEmail = jwtProvider.getEmailFromToken(token);
            log.debug("Retrieving intermediate certificates for Organization: {}, User: {}", userOrganization, userEmail);

            List<Certificate> intermediateCertificates = certificateService.getIntermediateCertificatesByOrganization(userOrganization);

            log.info("Retrieved {} intermediate certificates for organization: {}", intermediateCertificates.size(), userOrganization);
            return ResponseEntity.ok(intermediateCertificates);

        } catch (Exception e) {
            log.error("Error retrieving intermediate certificates: {}", e.getMessage(), e);
            return new ResponseEntity<>("Error retrieving intermediate certificates: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
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