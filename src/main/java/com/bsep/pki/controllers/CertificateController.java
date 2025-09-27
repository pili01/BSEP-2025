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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
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
            @RequestParam("validityInDays") long validityInDays,
            @RequestParam("caIssuerSerialNumber") String caIssuerSerialNumber,
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


            if (file.isEmpty()) {
                return new ResponseEntity<>("Please select a file to upload.", HttpStatus.BAD_REQUEST);
            }

            if (!file.getOriginalFilename().toLowerCase().endsWith(".pem")) {
                return new ResponseEntity<>("Only .pem files are allowed.", HttpStatus.BAD_REQUEST);
            }


            String pemContent = new String(file.getBytes());

            // Simple parsing from CSR content
            String commonName = extractCommonName(pemContent);
            String organization = extractOrganization(pemContent);
            String email = extractEmail(pemContent);
            String keyUsage = extractKeyUsage(pemContent);
            String extendedKeyUsage = extractExtendedKeyUsage(pemContent);

            CsrRequestDto csrDto = new CsrRequestDto();
            csrDto.setCsrPemContent(pemContent);
            csrDto.setCommonName(commonName);
            csrDto.setTargetUserEmail(email);
            csrDto.setValidityInDays(validityInDays);
            csrDto.setOrganization(organization);
            csrDto.setCaIssuerSerialNumber(caIssuerSerialNumber);
            csrDto.setKeyUsage(keyUsage);
            csrDto.setExtendedKeyUsage(extendedKeyUsage);

            // Validate organization matches user's organization
            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            if (!csrDto.getOrganization().equals(userOrganization)) {
                return new ResponseEntity<>("CSR organization '" + csrDto.getOrganization() + "' does not match your organization: " + userOrganization, HttpStatus.FORBIDDEN);
            }

            // Find target user
            Optional<User> targetUserOptional = userService.findByEmail(csrDto.getTargetUserEmail());
            if (targetUserOptional.isEmpty()) {
                return new ResponseEntity<>("Target user with email '" + csrDto.getTargetUserEmail() + "' not found.", HttpStatus.BAD_REQUEST);
            }

            User targetUser = targetUserOptional.get();

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

    @GetMapping("/revoke/{serialNumber}")
    public ResponseEntity<?> revoceCertificate(@PathVariable String serialNumber, HttpServletRequest request) {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            certificateService.revokeCertificate(serialNumber, RevokedReason.KEY_COMPROMISE);
            return ResponseEntity.ok("Certificate revoked successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/intermediate/organization")
    public ResponseEntity<?> getIntermediateCertificatesByOrganization(HttpServletRequest request) {
        try {
            String token = getJwtFromRequest(request);
            if (!StringUtils.hasText(token)) {
                return new ResponseEntity<>("Authorization token is missing.", HttpStatus.UNAUTHORIZED);
            }

            String userOrganization = jwtProvider.getOrganizationFromToken(token);
            List<Certificate> intermediateCertificates = certificateService.getIntermediateCertificatesByOrganization(userOrganization);

            return ResponseEntity.ok(intermediateCertificates);
        } catch (Exception e) {
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

    private String extractCommonName(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            X500Name subject = csr.getSubject();
            String subjectString = subject.toString();
            
            // Parse CN from subject string like "CN=NoviCA, O=Security Inc., E=papovicognjen59@gmail.com"
            int cnIndex = subjectString.indexOf("CN=");
            if (cnIndex != -1) {
                int start = cnIndex + 3;
                int end = subjectString.indexOf(",", start);
                if (end == -1) end = subjectString.length();
                return subjectString.substring(start, end).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private String extractOrganization(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            X500Name subject = csr.getSubject();
            String subjectString = subject.toString();
            
            // Parse O from subject string like "CN=NoviCA, O=Security Inc., E=papovicognjen59@gmail.com"
            int oIndex = subjectString.indexOf("O=");
            if (oIndex != -1) {
                int start = oIndex + 2;
                int end = subjectString.indexOf(",", start);
                if (end == -1) end = subjectString.length();
                return subjectString.substring(start, end).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private String extractEmail(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            X500Name subject = csr.getSubject();
            String subjectString = subject.toString();
            
            // Parse E from subject string like "CN=NoviCA, O=Security Inc., E=papovicognjen59@gmail.com"
            int eIndex = subjectString.indexOf("E=");
            if (eIndex != -1) {
                int start = eIndex + 2;
                int end = subjectString.indexOf(",", start);
                if (end == -1) end = subjectString.length();
                return subjectString.substring(start, end).trim();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private String extractKeyUsage(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            
            // Look for keyUsage extension in attributes
            org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();
            for (org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
                if (attr.getAttrType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    org.bouncycastle.asn1.ASN1Set attrValues = attr.getAttrValues();
                    for (int i = 0; i < attrValues.size(); i++) {
                        org.bouncycastle.asn1.x509.Extensions extensions = org.bouncycastle.asn1.x509.Extensions.getInstance(attrValues.getObjectAt(i));
                        org.bouncycastle.asn1.x509.Extension keyUsageExt = extensions.getExtension(org.bouncycastle.asn1.x509.Extension.keyUsage);
                        if (keyUsageExt != null) {
                            org.bouncycastle.asn1.x509.KeyUsage keyUsage = org.bouncycastle.asn1.x509.KeyUsage.getInstance(keyUsageExt.getParsedValue());
                            return keyUsageToString(keyUsage);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private String extractExtendedKeyUsage(String pemContent) {
        try {
            PKCS10CertificationRequest csr = parseCsrFromPem(pemContent);
            
            // Look for extendedKeyUsage extension in attributes
            org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();
            for (org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
                if (attr.getAttrType().equals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    org.bouncycastle.asn1.ASN1Set attrValues = attr.getAttrValues();
                    for (int i = 0; i < attrValues.size(); i++) {
                        org.bouncycastle.asn1.x509.Extensions extensions = org.bouncycastle.asn1.x509.Extensions.getInstance(attrValues.getObjectAt(i));
                        org.bouncycastle.asn1.x509.Extension extendedKeyUsageExt = extensions.getExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage);
                        if (extendedKeyUsageExt != null) {
                            org.bouncycastle.asn1.x509.ExtendedKeyUsage extendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(extendedKeyUsageExt.getParsedValue());
                            return extendedKeyUsageToString(extendedKeyUsage);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private PKCS10CertificationRequest parseCsrFromPem(String pemContent) throws Exception {
        try (java.io.StringReader stringReader = new java.io.StringReader(pemContent);
             org.bouncycastle.util.io.pem.PemReader pemReader = new org.bouncycastle.util.io.pem.PemReader(stringReader)) {

            org.bouncycastle.util.io.pem.PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("Invalid PEM content: no PEM object found");
            }

            if (!pemObject.getType().equals("CERTIFICATE REQUEST")) {
                throw new IllegalArgumentException("Invalid PEM content: expected CERTIFICATE REQUEST, got " + pemObject.getType());
            }

            return new PKCS10CertificationRequest(pemObject.getContent());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse CSR from PEM: " + e.getMessage(), e);
        }
    }

    private String keyUsageToString(org.bouncycastle.asn1.x509.KeyUsage keyUsage) {
        java.util.List<String> usages = new java.util.ArrayList<>();
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature)) usages.add("digitalSignature");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation)) usages.add("nonRepudiation");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment)) usages.add("keyEncipherment");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment)) usages.add("dataEncipherment");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.keyAgreement)) usages.add("keyAgreement");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign)) usages.add("keyCertSign");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.cRLSign)) usages.add("cRLSign");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.encipherOnly)) usages.add("encipherOnly");
        if (keyUsage.hasUsages(org.bouncycastle.asn1.x509.KeyUsage.decipherOnly)) usages.add("decipherOnly");
        return String.join(",", usages);
    }

    private String extendedKeyUsageToString(org.bouncycastle.asn1.x509.ExtendedKeyUsage extendedKeyUsage) {
        java.util.List<String> usages = new java.util.ArrayList<>();
        for (KeyPurposeId oid : extendedKeyUsage.getUsages()) {
            if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth)) usages.add("serverAuth");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth)) usages.add("clientAuth");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_codeSigning)) usages.add("codeSigning");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_emailProtection)) usages.add("emailProtection");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_timeStamping)) usages.add("timeStamping");
            else if (oid.equals(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning)) usages.add("ocspSigning");
        }
        return String.join(",", usages);
    }

}