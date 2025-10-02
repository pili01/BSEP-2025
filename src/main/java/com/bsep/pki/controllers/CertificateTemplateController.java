package com.bsep.pki.controllers;

import com.bsep.pki.models.CertificateTemplate;
import com.bsep.pki.services.CertificateTemplateService;
import com.bsep.pki.models.User;
import jakarta.servlet.http.HttpServletRequest; // DODATO: Import za HttpServletRequest
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/certificate-templates")
public class CertificateTemplateController {

    private final CertificateTemplateService certificateTemplateService;
    private final Logger log = LogManager.getLogger(CertificateTemplateController.class);

    public CertificateTemplateController(CertificateTemplateService certificateTemplateService) {
        this.certificateTemplateService = certificateTemplateService;
    }

    @PostMapping("/create")
    public ResponseEntity<CertificateTemplate> createTemplate(@RequestBody CertificateTemplate template, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Certificate template creation request - Name: {} from IP: {}", template.getTemplateName(), ipAddress);
        log.debug("Template details received: {}", template);

        try {
            User creator = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            userEmail = creator.getEmail(); // Ažuriranje email adrese
            log.debug("Template creator identified: {}", userEmail);

            template.setUser(creator);

            log.debug("Calling service to persist template: {}", template.getTemplateName());
            CertificateTemplate newTemplate = certificateTemplateService.createTemplate(template);

            log.info("Certificate template successfully created - ID: {}, Name: {} by {} from IP: {}", newTemplate.getId(), newTemplate.getTemplateName(), userEmail, ipAddress);

            return new ResponseEntity<>(newTemplate, HttpStatus.CREATED);

        } catch (IllegalArgumentException e) {
            log.warn("Invalid argument during template creation for {} by {} from IP: {}: {}", template.getTemplateName(), userEmail, ipAddress, e.getMessage());
            return ResponseEntity.badRequest().build();
        } catch (ClassCastException | IllegalStateException e) {
            log.warn("Unauthorized attempt to create template from IP: {} (User not authenticated or context error): {}", ipAddress, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            log.error("Error creating template by {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            System.err.println("Error creating template: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/all")
    public ResponseEntity<List<CertificateTemplate>> getAllTemplates(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        log.info("Request to get all certificate templates from IP: {}", ipAddress);

        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String userEmail = currentUser.getEmail();

            log.debug("Retrieving all templates from service. Requested by: {}", userEmail);
            List<CertificateTemplate> templates = certificateTemplateService.findAll();

            log.info("Successfully retrieved {} certificate templates by {} from IP: {}.", templates.size(), userEmail, ipAddress);
            return ResponseEntity.ok(templates);

        } catch (ClassCastException e) {
            log.debug("Unauthenticated request to get all templates from IP: {}", ipAddress);
            List<CertificateTemplate> templates = certificateTemplateService.findAll();
            log.info("Successfully retrieved {} certificate templates (Unauthenticated) from IP: {}.", templates.size(), ipAddress);
            return ResponseEntity.ok(templates);
        } catch (Exception e) {
            log.error("Error retrieving all templates from IP: {}: {}", ipAddress, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<CertificateTemplate> getTemplateById(@PathVariable Long id, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";
        log.info("Request to get certificate template by ID: {} from IP: {}", id, ipAddress);

        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            userEmail = currentUser.getEmail();
        } catch (Exception ignore) {
        }

        Optional<CertificateTemplate> template = certificateTemplateService.findById(id);

        if (template.isPresent()) {
            log.info("Certificate template found - ID: {}, Name: {} (Requested by: {} from IP: {})", id, template.get().getTemplateName(), userEmail, ipAddress);
            return ResponseEntity.ok(template.get());
        } else {
            log.warn("Certificate template not found for ID: {} (Requested by: {} from IP: {})", id, userEmail, ipAddress);
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/my-templates")
    public ResponseEntity<List<CertificateTemplate>> getMyTemplates(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userEmail = "UNKNOWN";

        log.info("Request to get current user's certificate templates from IP: {}", ipAddress);

        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            userEmail = currentUser.getEmail();
            log.debug("Current user for 'my-templates' found: {}", userEmail);

            log.debug("Calling service to find templates for User ID: {}", currentUser.getId());
            List<CertificateTemplate> userTemplates = certificateTemplateService.findByUserId(currentUser.getId());

            log.info("Retrieved {} templates for user: {} from IP: {}", userTemplates.size(), userEmail, ipAddress);
            return ResponseEntity.ok(userTemplates);

        } catch (ClassCastException | IllegalStateException e) {
            log.warn("Unauthorized attempt to get user templates from IP: {} (User context error): {}", ipAddress, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            log.error("Error retrieving user templates for {} from IP: {}: {}", userEmail, ipAddress, e.getMessage(), e);
            System.err.println("Error retrieving user templates: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}