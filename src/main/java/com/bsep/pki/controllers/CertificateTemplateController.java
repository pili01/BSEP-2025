package com.bsep.pki.controllers;

import com.bsep.pki.models.CertificateTemplate;
import com.bsep.pki.services.CertificateTemplateService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import com.bsep.pki.models.User;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/certificate-templates")
public class CertificateTemplateController {

    private final CertificateTemplateService certificateTemplateService;

    public CertificateTemplateController(CertificateTemplateService certificateTemplateService) {
        this.certificateTemplateService = certificateTemplateService;
    }

    @PostMapping("/create")
    public ResponseEntity<CertificateTemplate> createTemplate(@RequestBody CertificateTemplate template) {
        try {
            User creator = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            template.setUser(creator);
            CertificateTemplate newTemplate = certificateTemplateService.createTemplate(template);
            return new ResponseEntity<>(newTemplate, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (ClassCastException | IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            System.err.println("Error creating template: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/all")
    public ResponseEntity<List<CertificateTemplate>> getAllTemplates() {
        try {
            List<CertificateTemplate> templates = certificateTemplateService.findAll();
            return ResponseEntity.ok(templates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<CertificateTemplate> getTemplateById(@PathVariable Long id) {
        Optional<CertificateTemplate> template = certificateTemplateService.findById(id);

        if (template.isPresent()) {
            return ResponseEntity.ok(template.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/my-templates")
    public ResponseEntity<List<CertificateTemplate>> getMyTemplates() {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            List<CertificateTemplate> userTemplates = certificateTemplateService.findByUserId(currentUser.getId());
            return ResponseEntity.ok(userTemplates);
        } catch (ClassCastException | IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            System.err.println("Error retrieving user templates: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}