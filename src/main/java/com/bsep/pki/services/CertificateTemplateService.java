package com.bsep.pki.services;

import com.bsep.pki.models.CertificateTemplate;
import com.bsep.pki.repositories.CertificateTemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CertificateTemplateService {

    private final CertificateTemplateRepository certificateTemplateRepository;

    @Autowired
    public CertificateTemplateService(CertificateTemplateRepository certificateTemplateRepository) {
        this.certificateTemplateRepository = certificateTemplateRepository;
    }

    public CertificateTemplate createTemplate(CertificateTemplate template) {
        if (template.getMaxValidityDays() <= 0) {
            throw new IllegalArgumentException("Max valid days must be greater than 0");
        }

        return certificateTemplateRepository.save(template);
    }

    public Optional<CertificateTemplate> findById(Long id) {
        return certificateTemplateRepository.findById(id);
    }

    public List<CertificateTemplate> findAll() {
        return certificateTemplateRepository.findAll();
    }
}