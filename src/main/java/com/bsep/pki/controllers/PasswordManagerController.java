package com.bsep.pki.controllers;

import com.bsep.pki.dtos.PasswordShareDto;
import com.bsep.pki.dtos.StoredPasswordDto;
import com.bsep.pki.models.User;
import com.bsep.pki.services.StoredPasswordService;
import jakarta.servlet.http.HttpServletRequest; // DODATO: Import za HttpServletRequest
import jakarta.validation.Valid;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/passwords")
public class PasswordManagerController {

    private final StoredPasswordService storedPasswordService;
    private final Logger log = LogManager.getLogger(PasswordManagerController.class);

    public PasswordManagerController(StoredPasswordService storedPasswordService) {
        this.storedPasswordService = storedPasswordService;
    }

    @PostMapping("/add")
    public ResponseEntity<?> addNewPassword(@Valid @RequestBody StoredPasswordDto storedPasswordDto, HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();

        log.info("Request to add new stored password by user: {} from IP: {}", currentUser.getEmail(), ipAddress);
        log.debug("Password DTO details received: {}", storedPasswordDto);

        try {
            log.debug("Setting owner ID and share user IDs for user: {}", currentUser.getId());
            storedPasswordDto.setOwnerId(currentUser.getId());
            storedPasswordDto.getShares().forEach(share -> share.setUserId(currentUser.getId()));

            log.debug("Calling service to save password.");
            storedPasswordService.savePassword(storedPasswordDto);

            log.info("Password saved successfully by user: {} from IP: {}", currentUser.getEmail(), ipAddress);
            return ResponseEntity.ok("Password saved successfully");
        } catch (Exception e) {
            log.error("Error saving new password for user {} from IP: {}: {}", currentUser.getEmail(), ipAddress, e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/get")
    public ResponseEntity<?> getPasswords(HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();

        log.info("Request to retrieve all stored passwords for user: {} from IP: {}", currentUser.getEmail(), ipAddress);

        try {
            log.debug("Calling service to retrieve passwords for user ID: {}", currentUser.getId());
            var myPasswords = storedPasswordService.getMyPasswords(currentUser.getId());

            log.info("Successfully retrieved {} passwords for user: {} from IP: {}", myPasswords.size(), currentUser.getEmail(), ipAddress);
            return ResponseEntity.ok(myPasswords);
        } catch (Exception e) {
            log.error("Error retrieving passwords for user {} from IP: {}: {}", currentUser.getEmail(), ipAddress, e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/share/{id}")
    public ResponseEntity<?> sharePassword(@PathVariable String id, @RequestBody PasswordShareDto passwordShareDto, HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();

        log.info("Request to share password ID {} with user ID: {} by user: {} from IP: {}", id, passwordShareDto.getUserId(), currentUser.getEmail(), ipAddress);
        log.debug("Share details - ID: {}, Receiver: {}", id, passwordShareDto.getUserId());

        try {
            log.debug("Calling service to execute share operation.");
            storedPasswordService.sharePassword(currentUser.getId(), id, passwordShareDto);

            log.info("Password ID {} successfully shared by {} with user ID: {} from IP: {}", id, currentUser.getEmail(), passwordShareDto.getUserId(), ipAddress);
            return ResponseEntity.ok("Password shared successfully");
        } catch (Exception e) {
            log.error("Error sharing password ID {} by user {} from IP: {}: {}", id, currentUser.getEmail(), ipAddress, e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}