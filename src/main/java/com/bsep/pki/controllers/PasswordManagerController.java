package com.bsep.pki.controllers;

import com.bsep.pki.dtos.PasswordShareDto;
import com.bsep.pki.dtos.StoredPasswordDto;
import com.bsep.pki.models.User;
import com.bsep.pki.services.StoredPasswordService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/passwords")
public class PasswordManagerController {
    private final StoredPasswordService storedPasswordService;

    public PasswordManagerController(StoredPasswordService storedPasswordService) {
        this.storedPasswordService = storedPasswordService;
    }

    @PostMapping("/add")
    public ResponseEntity<?> addNewPassword(@Valid @RequestBody StoredPasswordDto storedPasswordDto) {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            storedPasswordDto.setOwnerId(currentUser.getId());
            storedPasswordDto.getShares().forEach(share -> share.setUserId(currentUser.getId()));
            storedPasswordService.savePassword(storedPasswordDto);
            return ResponseEntity.ok("Password saved successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/get")
    public ResponseEntity<?> getPasswords() {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            var myPasswords = storedPasswordService.getMyPasswords(currentUser.getId());
            return ResponseEntity.ok(myPasswords);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/share/{id}")
    public ResponseEntity<?> sharePassword(@PathVariable String id, @RequestBody PasswordShareDto passwordShareDto) {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            storedPasswordService.sharePassword(currentUser.getId(), id, passwordShareDto);
            return ResponseEntity.ok("Password shared successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
