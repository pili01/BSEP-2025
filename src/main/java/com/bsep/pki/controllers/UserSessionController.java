package com.bsep.pki.controllers;

import com.bsep.pki.models.User;
import com.bsep.pki.models.UserSession;
import com.bsep.pki.services.UserSessionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/sessions")
public class UserSessionController {

    private final UserSessionService userSessionService;

    public UserSessionController(UserSessionService userSessionService) {
        this.userSessionService = userSessionService;
    }

    @GetMapping
    public ResponseEntity<List<UserSession>> getUserSessions() {
        try {
            User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            List<UserSession> sessions = userSessionService.findSessionsByUserId(currentUser.getId());
            return ResponseEntity.ok(sessions);
        } catch (Exception e) {
            System.out.println("Exception in getUserSessions: " + e.getClass().getName());
            System.out.println("Exception message: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @DeleteMapping("/{jti}")
    public ResponseEntity<Void> revokeSession(@PathVariable String jti) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<UserSession> session = userSessionService.findSessionByJti(jti);

        if (session.isPresent() && session.get().getUser().getId().equals(currentUser.getId())) {
            userSessionService.deleteSessionByJti(jti);
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
