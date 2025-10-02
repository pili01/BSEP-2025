package com.bsep.pki.controllers;

import com.bsep.pki.models.User;
import com.bsep.pki.models.UserSession;
import com.bsep.pki.services.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
    private final Logger log = LogManager.getLogger(UserSessionController.class);

    public UserSessionController(UserSessionService userSessionService) {
        this.userSessionService = userSessionService;
    }

    @GetMapping
    public ResponseEntity<List<UserSession>> getUserSessions(HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();

        log.info("Request to retrieve all active user sessions for user: {} from IP: {}", currentUser.getEmail(), ipAddress);

        try {
            log.debug("Calling service to find sessions by user ID: {}", currentUser.getId());
            List<UserSession> sessions = userSessionService.findSessionsByUserId(currentUser.getId());

            log.info("Retrieved {} sessions for user: {} from IP: {}", sessions.size(), currentUser.getEmail(), ipAddress);
            return ResponseEntity.ok(sessions);

        } catch (Exception e) {
            log.error("Exception retrieving sessions for user {} from IP: {}: {}. Message: {}", currentUser.getEmail(), ipAddress, e.getClass().getName(), e.getMessage(), e);
            System.out.println("Exception in getUserSessions: " + e.getClass().getName());
            System.out.println("Exception message: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @DeleteMapping("/{jti}")
    public ResponseEntity<Void> revokeSession(@PathVariable String jti, HttpServletRequest request) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String ipAddress = request.getRemoteAddr();

        log.info("Request to revoke session with JTI: {} by user: {} from IP: {}", jti, currentUser.getEmail(), ipAddress);
        log.debug("Revocation attempt by user: {}", currentUser.getEmail());

        Optional<UserSession> session = userSessionService.findSessionByJti(jti);

        if (session.isPresent()) {
            UserSession userSession = session.get();
            log.debug("Session found for JTI {}. Owner ID: {}, Current User ID: {}", jti, userSession.getUser().getId(), currentUser.getId());

            if (userSession.getUser().getId().equals(currentUser.getId())) {
                userSessionService.deleteSessionByJti(jti);
                log.info("Session with JTI {} successfully revoked by owner: {} from IP: {}", jti, currentUser.getEmail(), ipAddress);
                return ResponseEntity.noContent().build();
            } else {
                log.warn("User {} from IP: {} attempted to revoke session with JTI {} owned by another user (Owner ID: {}). Access forbidden.", currentUser.getEmail(), ipAddress, jti, userSession.getUser().getId());
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
        }

        log.warn("User {} from IP: {} attempted to revoke non-existent session with JTI: {}. Returning FORBIDDEN (to obscure existence).", currentUser.getEmail(), ipAddress, jti);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}