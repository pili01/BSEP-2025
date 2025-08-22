package com.bsep.pki.services;

import com.bsep.pki.models.User;
import com.bsep.pki.models.UserSession;
import com.bsep.pki.repositories.UserSessionRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class UserSessionService {

    private final UserSessionRepository userSessionRepository;

    public UserSessionService(UserSessionRepository userSessionRepository) {
        this.userSessionRepository = userSessionRepository;
    }

    public UserSession createSession(User user, String jti, String deviceInfo, String ipAddress) {
        UserSession userSession = new UserSession();
        userSession.setUser(user);
        userSession.setJti(jti);
        userSession.setDevice(deviceInfo);
        userSession.setIpAddress(ipAddress);
        userSession.setLastActivity(LocalDateTime.now());

        return userSessionRepository.save(userSession);
    }

    public Optional<UserSession> findSessionByJti(String jti) {
        return userSessionRepository.findByJti(jti);
    }

    public List<UserSession> findSessionsByUserId(Long userId) {
        return userSessionRepository.findAllByUserId(userId);
    }


    @Transactional
    public void deleteSessionByJti(String jti) {
        userSessionRepository.deleteByJti(jti);
    }

    @Transactional
    public void updateLastActivity(String jti) {
        Optional<UserSession> sessionOptional = userSessionRepository.findByJti(jti);
        if (sessionOptional.isPresent()) {
            UserSession session = sessionOptional.get();
            session.setLastActivity(LocalDateTime.now());
            userSessionRepository.save(session);
        }
    }

    public void deleteAllSessionsForUser(Long userId) {
        List<UserSession> sessions = userSessionRepository.findAllByUserId(userId);
        userSessionRepository.deleteAll(sessions);
    }
}