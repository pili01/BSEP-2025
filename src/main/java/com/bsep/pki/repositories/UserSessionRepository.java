package com.bsep.pki.repositories;
import com.bsep.pki.models.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findByJti(String jti);
    List<UserSession> findAllByUserId(Long userId);
    void deleteByJti(String jti);
}