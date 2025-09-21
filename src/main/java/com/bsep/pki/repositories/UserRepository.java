package com.bsep.pki.repositories;
import com.bsep.pki.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    @Query("SELECT u FROM User u WHERE u.id = :userId AND u.role = 'REGULAR_USER'")
    Optional<User> findRegularById(Long userId);
}