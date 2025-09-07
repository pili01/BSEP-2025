package com.bsep.pki.models;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, unique = true)
    private String jti;

    @Column
    private String ipAddress;

    @Column
    private String device;

    @Column
    private LocalDateTime lastActivity;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    public UserSession() {
        this.createdAt = LocalDateTime.now();
    }

}