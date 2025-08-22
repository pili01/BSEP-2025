package com.bsep.pki.utils;

import com.bsep.pki.models.User;
import com.bsep.pki.models.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtProvider {

    @Value("${app.jwt-secret}")
    private String jwtSecret;

    @Value("${app.jwt-expiration-milliseconds}")
    private long jwtExpiration;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(Authentication authentication) {
        User user = (User) authentication.getPrincipal();

        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + jwtExpiration);
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setSubject(user.getEmail())
                .setIssuedAt(currentDate)
                .setExpiration(expireDate)
                .setId(jti)
                .claim("userId", user.getId())
                .claim("role", user.getRole().name())
                .claim("organization", user.getOrganization())
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getJtiFromToken(String token) {
        return getClaimsFromToken(token).getId();
    }

    public String getEmailFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public Long getUserIdFromToken(String token) {
        return getClaimsFromToken(token).get("userId", Long.class);
    }

    public UserRole getRoleFromToken(String token) {
        String roleName = getClaimsFromToken(token).get("role", String.class);
        return UserRole.valueOf(roleName);
    }

    public boolean validateToken(String token) {
        try {
            getClaimsFromToken(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getOrganizationFromToken(String token) {
        return getClaimsFromToken(token).get("organization", String.class);
    }
}