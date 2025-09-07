package com.bsep.pki.models;

import org.springframework.security.core.GrantedAuthority;

public enum UserRole implements GrantedAuthority {
    ADMIN,
    CA_USER,
    REGULAR_USER;

    @Override
    public String getAuthority() {
        return name();
    }
}
