package com.bsep.pki.filters;

import com.bsep.pki.services.UserSessionService;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class UserActivityFilter implements Filter {

    private final UserSessionService userSessionService;
    private final JwtProvider jwtProvider;

    public UserActivityFilter(UserSessionService userSessionService, JwtProvider jwtProvider) {
        this.userSessionService = userSessionService;
        this.jwtProvider = jwtProvider;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String authHeader = httpRequest.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtProvider.validateToken(token)) {
                String jti = jwtProvider.getJtiFromToken(token);
                userSessionService.updateLastActivity(jti);
            }
        }

        chain.doFilter(request, response);
    }
}