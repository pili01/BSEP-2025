package com.bsep.pki.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LogManager.getLogger(RequestLoggingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestId = UUID.randomUUID().toString();
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null && auth.getPrincipal() != null ? auth.getName() : "anonymous";

        ThreadContext.put("requestId", requestId);
        ThreadContext.put("ipAddress", ipAddress);
        ThreadContext.put("userAgent", userAgent != null ? userAgent : "");
        ThreadContext.put("username", username);

        try {
            filterChain.doFilter(request, response);
        } finally {
            ThreadContext.clearAll();
        }
    }
}


