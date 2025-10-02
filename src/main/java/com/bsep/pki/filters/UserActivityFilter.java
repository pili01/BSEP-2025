package com.bsep.pki.filters;

import com.bsep.pki.services.UserSessionService;
import com.bsep.pki.utils.JwtProvider;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String authHeader = httpRequest.getHeader("Authorization");
        String uri = httpRequest.getRequestURI();

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtProvider.validateToken(token)) {
                String jti = jwtProvider.getJtiFromToken(token);
                boolean initial = jwtProvider.isInitialPasswordToken(token);
                if (initial) {
                    // Allow only auth endpoints when initial password token is used
                    if (uri.startsWith("/api/auth")) {
                        chain.doFilter(request, response);
                        return;
                    } else {
                        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        httpResponse.setContentType("application/json");
                        httpResponse.getWriter().write("{\"message\":\"Password change required\"}");
                        return;
                    }
                }

                if (userSessionService.findSessionByJti(jti).isEmpty()) {
                    httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    httpResponse.setContentType("application/json");
                    httpResponse.getWriter().write("{\"message\":\"Session revoked\"}");
                    return;
                }

                userSessionService.updateLastActivity(jti);
            }
        }

        chain.doFilter(request, response);
    }
}