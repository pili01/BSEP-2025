package com.bsep.pki.config;

import com.bsep.pki.filters.JwtAuthentificationFilter;
import com.bsep.pki.filters.UserActivityFilter;
import com.bsep.pki.services.CustomUserDetailsService;
import com.bsep.pki.utils.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    private final UserActivityFilter userActivityFilter;

    @Autowired
    public JwtProvider token;

    @Autowired
    public CustomUserDetailsService customUserDetailsService;

    public SecurityConfig(UserActivityFilter userActivityFilter) {
        this.userActivityFilter = userActivityFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/auth/**").permitAll()  //.hasAuthority('REGULAR_USER') .authenticated()
                        .requestMatchers("/api/certificates/**").permitAll()
                        .requestMatchers("/api/admin/**").permitAll()
                        .requestMatchers("/api/crl").permitAll()
                        .requestMatchers("/api/sessions/**").authenticated()
                        .requestMatchers("/api/passwords/**").hasAnyAuthority("REGULAR_USER")
                        .anyRequest().authenticated()
                )
                .cors(cors -> cors
                        .configurationSource(corsConfigurationSource())
                )
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("frame-ancestors 'self' https://www.google.com https://www.gstatic.com;")
                        )
                )
                .addFilterBefore(userActivityFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthentificationFilter(token, customUserDetailsService),
                        BasicAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration configuration = new org.springframework.web.cors.CorsConfiguration();
        configuration.setAllowedOrigins(java.util.List.of("https://localhost:5173"));
        configuration.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(java.util.List.of("*"));
        configuration.setAllowCredentials(true);
        org.springframework.web.cors.UrlBasedCorsConfigurationSource source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}