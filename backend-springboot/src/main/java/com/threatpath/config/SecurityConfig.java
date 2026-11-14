package com.threatpath.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${threatpath.security.admin-bcrypt-hash:$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW}")
    private String adminBcryptHash;

    @Value("${threatpath.security.analyst-bcrypt-hash:$2a$12$8K1p/a0dL1LXMIgoEDFrwOfMQkL/bO8S8xU9z0v1w2x3y4z5A6B7C}")
    private String analystBcryptHash;

    @Value("${threatpath.security.readonly-bcrypt-hash:$2a$12$4J2q/b1eM2MYNJhpFEGsxPgNRlM/cP9T9yV0A1w3x4y5z6A7B8C9D}")
    private String readonlyBcryptHash;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/v1/health"))
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/health").permitAll()
                .requestMatchers("/api/v1/lifecycle/remediation/**").hasRole("ADMIN")
                .requestMatchers("/api/v1/scans/**", "/api/v1/investigations/**", "/api/v1/lifecycle/**").hasAnyRole("ADMIN", "ANALYST")
                .requestMatchers("/api/v1/**").hasAnyRole("ADMIN", "ANALYST", "READ_ONLY")
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.builder()
            .username("admin_secops")
            .password(adminBcryptHash)
            .roles("ADMIN", "ANALYST")
            .build();
        UserDetails analyst = User.builder()
            .username("student_analyst")
            .password(analystBcryptHash)
            .roles("ANALYST")
            .build();
        UserDetails viewer = User.builder()
            .username("audit_viewer")
            .password(readonlyBcryptHash)
            .roles("READ_ONLY")
            .build();
        return new InMemoryUserDetailsManager(admin, analyst, viewer);
    }
}
