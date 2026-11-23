package com.tracking.logistica.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.tracking.logistica.security.JsonSecurityHandlers;
import com.tracking.logistica.security.JwtAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.List;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JsonSecurityHandlers securityHandlers;

    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(allowedOrigins);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            // Sin HttpSession: el estado de la sesión vive en la tabla user_sessions (HU-S-22).
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Sin sesión válida (ausente, vencida o cerrada): 401 con motivo. Con sesión pero sin rol: 403.
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(securityHandlers.entryPoint())
                .accessDeniedHandler(securityHandlers.accessDeniedHandler()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                // El 403 se reenvía a /error sin contexto de seguridad (API stateless);
                // si /error exigiera autenticación, la respuesta se convertiría en 401.
                .requestMatchers("/error").permitAll()
                .requestMatchers("/api/tracking/mine", "/api/contact").hasRole("CLIENTE")
                .requestMatchers("/api/admin/**").hasRole("ADMINISTRADOR")
                .requestMatchers("/api/supervisor/**").hasRole("SUPERVISOR_LOGISTICO")
                .requestMatchers("/api/operador/**").hasRole("OPERADOR_LOGISTICO")
                .requestMatchers("/api/tracking/**").hasAnyRole(
                    "CLIENTE", "OPERADOR_LOGISTICO", "SUPERVISOR_LOGISTICO")
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
