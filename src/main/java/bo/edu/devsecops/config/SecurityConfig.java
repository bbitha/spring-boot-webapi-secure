package bo.edu.devsecops.config;

import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig {

    static final Pattern BCRYPT_HASH = Pattern.compile("^\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}$");

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Cookie XSRF-TOKEN, no httpOnly, para que un cliente JS la
                // pueda leer y devolverla en la cabecera X-XSRF-TOKEN.
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/products/search").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/csrf").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                // X-Content-Type-Options: nosniff ya viene por defecto;
                // CSP no, hay que declararla (mitiga el XSS de CommentController).
                .headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")))
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(
            @Value("${app.security.admin-username:admin}") String adminUsername,
            @Value("${app.security.admin-password-hash:}") String adminPasswordHash) {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        if (BCRYPT_HASH.matcher(adminPasswordHash).matches()) {
            manager.createUser(User.withUsername(adminUsername)
                    .password(adminPasswordHash)
                    .roles("ADMIN")
                    .build());
        }
        // Si ADMIN_PASSWORD_HASH falta o no es un hash bcrypt valido, no se
        // registra ningun usuario: /api/admin/** queda inaccesible en vez de
        // caer a una credencial por defecto conocida.
        return manager;
    }
}
