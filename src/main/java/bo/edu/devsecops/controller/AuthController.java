package bo.edu.devsecops.controller;

import java.util.Map;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private static final Pattern BCRYPT_HASH = Pattern.compile("^\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}$");

    private final PasswordEncoder passwordEncoder;
    private final String adminUsername;
    private final String adminPasswordHash;

    public AuthController(
            PasswordEncoder passwordEncoder,
            @Value("${app.security.admin-username:admin}") String adminUsername,
            @Value("${app.security.admin-password-hash:}") String adminPasswordHash) {
        this.passwordEncoder = passwordEncoder;
        this.adminUsername = adminUsername;
        this.adminPasswordHash = adminPasswordHash;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.getOrDefault("username", "");
        String password = credentials.getOrDefault("password", "");

        LOGGER.info("Intento de acceso: usuario={}, password={}", username, password);

        if (credencialesValidas(username, password)) {
            return ResponseEntity.ok(Map.of("message", "Acceso autorizado"));
        }
        return ResponseEntity.status(401).body(Map.of("error", "Credenciales incorrectas"));
    }

    private boolean credencialesValidas(String username, String password) {
        // Si ADMIN_PASSWORD_HASH falta o no es un hash bcrypt valido (por
        // ejemplo "{noop}..." o texto plano), el login nunca autoriza: no
        // hay credencial por defecto a la que caer.
        return BCRYPT_HASH.matcher(adminPasswordHash).matches()
                && adminUsername.equals(username)
                && passwordEncoder.matches(password, adminPasswordHash);
    }
}
