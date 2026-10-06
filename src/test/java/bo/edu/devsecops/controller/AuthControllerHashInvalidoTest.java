package bo.edu.devsecops.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Trampa documentada en remediacion.md: si ADMIN_PASSWORD_HASH no es un hash
 * bcrypt valido (texto plano, o un prefijo tipo "{noop}..."), el login debe
 * rechazar siempre, sin caer a ninguna comparacion de texto plano.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "app.security.admin-password-hash=plaintext-no-es-un-hash-bcrypt")
class AuthControllerHashInvalidoTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void conHashNoBcryptElLoginSiempreRechazaAunqueElTextoCoincidaLiteral() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"plaintext-no-es-un-hash-bcrypt\"}"))
                .andExpect(status().isUnauthorized());
    }
}
