package bo.edu.devsecops.controller;

import bo.edu.devsecops.TestCredentials;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void loginConCredencialesCorrectasNoDevuelveNingunSecreto() throws Exception {
        // Contra el codigo vulnerable, una respuesta 200 aqui incluia
        // "token": JWT_SECRET en el cuerpo. Ahora solo confirma el acceso.
        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}"""
                                .formatted(TestCredentials.ADMIN_USERNAME, TestCredentials.ADMIN_PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").doesNotExist())
                .andExpect(jsonPath("$.message").value("Acceso autorizado"));
    }

    @Test
    void loginConPasswordIncorrectaDevuelve401() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"otra-cosa"}"""
                                .formatted(TestCredentials.ADMIN_USERNAME)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginSinTokenCsrfEsRechazado() throws Exception {
        // Antes de habilitar CSRF, este mismo POST (sin token) era aceptado.
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}"""
                                .formatted(TestCredentials.ADMIN_USERNAME, TestCredentials.ADMIN_PASSWORD)))
                .andExpect(status().isForbidden());
    }
}
