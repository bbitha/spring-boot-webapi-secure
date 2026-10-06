package bo.edu.devsecops.controller;

import bo.edu.devsecops.TestCredentials;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CommentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void previewCodificaElHtmlDelComentario() throws Exception {
        // Contra el codigo vulnerable, este mismo comentario volvia intacto
        // en el HTML de la respuesta (XSS reflejado).
        mockMvc.perform(post("/api/comments/preview")
                        .with(csrf())
                        .with(httpBasic(TestCredentials.ADMIN_USERNAME, TestCredentials.ADMIN_PASSWORD))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"<script>alert(1)</script>\"}"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("<script>"))))
                .andExpect(content().string(containsString("&lt;script&gt;")))
                .andExpect(header().string("Content-Security-Policy", notNullValue()))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }

    @Test
    void previewSinAutenticarseDevuelve401() throws Exception {
        mockMvc.perform(post("/api/comments/preview")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"comment\":\"hola\"}"))
                .andExpect(status().isUnauthorized());
    }
}
