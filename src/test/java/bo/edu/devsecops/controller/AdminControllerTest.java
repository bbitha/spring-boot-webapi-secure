package bo.edu.devsecops.controller;

import bo.edu.devsecops.TestCredentials;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void sinCredencialesDevuelve401() throws Exception {
        mockMvc.perform(get("/api/admin/users/1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void credencialesInvalidasDevuelven401() throws Exception {
        mockMvc.perform(get("/api/admin/users/1")
                        .with(httpBasic(TestCredentials.ADMIN_USERNAME, "contrasena-incorrecta")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminAutenticadoPuedeConsultarUsuarios() throws Exception {
        mockMvc.perform(get("/api/admin/users/1")
                        .with(httpBasic(TestCredentials.ADMIN_USERNAME, TestCredentials.ADMIN_PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.USERNAME").value("admin"));
    }
}
