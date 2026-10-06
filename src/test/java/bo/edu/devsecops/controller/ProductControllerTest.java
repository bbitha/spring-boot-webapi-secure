package bo.edu.devsecops.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ProductControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void searchDevuelveCoincidenciasReales() throws Exception {
        mockMvc.perform(get("/api/products/search").param("name", "Laptop"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].NAME").value("Laptop"));
    }

    @Test
    void searchNoPermiteInyeccionSql() throws Exception {
        // REGRESION INTENCIONAL (Paso 7.6): se revierte temporalmente junto
        // con ProductController para que Build & Test siga en verde y la
        // regresion quede aislada a los escaneres de seguridad (Semgrep
        // lab-java-sql-concatenation + CodeQL). No fusionar este PR.
        mockMvc.perform(get("/api/products/search").param("name", "' OR '1'='1"))
                .andExpect(status().isOk());
    }
}
