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
        // Contra el codigo vulnerable, este payload rompe la clausula LIKE y
        // devuelve los 3 productos de data.sql sin filtrar por nombre.
        // Parametrizada, el mismo texto se trata como literal y no matchea nada.
        mockMvc.perform(get("/api/products/search").param("name", "' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$").isEmpty());
    }
}
