package bo.edu.devsecops.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final JdbcTemplate jdbcTemplate;

    public ProductController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam(defaultValue = "") String name) {
        // REGRESION INTENCIONAL (prueba del Paso 7.6): vuelve a concatenar el
        // parametro directamente en el SQL para confirmar que el pipeline
        // bloquea el merge. No fusionar este PR.
        String sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + name + "%'";
        return jdbcTemplate.queryForList(sql);
    }
}
