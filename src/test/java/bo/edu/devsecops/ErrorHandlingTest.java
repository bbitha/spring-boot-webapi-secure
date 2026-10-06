package bo.edu.devsecops;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

/**
 * La pagina de error de Spring Boot solo se ejerce con un servidor real:
 * MockMvc no la atraviesa (ver remediacion.md).
 */
@SpringBootTest(webEnvironment = RANDOM_PORT)
@ActiveProfiles("test")
class ErrorHandlingTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void unErrorNoIncluyeStacktraceNiMensajeDetallado() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, "application/json");

        // Id inexistente: EmptyResultDataAccessException sin manejar ->
        // pagina de error por defecto de Spring Boot.
        ResponseEntity<String> response = restTemplate
                .withBasicAuth(TestCredentials.ADMIN_USERNAME, TestCredentials.ADMIN_PASSWORD)
                .exchange("/api/admin/users/999999", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode().is5xxServerError()).isTrue();
        assertThat(response.getBody()).doesNotContain("\"trace\"");
        assertThat(response.getBody()).doesNotContain("EmptyResultDataAccessException");
    }
}
