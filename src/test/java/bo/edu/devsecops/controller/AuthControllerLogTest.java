package bo.edu.devsecops.controller;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerLogTest {

    @Autowired
    private MockMvc mockMvc;

    private ListAppender<ILoggingEvent> appender;
    private Logger authLogger;

    @BeforeEach
    void attachAppender() {
        authLogger = (Logger) LoggerFactory.getLogger(AuthController.class);
        appender = new ListAppender<>();
        appender.start();
        authLogger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        authLogger.detachAppender(appender);
    }

    @Test
    void elLogNoContieneLaContrasena() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin\",\"password\":\"Secreto-Que-No-Debe-Loguearse\"}"));

        List<String> mensajes = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertThat(mensajes).isNotEmpty();
        assertThat(mensajes).noneMatch(m -> m.contains("Secreto-Que-No-Debe-Loguearse"));
    }

    @Test
    void elLogNeutralizaCrlfEnElUsuario() throws Exception {
        // Si el username se logueara tal cual, esto inyectaria una linea de
        // log falsa ("FAKE LOG LINE") separada por un salto de linea real.
        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin\\r\\nFAKE LOG LINE\",\"password\":\"x\"}"));

        List<String> mensajes = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertThat(mensajes).isNotEmpty();
        assertThat(mensajes).noneMatch(m -> m.contains("\r") || m.contains("\n"));
    }
}
