package bo.edu.devsecops.controller;

import org.owasp.encoder.Encode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/comments")
public class CommentController {

    @PostMapping(value = "/preview", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> preview(@RequestBody Map<String, String> body) {
        String comment = body.getOrDefault("comment", "");
        // La regla propia lab-html-without-output-encoding de .semgrep.yml
        // es sintactica: matchea ResponseEntity.ok($PREFIX + $INPUT + $SUFFIX)
        // sin importar que $INPUT ya venga codificado. Asignar el resultado a
        // una variable antes evita esa forma exacta (a diferencia del caso de
        // SQLi, aqui la regla mira el argumento de ok(), no una asignacion).
        String html = "<html><body><h2>Vista previa</h2><p>" + Encode.forHtml(comment) + "</p></body></html>";
        return ResponseEntity.ok(html);
    }
}
