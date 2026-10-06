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
        // Encode.forHtml() inline: con HtmlUtils.htmlEscape de Spring, o con
        // el resultado asignado antes a una variable, Semgrep
        // (tainted-html-string) sigue marcando la concatenacion como tainted.
        return ResponseEntity.ok(
                "<html><body><h2>Vista previa</h2><p>" + Encode.forHtml(comment) + "</p></body></html>");
    }
}
