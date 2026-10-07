package jacky917.demo.bff;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The BFF API for the page: who is signed in, and a proxy to the resource
 * server.
 * <p>
 * 提供給頁面的 BFF API：目前登入者，以及轉送到 Resource Server 的代理。
 */
@RestController
class BffController {

    private final RestClient resourceServer;

    BffController(RestClient resourceServer) {
        this.resourceServer = resourceServer;
    }

    /**
     * Returns the signed-in user from the ID token.
     * <p>
     * 從 ID Token 回傳目前登入的使用者。
     */
    @GetMapping("/me")
    Map<String, Object> me(@AuthenticationPrincipal OidcUser user) {
        Map<String, Object> me = new LinkedHashMap<>();
        me.put("sub", user.getSubject());
        me.put("name", user.getFullName());
        me.put("email", user.getEmail());
        return me;
    }

    /**
     * Forwards {@code GET /api/**} to the resource server with the user's
     * access token and returns its status and body unchanged.
     * <p>
     * 將 {@code GET /api/**} 以使用者的 Access Token 轉送到 Resource Server，
     * 原樣回傳其狀態碼與內容。
     */
    @GetMapping("/api/**")
    ResponseEntity<String> proxy(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length() + "/api".length());
        return resourceServer.get().uri(path).exchange((clientRequest, response) -> ResponseEntity
                .status(response.getStatusCode())
                .contentType(response.getHeaders().getContentType() == null
                        ? MediaType.APPLICATION_JSON : response.getHeaders().getContentType())
                .body(new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }
}
