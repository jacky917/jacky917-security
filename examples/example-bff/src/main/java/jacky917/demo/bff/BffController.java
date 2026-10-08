package jacky917.demo.bff;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.net.URI;
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
    private final BffProperties properties;

    BffController(RestClient resourceServer, BffProperties properties) {
        this.resourceServer = resourceServer;
        this.properties = properties;
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
        // 只轉送本服務的路徑：以 "//" 開頭會被解讀成另一台主機，token 就會被送到那裡
        if (!path.startsWith("/") || path.startsWith("//")) {
            return ResponseEntity.badRequest().build();
        }
        // 已編碼的路徑與 query 原樣轉送；不以 URI 樣板處理，路徑中的 "{" 不會被當成變數
        String query = request.getQueryString();
        URI target = URI.create(properties.resourceServerUrl() + path + (query == null ? "" : "?" + query));
        return resourceServer.get().uri(target).exchange((clientRequest, response) -> ResponseEntity
                .status(response.getStatusCode())
                .contentType(response.getHeaders().getContentType() == null
                        ? MediaType.APPLICATION_JSON : response.getHeaders().getContentType())
                .body(new String(response.getBody().readAllBytes(), StandardCharsets.UTF_8)));
    }
}
