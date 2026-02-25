package jacky917.demo.authorizationserver.controller;

import com.nimbusds.jose.JOSEException;
import io.swagger.v3.oas.annotations.Operation;
import jacky917.demo.authorizationserver.service.JwtIssuerService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Demo Authorization Server：提供最小化的 Token 簽發端點。
 */
@RestController
@RequestMapping("/oauth2")
public class AuthController {

    private final JwtIssuerService jwtIssuerService;

    public AuthController(JwtIssuerService jwtIssuerService) {
        this.jwtIssuerService = jwtIssuerService;
    }

    @Operation(summary = "簽發測試 JWT", description = "以 demo 帳密換發 Bearer Token，供 Resource Server 測試使用。")
    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestBody TokenRequest request) throws JOSEException {
        if (!StringUtils.hasText(request.username())) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_request",
                    "message", "username 不可為空"
            ));
        }

        // Demo 用固定密碼：password，僅供本地 E2E 測試。
        if (!"password".equals(request.password())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "invalid_grant",
                    "message", "帳號或密碼錯誤"
            ));
        }

        List<String> roles = request.roles() == null || request.roles().isEmpty()
                ? List.of("A")
                : request.roles();
        List<String> permissions = request.permissions() == null || request.permissions().isEmpty()
                ? List.of("bb", "clip:read")
                : request.permissions();
        List<String> scp = request.scp() == null || request.scp().isEmpty()
                ? List.of("profile.read")
                : request.scp();
        String sid = StringUtils.hasText(request.sid()) ? request.sid() : "sid-demo-auth";
        long expires = request.expiresInSeconds() == null || request.expiresInSeconds() <= 0
                ? JwtIssuerService.DEFAULT_EXPIRES_SECONDS
                : request.expiresInSeconds();

        String accessToken = jwtIssuerService.issueAccessToken(
                request.username(),
                roles,
                permissions,
                scp,
                sid,
                expires
        );
        return ResponseEntity.ok(new TokenResponse("Bearer", accessToken, expires, JwtIssuerService.ISSUER));
    }
}

