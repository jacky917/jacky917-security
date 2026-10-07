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
 * Demo authorization server endpoint that issues access tokens.
 * <p>
 * Demo Authorization Server 的 Token 簽發端點。
 * <p>
 * This is a minimal stand-in for a real OAuth 2.0 token endpoint and must
 * not be used in production: every user shares the fixed password
 * {@code password}, and callers choose their own roles and permissions.
 * <p>
 * 這是真正 OAuth 2.0 token 端點的最小化替代品，不可用於正式環境：所有使用者
 * 共用固定密碼 {@code password}，且呼叫端可自行指定角色與權限。
 */
@RestController
@RequestMapping("/oauth2")
public class AuthController {

    private final JwtIssuerService jwtIssuerService;

    /**
     * Creates a controller that issues tokens through the given service.
     * <p>
     * 建立透過指定服務簽發 token 的 controller。
     *
     * @param jwtIssuerService  the service that signs access tokens
     *                          <br>負責簽署 access token 的服務
     */
    public AuthController(JwtIssuerService jwtIssuerService) {
        this.jwtIssuerService = jwtIssuerService;
    }

    /**
     * Issues a signed access token for the given demo credentials.
     * <p>
     * 依指定的 demo 帳密簽發已簽署的 access token。
     * <p>
     * Missing or empty roles, permissions, and scopes fall back to
     * {@code A}, {@code bb} and {@code clip:read}, and {@code profile.read}.
     * A missing or non-positive lifetime falls back to
     * {@link JwtIssuerService#DEFAULT_EXPIRES_SECONDS}.
     * <p>
     * 未提供或為空的角色、權限與 scope，分別預設為 {@code A}、{@code bb} 與
     * {@code clip:read}、{@code profile.read}。未提供或非正數的有效秒數則使用
     * {@code JwtIssuerService.DEFAULT_EXPIRES_SECONDS}。
     *
     * @param request  the token request; {@code username} must not be blank
     *                 <br>token 申請內容，{@code username} 不可為空白
     * @return 200 with a {@link TokenResponse}; 400 if {@code username} is
     *         blank; 401 if the password is not {@code password}
     *         <br>成功時為 200 與 {@code TokenResponse}；{@code username} 為空白
     *         時為 400；密碼不是 {@code password} 時為 401
     * @throws JOSEException if the token cannot be signed
     *         <br>若無法簽署 token
     */
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

