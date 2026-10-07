package jacky917.security.authorizationserver.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 測試用的 OpenID Connect 提供者（取代 Google）：以 JDK 內建的 HttpServer 提供 token、JWKS、userinfo
 * 端點，以自己的 RSA 金鑰簽 ID Token。Spring 的 oauth2Login 會實際呼叫這些端點並驗證簽章、nonce 與 aud。
 * <p>
 * 每一次登入以 {@link #prepare} 回傳的授權碼區分（token 端點依 code、userinfo 端點依 access token 找到
 * 對應的使用者），測試之間不共用狀態；使用完畢以 {@link #close()} 關閉。
 */
public final class FakeOidcProvider implements AutoCloseable {

    public static final String CLIENT_ID = "google-client";

    /**
     * Google 的 issuer：Spring 內建的 Google 設定以此驗證 ID Token 的 iss。
     */
    public static final String ISSUER = "https://accounts.google.com";

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpServer server;
    private final RSAKey key;
    private final Map<String, Login> logins = new ConcurrentHashMap<>();

    private FakeOidcProvider() {
        try {
            key = new RSAKeyGenerator(2048).keyID("fake-key").generate();
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        } catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        }
        server.createContext("/token", this::token);
        server.createContext("/jwks", exchange -> respond(exchange, new JWKSet(key.toPublicJWK()).toString()));
        server.createContext("/userinfo", exchange -> {
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            Login login = authorization == null ? null : logins.get(authorization.substring("Bearer at-".length()));
            if (login == null) {
                exchange.sendResponseHeaders(401, -1);
                exchange.close();
                return;
            }
            respond(exchange, JSON.writeValueAsString(login.claims()));
        });
        server.start();
    }

    /**
     * 啟動提供者（埠號隨機）。
     */
    public static FakeOidcProvider start() {
        return new FakeOidcProvider();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /**
     * 登記一次登入：使用者資料與 Spring 在授權請求中送出的 nonce。回傳的授權碼用於導回 Spring。
     */
    public String prepare(String subject, String email, boolean emailVerified, String name, String nonce) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", subject);
        if (email != null) {
            claims.put("email", email);
            claims.put("email_verified", emailVerified);
        }
        claims.put("name", name);
        claims.put("picture", "https://example.com/" + subject + ".png");
        claims.put("locale", "zh-TW");
        String code = UUID.randomUUID().toString();
        logins.put(code, new Login(Map.copyOf(claims), nonce));
        return code;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void token(HttpExchange exchange) throws IOException {
        String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String code = Arrays.stream(form.split("&")).filter(pair -> pair.startsWith("code="))
                .map(pair -> URLDecoder.decode(pair.substring(5), StandardCharsets.UTF_8)).findFirst().orElse("");
        Login login = logins.get(code);
        if (login == null) {
            byte[] error = "{\"error\":\"invalid_grant\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(400, error.length);
            exchange.getResponseBody().write(error);
            exchange.close();
            return;
        }
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(ISSUER)
                    .audience(CLIENT_ID)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(300)))
                    .claim("nonce", login.nonce());
            login.claims().forEach(claims::claim);
            SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                    claims.build());
            idToken.sign(new RSASSASigner(key));
            respond(exchange, JSON.writeValueAsString(Map.of(
                    "access_token", "at-" + code,
                    "token_type", "Bearer",
                    "expires_in", 3600,
                    "scope", "openid profile email",
                    "id_token", idToken.serialize())));
        } catch (JOSEException ex) {
            throw new IOException(ex);
        }
    }

    private record Login(Map<String, Object> claims, String nonce) {
    }

    private static void respond(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
