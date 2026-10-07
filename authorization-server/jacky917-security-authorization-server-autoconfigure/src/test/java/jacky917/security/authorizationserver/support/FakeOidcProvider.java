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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 測試用的 OpenID Connect 提供者（取代 Google）：以 JDK 內建的 HttpServer 提供 token、JWKS、userinfo
 * 端點，以自己的 RSA 金鑰簽 ID Token。Spring 的 oauth2Login 會實際呼叫這些端點並驗證簽章、nonce 與 aud。
 */
public final class FakeOidcProvider {

    public static final String CLIENT_ID = "google-client";

    /**
     * Google 的 issuer：Spring 內建的 Google 設定以此驗證 ID Token 的 iss。
     */
    public static final String ISSUER = "https://accounts.google.com";

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpServer server;
    private final RSAKey key;
    private volatile Map<String, Object> user = Map.of();
    private volatile String nonce;

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
        server.createContext("/userinfo", exchange -> respond(exchange, JSON.writeValueAsString(user)));
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
     * 設定下一次登入的使用者與 Spring 在授權請求中送出的 nonce。
     */
    public void prepare(String subject, String email, boolean emailVerified, String name, String nonce) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", subject);
        if (email != null) {
            claims.put("email", email);
            claims.put("email_verified", emailVerified);
        }
        claims.put("name", name);
        claims.put("picture", "https://example.com/" + subject + ".png");
        claims.put("locale", "zh-TW");
        this.user = claims;
        this.nonce = nonce;
    }

    private void token(HttpExchange exchange) throws IOException {
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(ISSUER)
                    .audience(CLIENT_ID)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(300)))
                    .claim("nonce", nonce);
            user.forEach(claims::claim);
            SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                    claims.build());
            idToken.sign(new RSASSASigner(key));
            respond(exchange, JSON.writeValueAsString(Map.of(
                    "access_token", "provider-access-token",
                    "token_type", "Bearer",
                    "expires_in", 3600,
                    "scope", "openid profile email",
                    "id_token", idToken.serialize())));
        } catch (JOSEException ex) {
            throw new IOException(ex);
        }
    }

    private static void respond(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
