package jacky917.demo.authorizationserver.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Service that signs demo JWT access tokens with a shared HS256 key.
 * <p>
 * 以共用 HS256 金鑰簽署 demo JWT access token 的服務。
 * <p>
 * The key is loaded from {@code demo/jwk/demo-hs256.jwk.json} on the
 * classpath. The resource server must hold the same key.
 * <p>
 * 金鑰從 classpath 上的 {@code demo/jwk/demo-hs256.jwk.json} 載入。資源伺服器
 * 必須持有相同的金鑰。
 */
@Service
public class JwtIssuerService {

    /**
     * The issuer ({@code iss}) written into every token.
     * <p>
     * 寫入每個 token 的簽發者（{@code iss}）。
     */
    public static final String ISSUER = "jacky917-demo-auth-server";
    /**
     * The audience ({@code aud}) written into every token.
     * <p>
     * 寫入每個 token 的受眾（{@code aud}）。
     */
    public static final String AUDIENCE = "demo-resource-server";
    /**
     * The default token lifetime in seconds.
     * <p>
     * 預設的 token 有效秒數。
     */
    public static final long DEFAULT_EXPIRES_SECONDS = 600L;

    private OctetSequenceKey signingKey;

    @PostConstruct
    void init() throws Exception {
        ClassPathResource resource = new ClassPathResource("demo/jwk/demo-hs256.jwk.json");
        try (InputStream inputStream = resource.getInputStream()) {
            this.signingKey = OctetSequenceKey.parse(new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /**
     * Issues a signed HS256 access token with the given claims.
     * <p>
     * 以指定的 claims 簽發 HS256 access token。
     * <p>
     * The token also carries the fixed issuer and audience, the issue and
     * expiration times, and a random {@code jti}.
     * <p>
     * token 另外包含固定的簽發者與受眾、簽發與到期時間，以及隨機的
     * {@code jti}。
     *
     * @param username          the subject ({@code sub})
     *                          <br>主體（{@code sub}）
     * @param roles             the values of the {@code roles} claim
     *                          <br>{@code roles} claim 的值
     * @param permissions       the values of the {@code permissions} claim
     *                          <br>{@code permissions} claim 的值
     * @param scp               the values of the {@code scp} claim
     *                          <br>{@code scp} claim 的值
     * @param sid               the value of the {@code sid} claim
     *                          <br>{@code sid} claim 的值
     * @param expiresInSeconds  the token lifetime in seconds; should be
     *                          positive
     *                          <br>token 有效秒數，應為正數
     * @return the serialized JWT in compact form
     *         <br>以 compact 格式序列化的 JWT
     * @throws JOSEException if the token cannot be signed
     *         <br>若無法簽署 token
     */
    public String issueAccessToken(
            String username,
            List<String> roles,
            List<String> permissions,
            List<String> scp,
            String sid,
            long expiresInSeconds
    ) throws JOSEException {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(expiresInSeconds);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim("sid", sid)
                .claim("roles", roles)
                .claim("permissions", permissions)
                .claim("scp", scp)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .type(JOSEObjectType.JWT)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claims
        );
        signedJWT.sign(new MACSigner(signingKey.toByteArray()));
        return signedJWT.serialize();
    }
}

