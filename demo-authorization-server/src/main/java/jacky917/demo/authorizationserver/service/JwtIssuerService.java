package jacky917.demo.authorizationserver.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Demo JWT 簽發服務。
 */
@Service
public class JwtIssuerService {

    public static final String ISSUER = "jacky917-demo-auth-server";
    public static final String AUDIENCE = "demo-resource-server";
    public static final long DEFAULT_EXPIRES_SECONDS = 600L;

    private OctetSequenceKey signingKey;

    @PostConstruct
    void init() throws Exception {
        ClassPathResource resource = new ClassPathResource("demo/jwk/demo-hs256.jwk.json");
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream inputStream = resource.getInputStream()) {
            JsonNode node = mapper.readTree(inputStream);
            this.signingKey = OctetSequenceKey.parse(node.toString());
        }
    }

    /**
     * 產生 Access Token。
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

