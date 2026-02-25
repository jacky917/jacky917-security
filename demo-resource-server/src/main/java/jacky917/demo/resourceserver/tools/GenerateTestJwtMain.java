package jacky917.demo.resourceserver.tools;

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

import java.io.InputStream;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 本地產生測試 JWT 的 CLI 工具。
 *
 * <p>範例：</p>
 * <pre>
 * mvn -pl demo-resource-server -q exec:java \
 *   -Dexec.mainClass=jacky917.demo.resourceserver.tools.GenerateTestJwtMain \
 *   -Dexec.args="--sub=alice --roles=A --perms=bb,clip:read --scope=profile.read --minutes=30"
 * </pre>
 */
public class GenerateTestJwtMain {

    public static void main(String[] args) throws Exception {
        Map<String, String> cli = parseArgs(args);
        String sub = cli.getOrDefault("sub", "demo-user");
        String rolesArg = cli.getOrDefault("roles", "A");
        String permsArg = cli.getOrDefault("perms", "bb,clip:read");
        String scope = cli.getOrDefault("scope", "profile.read");
        String issuer = cli.getOrDefault("issuer", "jacky917-demo-auth-server");
        String audience = cli.getOrDefault("aud", "demo-resource-server");
        String sid = cli.getOrDefault("sid", "sid-demo");
        long minutes = Long.parseLong(cli.getOrDefault("minutes", "30"));
        if (minutes <= 0) {
            minutes = 30;
        }

        OctetSequenceKey key = loadJwk();
        String token = generateToken(key, sub, rolesArg, permsArg, scope, issuer, audience, sid, minutes);

        System.out.println("=== 測試 JWT ===");
        System.out.println(token);
        System.out.println();
        System.out.println("=== 快速使用 ===");
        System.out.println("export TOKEN=\"" + token + "\"");
    }

    private static String generateToken(
            OctetSequenceKey key,
            String sub,
            String rolesArg,
            String permsArg,
            String scope,
            String issuer,
            String audience,
            String sid,
            long minutes
    ) throws JOSEException {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(minutes * 60);

        List<String> roles = splitByComma(rolesArg);
        List<String> perms = splitByComma(permsArg);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(sub)
                .issuer(issuer)
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .jwtID("jti-" + now.toEpochMilli())
                .claim("sid", sid)
                .claim("roles", roles)
                .claim("permissions", perms)
                .claim("scope", scope)
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .type(JOSEObjectType.JWT)
                        .keyID(key.getKeyID())
                        .build(),
                claims
        );
        jwt.sign(new MACSigner(key.toByteArray()));
        return jwt.serialize();
    }

    private static OctetSequenceKey loadJwk() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream inputStream = GenerateTestJwtMain.class
                .getClassLoader()
                .getResourceAsStream("demo/jwk/demo-hs256.jwk.json")) {
            if (inputStream == null) {
                throw new IllegalStateException("找不到 JWK 檔案：demo/jwk/demo-hs256.jwk.json");
            }
            JsonNode node = mapper.readTree(inputStream);
            return OctetSequenceKey.parse(node.toString());
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> parsed = new LinkedHashMap<>();
        for (String arg : args) {
            if (!arg.startsWith("--") || !arg.contains("=")) {
                continue;
            }
            int idx = arg.indexOf('=');
            parsed.put(arg.substring(2, idx), arg.substring(idx + 1));
        }
        return parsed;
    }

    private static List<String> splitByComma(String source) {
        return Arrays.stream(source.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }
}

