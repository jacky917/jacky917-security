package jacky917.demo.resourceserver.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Demo configuration of the JWT decoder.
 * <p>
 * Demo 用的 JWT decoder 設定。
 * <p>
 * Tokens are verified with the symmetric HS256 key in
 * {@code demo/jwk/demo-hs256.jwk.json}, which the demo authorization server
 * also uses to sign them.
 * <p>
 * 使用 {@code demo/jwk/demo-hs256.jwk.json} 中的對稱式 HS256 金鑰驗證
 * token，Demo Authorization Server 也使用同一把金鑰簽署。
 */
@Configuration
public class DemoJwtDecoderConfiguration {

    /**
     * Creates a decoder that verifies the HS256 signature, the expiration
     * time, and the issuer {@code jacky917-demo-auth-server}.
     * <p>
     * 建立驗證 HS256 簽章、到期時間與簽發者
     * {@code jacky917-demo-auth-server} 的 decoder。
     *
     * @return the configured JWT decoder
     *         <br>設定完成的 JWT decoder
     * @throws Exception if the key file cannot be read or parsed
     *         <br>若無法讀取或解析金鑰檔
     */
    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
        ClassPathResource jwkResource = new ClassPathResource("demo/jwk/demo-hs256.jwk.json");
        String jwkJson;
        try (InputStream inputStream = jwkResource.getInputStream()) {
            jwkJson = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }

        OctetSequenceKey octetKey = OctetSequenceKey.parse(jwkJson);
        SecretKey secretKey = new SecretKeySpec(octetKey.toByteArray(), "HmacSHA256");

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.from(JWSAlgorithm.HS256.getName()))
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("jacky917-demo-auth-server"));
        return decoder;
    }
}

