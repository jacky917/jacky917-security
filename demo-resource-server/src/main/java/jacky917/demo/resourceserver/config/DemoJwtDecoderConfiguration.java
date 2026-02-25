package jacky917.demo.resourceserver.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

/**
 * Demo 用 JWT Decoder 設定。
 * 這裡使用 resources 內的對稱式 JWK（oct）作為本地驗證金鑰。
 */
@Configuration
public class DemoJwtDecoderConfiguration {

    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
        ClassPathResource jwkResource = new ClassPathResource("demo/jwk/demo-hs256.jwk.json");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node;
        try (InputStream inputStream = jwkResource.getInputStream()) {
            node = mapper.readTree(inputStream);
        }

        OctetSequenceKey octetKey = OctetSequenceKey.parse(node.toString());
        SecretKey secretKey = new SecretKeySpec(octetKey.toByteArray(), "HmacSHA256");

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.from(JWSAlgorithm.HS256.getName()))
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("jacky917-demo-auth-server"));
        return decoder;
    }
}

