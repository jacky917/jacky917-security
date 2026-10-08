package jacky917.security.authorizationserver.keys;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link ActiveKeyJwtEncoder}：不論要求的演算法為何，一律以目前金鑰的演算法簽章。
 */
@DisplayName("ActiveKeyJwtEncoder")
class ActiveKeyJwtEncoderTest {

    @Test
    @DisplayName("Spring 要求 RS256、目前金鑰為 ES256：以 ES256 簽章，header 帶 kid，可用公鑰驗證")
    void usesTheActiveKeysAlgorithm() throws Exception {
        JWK es256 = new ECKeyGenerator(Curve.P_256).keyID("ec-1").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
        Jwt jwt = encode(es256, SignatureAlgorithm.RS256);
        assertThat(jwt.getHeaders()).containsEntry("alg", SignatureAlgorithm.ES256).containsEntry("kid", "ec-1");
        assertThat(verify(es256, jwt, SignatureAlgorithm.ES256).getSubject()).isEqualTo("user-1");
    }

    @Test
    @DisplayName("演算法設定已改為 ES256、但目前仍是 RS256 的舊金鑰：以 RS256 簽章")
    void followsTheKeyNotTheSetting() throws Exception {
        JWK rs256 = new RSAKeyGenerator(2048).keyID("rsa-1").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).generate();
        Jwt jwt = encode(rs256, SignatureAlgorithm.ES256);
        assertThat(jwt.getHeaders()).containsEntry("alg", SignatureAlgorithm.RS256).containsEntry("kid", "rsa-1");
        assertThat(verify(rs256, jwt, SignatureAlgorithm.RS256).getSubject()).isEqualTo("user-1");
    }

    private static Jwt encode(JWK active, SignatureAlgorithm requested) {
        SigningKeyService keys = mock(SigningKeyService.class);
        when(keys.activeSigningKey()).thenReturn(active);
        return new ActiveKeyJwtEncoder(keys).encode(JwtEncoderParameters.from(
                JwsHeader.with(requested).build(), JwtClaimsSet.builder().subject("user-1").build()));
    }

    private static Jwt verify(JWK key, Jwt jwt, SignatureAlgorithm algorithm) {
        return NimbusJwtDecoder.withJwkSource(new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK())))
                .jwsAlgorithm(algorithm).build().decode(jwt.getTokenValue());
    }
}
