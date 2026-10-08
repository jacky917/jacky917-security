package jacky917.security.authorizationserver.keys;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Signs every token with the active signing key, using that key's
 * algorithm.
 * <p>
 * 以目前的簽章金鑰簽發所有 token，並使用該金鑰的演算法。
 * <p>
 * Spring Authorization Server always asks for {@code RS256} for access
 * tokens, and for the client's configured algorithm for ID tokens. When the
 * active key is an {@code ES256} key, or the algorithm setting changed
 * while an older key is still active, the requested algorithm does not
 * match the key and signing would fail. The header's algorithm is therefore
 * replaced with the active key's before signing; resource servers read the
 * algorithm from the token and the JWKS.
 * <p>
 * Spring Authorization Server 對 Access Token 一律要求 {@code RS256}，對 ID Token
 * 則使用 client 設定的演算法。目前的金鑰為 {@code ES256}，或演算法設定改變但
 * 舊金鑰仍在使用時，要求的演算法與金鑰不符，簽章會失敗。因此簽章前把標頭的
 * 演算法換成目前金鑰的演算法；Resource Server 依 token 與 JWKS 判斷演算法。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ActiveKeyJwtEncoder implements JwtEncoder {

    private final SigningKeyService keys;

    /**
     * Creates the encoder.
     * <p>
     * 建立 encoder。
     *
     * @param keys  the signing key service
     *              <br>簽章金鑰服務
     */
    public ActiveKeyJwtEncoder(SigningKeyService keys) {
        this.keys = keys;
    }

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        JWK active = keys.activeSigningKey();
        SignatureAlgorithm algorithm = SignatureAlgorithm.from(active.getAlgorithm().getName());
        JwsHeader requested = parameters.getJwsHeader();
        JwsHeader header = requested == null
                ? JwsHeader.with(algorithm).build()
                : JwsHeader.from(requested).algorithm(algorithm).build();
        NimbusJwtEncoder encoder = new NimbusJwtEncoder((selector, context) -> selector.select(new JWKSet(active)));
        return encoder.encode(JwtEncoderParameters.from(header, parameters.getClaims()));
    }
}
