package jacky917.security.authorizationserver.keys;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.List;

/**
 * The public keys published at the JWKS endpoint: {@code NEXT},
 * {@code ACTIVE}, and {@code RETIRING}.
 * <p>
 * 公開於 JWKS 端點的公鑰：{@code NEXT}、{@code ACTIVE}、{@code RETIRING}。
 * <p>
 * It never returns private keys. Tokens are signed by a separate encoder
 * that only sees the active private key; with several keys published,
 * Spring Security's encoder would otherwise refuse to choose one.
 * <p>
 * 此來源不會回傳任何私鑰。Token 由另一個只看得到目前私鑰的 encoder 簽章；
 * 否則公開多把金鑰時，Spring Security 的 encoder 會因無法選擇而拒絕簽章。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class RotatingJwkSource implements JWKSource<SecurityContext> {

    private final SigningKeyService keys;

    /**
     * Creates a source backed by the given service.
     * <p>
     * 建立以指定服務為來源的 JWK source。
     *
     * @param keys  the signing key service
     *              <br>簽章金鑰服務
     */
    public RotatingJwkSource(SigningKeyService keys) {
        this.keys = keys;
    }

    @Override
    public List<JWK> get(JWKSelector selector, SecurityContext context) {
        return selector.select(new JWKSet(keys.publishableKeys()));
    }
}
