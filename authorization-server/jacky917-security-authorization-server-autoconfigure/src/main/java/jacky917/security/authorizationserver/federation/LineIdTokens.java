package jacky917.security.authorizationserver.federation;

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

/**
 * ID token verification for LINE Login.
 * <p>
 * LINE Login 的 ID Token 驗證。
 * <p>
 * LINE signs the ID tokens of web logins with HS256, using the channel
 * secret as the key, instead of a published public key. Spring verifies ID
 * tokens with RS256 by default, so LINE logins would always fail. A
 * registration is treated as LINE when its id is {@code line} or its issuer
 * is {@code https://access.line.me}. LINE does not report whether an email
 * is verified, so its emails are never used to match existing accounts.
 * <p>
 * LINE 以 HS256、以 channel secret 為金鑰簽署網頁登入的 ID Token，而不是公開
 * 的公鑰。Spring 預設以 RS256 驗證 ID Token，LINE 登入因此一律失敗。registration
 * id 為 {@code line}、或 issuer 為 {@code https://access.line.me} 時視為 LINE。
 * LINE 不提供 Email 是否已驗證，因此其 Email 一律不用於比對既有帳號。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class LineIdTokens {

    private static final String ISSUER = "https://access.line.me";

    private LineIdTokens() {
    }

    /**
     * Creates the ID token decoder factory used by every external login:
     * HS256 for LINE, Spring's default RS256 for the others.
     * <p>
     * 建立所有第三方登入使用的 ID Token decoder factory：LINE 使用 HS256，其餘
     * 使用 Spring 預設的 RS256。
     *
     * @return the factory
     *         <br>factory
     */
    public static OidcIdTokenDecoderFactory decoderFactory() {
        OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
        factory.setJwsAlgorithmResolver(LineIdTokens::algorithm);
        return factory;
    }

    /**
     * Returns the algorithm of a registration's ID tokens.
     * <p>
     * 回傳 registration 的 ID Token 演算法。
     *
     * @param registration  the client registration
     *                      <br>client registration
     * @return {@code HS256} for LINE, otherwise {@code RS256}
     *         <br>LINE 為 {@code HS256}，其他為 {@code RS256}
     */
    public static JwsAlgorithm algorithm(ClientRegistration registration) {
        return isLine(registration) ? MacAlgorithm.HS256 : SignatureAlgorithm.RS256;
    }

    /**
     * Returns whether a registration is LINE Login.
     * <p>
     * 回傳 registration 是否為 LINE Login。
     *
     * @param registration  the client registration
     *                      <br>client registration
     * @return {@code true} for the id {@code line} or the LINE issuer
     *         <br>id 為 {@code line} 或 issuer 為 LINE 時為 {@code true}
     */
    public static boolean isLine(ClientRegistration registration) {
        return "line".equals(registration.getRegistrationId())
                || ISSUER.equals(registration.getProviderDetails().getIssuerUri());
    }
}
