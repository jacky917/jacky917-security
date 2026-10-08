package jacky917.security.authorizationserver.federation;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Maps any OpenID Connect provider (Google, Microsoft, LINE, ...) from the
 * standard claims of the ID token.
 * <p>
 * 以 ID Token 的標準 claim 轉換任何 OpenID Connect 提供者（Google、Microsoft、
 * LINE 等）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class OidcFederatedUserInfoMapper implements FederatedUserInfoMapper {

    /**
     * Supports every provider; non-OIDC users are rejected in
     * {@link #map}.
     * <p>
     * 支援所有提供者；非 OIDC 的使用者會在 {@link #map} 中被拒絕。
     */
    @Override
    public boolean supports(String registrationId) {
        return true;
    }

    @Override
    public FederatedUserInfo map(String registrationId, OAuth2User user, OAuth2AccessToken accessToken) {
        if (!(user instanceof OidcUser oidc)) {
            throw new IllegalArgumentException("Provider " + registrationId + " is not an OpenID Connect provider; "
                    + "add a FederatedUserInfoMapper bean for it");
        }
        // email_verified 依提供者可能是布林或字串
        boolean verified = Boolean.TRUE.equals(oidc.getEmailVerified())
                || "true".equalsIgnoreCase(String.valueOf(oidc.getClaims().get("email_verified")));
        return new FederatedUserInfo(registrationId, oidc.getSubject(), oidc.getEmail(), verified,
                oidc.getFullName(), oidc.getPicture(), oidc.getLocale(), oidc.getClaims());
    }
}
