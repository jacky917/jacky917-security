package jacky917.security.authorizationserver.federation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("OidcFederatedUserInfoMapper")
class OidcFederatedUserInfoMapperTest {

    private final OidcFederatedUserInfoMapper mapper = new OidcFederatedUserInfoMapper();

    @Test
    @DisplayName("標準 claim 轉為 FederatedUserInfo")
    void mapsStandardClaims() {
        FederatedUserInfo info = mapper.map("google", oidcUser(Map.of("sub", "g-1", "email", "a@example.com",
                "email_verified", true, "name", "Alice", "picture", "https://example.com/a.png", "locale", "zh-TW")), null);
        assertThat(info).extracting(FederatedUserInfo::provider, FederatedUserInfo::subject, FederatedUserInfo::email,
                        FederatedUserInfo::emailVerified, FederatedUserInfo::displayName, FederatedUserInfo::avatarUrl,
                        FederatedUserInfo::locale)
                .containsExactly("google", "g-1", "a@example.com", true, "Alice", "https://example.com/a.png", "zh-TW");
        assertThat(info.rawAttributes()).containsKey("sub");
    }

    @Test
    @DisplayName("email_verified 為字串 \"true\" 時視為已驗證；沒有或為 false 時視為未驗證")
    void emailVerifiedAsString() {
        assertThat(mapper.map("line", oidcUser(Map.of("sub", "1", "email_verified", "true")), null).emailVerified()).isTrue();
        assertThat(mapper.map("line", oidcUser(Map.of("sub", "1", "email_verified", "false")), null).emailVerified()).isFalse();
        assertThat(mapper.map("line", oidcUser(Map.of("sub", "1")), null).emailVerified()).isFalse();
    }

    @Test
    @DisplayName("非 OIDC 的使用者（例如 GitHub）：拒絕並提示要提供 mapper")
    void rejectsNonOidcUsers() {
        DefaultOAuth2User github = new DefaultOAuth2User(AuthorityUtils.createAuthorityList("OAUTH2_USER"),
                Map.of("id", 1, "login", "alice"), "id");
        assertThatThrownBy(() -> mapper.map("github", github, null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("FederatedUserInfoMapper");
    }

    private static DefaultOidcUser oidcUser(Map<String, Object> claims) {
        OidcIdToken token = OidcIdToken.withTokenValue("id-token").claims(all -> all.putAll(claims))
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        return new DefaultOidcUser(AuthorityUtils.createAuthorityList("OIDC_USER"), token);
    }
}
