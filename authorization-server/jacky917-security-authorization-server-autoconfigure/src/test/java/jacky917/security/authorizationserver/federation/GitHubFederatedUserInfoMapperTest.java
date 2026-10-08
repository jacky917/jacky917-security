package jacky917.security.authorizationserver.federation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link GitHubFederatedUserInfoMapper} 不需要 HTTP 的分支：支援哪些 registration、缺少 id、沒有 access token。
 * 讀取 {@code /user/emails} 的部分由 ExternalProvidersIntegrationTest 以假的 GitHub 測試。
 */
@DisplayName("GitHubFederatedUserInfoMapper")
class GitHubFederatedUserInfoMapperTest {

    private final GitHubFederatedUserInfoMapper mapper = new GitHubFederatedUserInfoMapper(
            new InMemoryClientRegistrationRepository(
                    CommonOAuth2Provider.GITHUB.getBuilder("github").clientId("a").clientSecret("b").build(),
                    CommonOAuth2Provider.GITHUB.getBuilder("github-work").clientId("a").clientSecret("b").build(),
                    CommonOAuth2Provider.GOOGLE.getBuilder("google").clientId("a").clientSecret("b").build()));

    @Test
    @DisplayName("支援 github 與使用者資訊端點在 api.github.com 的 registration；不支援 Google 與不存在的 registration")
    void supports() {
        assertThat(mapper.supports("github")).isTrue();
        assertThat(mapper.supports("github-work")).isTrue();
        assertThat(mapper.supports("google")).isFalse();
        assertThat(mapper.supports("unknown")).isFalse();
        assertThat(new GitHubFederatedUserInfoMapper(null).supports("github")).isFalse();
    }

    @Test
    @DisplayName("沒有 access token：subject 為數字 id、名稱沒有時用 login、沒有 Email")
    void mapsWithoutEmails() {
        FederatedUserInfo info = mapper.map("github", user(Map.of("id", 42, "login", "octo",
                "avatar_url", "https://avatars.example.com/42", "email", "octo@public.example.com")), null);
        assertThat(info.subject()).isEqualTo("42");
        assertThat(info.displayName()).isEqualTo("octo");
        assertThat(info.email()).as("公開的 Email 不採信").isNull();
        assertThat(info.emailVerified()).isFalse();
        assertThat(info.avatarUrl()).isEqualTo("https://avatars.example.com/42");
    }

    @Test
    @DisplayName("沒有 id：拒絕")
    void missingId() {
        assertThatThrownBy(() -> mapper.map("github", user(Map.of("login", "octo")), null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static DefaultOAuth2User user(Map<String, Object> attributes) {
        return new DefaultOAuth2User(AuthorityUtils.createAuthorityList("OAUTH2_USER"), attributes, "login");
    }
}
