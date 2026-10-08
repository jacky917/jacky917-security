package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.FakeGitHub;
import jacky917.security.authorizationserver.support.FakeOidcProvider;
import jacky917.security.authorizationserver.support.TestDatabases;
import jacky917.security.authorizationserver.user.NewUser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * GitHub（OAuth 2.0，以 {@code /user/emails} 取得主要且已驗證的 Email）與 LINE（ID Token 以 channel secret 簽
 * HS256、沒有 email_verified）。兩者的處理與資料庫無關，只在 SQLite 上執行。
 */
@DisplayName("GitHub 與 LINE 登入整合測試（SQLite）")
@TestPropertySource(properties = {
        "spring.security.oauth2.client.registration.github.client-id=gh-client",
        "spring.security.oauth2.client.registration.github.client-secret=gh-secret",
        "spring.security.oauth2.client.registration.github.scope=read:user,user:email",
        "spring.security.oauth2.client.registration.line.client-name=LINE",
        "spring.security.oauth2.client.registration.line.client-id=line-client",
        "spring.security.oauth2.client.registration.line.client-secret=" + ExternalProvidersIntegrationTest.LINE_SECRET,
        "spring.security.oauth2.client.registration.line.scope=openid,profile,email",
        "spring.security.oauth2.client.registration.line.authorization-grant-type=authorization_code",
        "spring.security.oauth2.client.registration.line.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
        "spring.security.oauth2.client.provider.line.user-name-attribute=sub"
})
class ExternalProvidersIntegrationTest extends AbstractGoogleIntegrationTest {

    static final String LINE_SECRET = "0123456789abcdef0123456789abcdef";

    private static final AtomicLong GITHUB_IDS = new AtomicLong(1000);
    private static FakeGitHub GITHUB;
    private static FakeOidcProvider LINE;

    @BeforeAll
    static void startProviders() {
        GITHUB = FakeGitHub.start();
        LINE = FakeOidcProvider.startLine("line-client", LINE_SECRET);
    }

    @AfterAll
    static void stopProviders() {
        GITHUB.close();
        LINE.close();
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String url = TestDatabases.newDatabaseUrl(TestDatabases.SQLITE);
        registry.add("spring.datasource.url", () -> url);
        provider(registry);
        registry.add("spring.security.oauth2.client.provider.github.authorization-uri",
                () -> GITHUB.baseUrl() + "/login/oauth/authorize");
        registry.add("spring.security.oauth2.client.provider.github.token-uri",
                () -> GITHUB.baseUrl() + "/login/oauth/access_token");
        registry.add("spring.security.oauth2.client.provider.github.user-info-uri", () -> GITHUB.baseUrl() + "/user");
        registry.add("spring.security.oauth2.client.provider.line.authorization-uri", () -> LINE.baseUrl() + "/authorize");
        registry.add("spring.security.oauth2.client.provider.line.token-uri", () -> LINE.baseUrl() + "/token");
        registry.add("spring.security.oauth2.client.provider.line.user-info-uri", () -> LINE.baseUrl() + "/userinfo");
        registry.add("spring.security.oauth2.client.provider.line.jwk-set-uri", () -> LINE.baseUrl() + "/jwks");
    }

    @Test
    @DisplayName("GitHub：subject 為數字 id；Email 取自主要且已驗證的地址（公開 Email 不採信）")
    void gitHubUsesThePrimaryVerifiedEmail() throws Exception {
        long id = GITHUB_IDS.incrementAndGet();
        String email = "octo-" + id + "@example.com";
        Flow flow = startFlow();
        String location = gitHubCallback(flow.session, id, "octo" + id, List.of(
                Map.of("email", "old-" + id + "@example.com", "primary", false, "verified", true),
                Map.of("email", email, "primary", true, "verified", true)));
        assertThat(location).startsWith("http://localhost/oauth2/authorize");
        Map<String, Object> user = jdbc.sql("SELECT u.email, u.email_verified, u.display_name, f.provider_subject "
                + "FROM app_user u JOIN user_federated_identity f ON f.user_id = u.id WHERE f.provider = 'github' "
                + "AND f.provider_subject = :id").param("id", String.valueOf(id)).query().singleRow();
        assertThat(user).containsEntry("email", email).containsEntry("display_name", "Octo " + id);
        assertThat(user.get("email_verified")).isIn(true, 1);
    }

    @Test
    @DisplayName("GitHub 沒有 user:email 權限（/user/emails 回 403）：仍可登入，但沒有 Email")
    void gitHubWithoutEmailScope() throws Exception {
        long id = GITHUB_IDS.incrementAndGet();
        Flow flow = startFlow();
        assertThat(gitHubCallback(flow.session, id, "noemail" + id, null)).startsWith("http://localhost/oauth2/authorize");
        assertThat(jdbc.sql("SELECT u.email FROM app_user u JOIN user_federated_identity f ON f.user_id = u.id "
                        + "WHERE f.provider = 'github' AND f.provider_subject = :id").param("id", String.valueOf(id))
                .query(String.class).optional()).as("公開的 Email 不採信").isEmpty();
    }

    @Test
    @DisplayName("GitHub 的已驗證 Email 屬於既有帳號：導向連結確認頁")
    void gitHubEmailOfExistingAccount() throws Exception {
        long id = GITHUB_IDS.incrementAndGet();
        String email = "taken-" + id + "@example.com";
        users.createUser(new NewUser(null, email, true, "correct horse battery", null, Set.of()));
        Flow flow = startFlow();
        assertThat(gitHubCallback(flow.session, id, "taken" + id,
                List.of(Map.of("email", email, "primary", true, "verified", true)))).isEqualTo("/jacky917/link-account");
    }

    @Test
    @DisplayName("LINE：以 channel secret 驗證 HS256 的 ID Token；沒有 email_verified，因此不儲存 Email")
    void lineVerifiesHs256IdTokens() throws Exception {
        String subject = "U" + UUID.randomUUID().toString().replace("-", "");
        Flow flow = startFlow();
        String location = providerCallback(LINE, flow.session, "line", subject, subject + "@line.example.com", true,
                "LINE User");
        assertThat(location).startsWith("http://localhost/oauth2/authorize");
        Map<String, Object> user = jdbc.sql("SELECT u.email, u.display_name, f.email_verified FROM app_user u "
                        + "JOIN user_federated_identity f ON f.user_id = u.id WHERE f.provider = 'line' "
                        + "AND f.provider_subject = :s").param("s", subject).query().singleRow();
        assertThat(user).containsEntry("email", null).containsEntry("display_name", "LINE User");
        assertThat(user.get("email_verified")).isIn(false, 0);
    }

    @Test
    @DisplayName("登入頁同時顯示 Google、GitHub、LINE")
    void loginPageShowsEveryProvider() throws Exception {
        String page = mockMvc.perform(get("/login").header(HttpHeaders.ACCEPT_LANGUAGE, "en"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("/oauth2/authorization/github").contains("/oauth2/authorization/line")
                .contains("/oauth2/authorization/google");
    }

    private String gitHubCallback(MockHttpSession session, long id, String login, List<Map<String, Object>> emails)
            throws Exception {
        String toGitHub = mockMvc.perform(get("/oauth2/authorization/github").session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(toGitHub).startsWith(GITHUB.baseUrl());
        String state = URLDecoder.decode(UriComponentsBuilder.fromUriString(toGitHub).build().getQueryParams()
                .getFirst("state"), StandardCharsets.UTF_8);
        String code = GITHUB.prepare(id, login, "Octo " + id, emails);
        URI callback = UriComponentsBuilder.fromPath("/login/oauth2/code/github")
                .queryParam("code", code).queryParam("state", state).encode().build().toUri();
        return mockMvc.perform(get(callback).session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }
}
