package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.support.TestDatabases;
import jacky917.security.authorizationserver.token.TokenClaimsContributor;
import jacky917.security.authorizationserver.user.NewUser;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.support.MutableClock;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
/**
 * 授權流程整合測試的共用設定與工具：以 MockMvc 模擬瀏覽器與 BFF（授權請求 → 登入頁 → 登入 → 授權碼 →
 * 以 PKCE 換 Token）。子類別以 {@code @DynamicPropertySource} 指定資料庫（SQLite 或 PostgreSQL）。
 */
@SpringBootTest(classes = AbstractFlowIntegrationTest.TestApplication.class, properties = {
        "jacky917.security.authorization-server.issuer=http://localhost:9000",
        "jacky917.security.authorization-server.keys.encryption-key=" + TestDatabases.TEST_ENCRYPTION_KEY,
        "jacky917.security.authorization-server.bootstrap-admin.username=admin",
        "jacky917.security.authorization-server.bootstrap-admin.password=" + AbstractFlowIntegrationTest.PASSWORD,
        "jacky917.security.authorization-server.clients.web-bff.secret=bff-secret",
        "jacky917.security.authorization-server.clients.web-bff.redirect-uris=" + AbstractFlowIntegrationTest.REDIRECT_URI,
        "jacky917.security.authorization-server.clients.web-bff.scopes=openid,profile",
        "jacky917.security.authorization-server.clients.web-bff.post-logout-redirect-uris=" + AbstractFlowIntegrationTest.LOGGED_OUT_URI,
        "jacky917.security.authorization-server.clients.report-batch.secret=batch-secret",
        "jacky917.security.authorization-server.clients.report-batch.grant-types=client_credentials",
        "jacky917.security.authorization-server.clients.report-batch.scopes=report.generate",
        "jacky917.security.authorization-server.clients.suspended.secret=suspended-secret",
        "jacky917.security.authorization-server.clients.suspended.grant-types=client_credentials",
        "jacky917.security.authorization-server.clients.suspended.scopes=report.generate"
})
@AutoConfigureMockMvc
abstract class AbstractFlowIntegrationTest {

    static final String PASSWORD = "correct horse battery";

    static final String REDIRECT_URI = "https://app.example.com/login/oauth2/code/jacky917";

    static final String LOGGED_OUT_URI = "https://app.example.com/logged-out";

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");

    static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    MockMvc mockMvc;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    JwtDecoder jwtDecoder;

    @Autowired
    RegisteredClientRepository clients;

    @Autowired
    OAuth2AuthorizationService authorizations;

    @Autowired
    UserAccountService users;

    @Autowired
    MutableClock clock;

    @AfterEach
    void resetClock() {
        clock.reset();
    }

    void assertSession(String asid, String status, String reason) {
        Map<String, Object> row = jdbc.sql("SELECT status, revoke_reason FROM auth_session WHERE session_id = :id")
                .param("id", asid).query().singleRow();
        assertThat(row.get("status")).isEqualTo(status);
        assertThat(row.get("revoke_reason")).isEqualTo(reason);
    }

    int authorizationCount(String asid) {
        return jdbc.sql("SELECT COUNT(*) FROM session_authorization WHERE session_id = :id").param("id", asid)
                .query(Integer.class).single();
    }

    JsonNode refresh(LoggedIn result) throws Exception {
        return refresh(result.tokens().get("refresh_token").asString());
    }

    JsonNode refresh(String refreshToken) throws Exception {
        return tokenRequest(mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                .param("grant_type", "refresh_token").param("refresh_token", refreshToken)));
    }

    void assertRefreshRefused(LoggedIn result) throws Exception {
        assertRefreshRefused(result.tokens().get("refresh_token").asString());
    }

    void assertRefreshRefused(String refreshToken) throws Exception {
        String body = mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isBadRequest()).andReturn().getResponse().getContentAsString();
        assertThat(body).contains("invalid_grant");
    }

    String createUser(String username, String displayName, String... roles) {
        return users.createUser(new NewUser(username, null, false, PASSWORD, displayName, java.util.Set.of(roles))).id();
    }

    /**
     * 模擬瀏覽器：授權請求 → 登入頁 → 登入 → 授權碼；再模擬 BFF 以授權碼換 Token。
     */
    LoggedIn logInAndExchangeCode(String username) throws Exception {
        return logInAndExchangeCode(username, new MockHttpSession());
    }

    /**
     * 以指定的瀏覽器 Session 登入（可模擬同一個瀏覽器再次登入）。
     */
    LoggedIn logInAndExchangeCode(String username, MockHttpSession browser) throws Exception {
        String verifier = randomVerifier();
        MockHttpSession session = browser;

        // 1. 未登入的瀏覽器發出授權請求 → 導向登入頁
        MvcResult toLogin = mockMvc.perform(get(authorizeUrl(challenge(verifier))).session(session).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login")).andReturn();
        // 舊的瀏覽器 Session 可能已被結束（登入 Session 失效時）：與瀏覽器一樣改用新的 Session Cookie
        session = (MockHttpSession) toLogin.getRequest().getSession();

        // 2. 登入頁有表單與 CSRF token；3. 送出帳密 → 回到原本的授權請求
        String csrf = csrfToken(session);
        MvcResult login = mockMvc.perform(post("/login").session(session)
                        .param("username", username).param("password", PASSWORD).param("_csrf", csrf))
                .andExpect(status().is3xxRedirection()).andReturn();
        String savedRequest = login.getResponse().getRedirectedUrl();
        assertThat(savedRequest).startsWith("http://localhost/oauth2/authorize");
        String asid = (String) session.getAttribute(AuthSessionService.SESSION_ATTRIBUTE);
        assertThat(asid).isNotNull();

        // 4. 已登入 → 授權碼導回 client（以 URI 傳入：字串會被當成 URI 樣板再編碼一次）
        MvcResult code = mockMvc.perform(get(URI.create(savedRequest)).session(session))
                .andExpect(status().is3xxRedirection()).andReturn();
        Map<String, String> callback = UriComponentsBuilder.fromUriString(code.getResponse().getRedirectedUrl())
                .build().getQueryParams().toSingleValueMap();
        assertThat(code.getResponse().getRedirectedUrl()).startsWith(REDIRECT_URI);
        assertThat(callback).containsEntry("state", "state-123").containsKey("code");

        // 5. BFF 以授權碼與 code_verifier 換 Token
        JsonNode tokens = tokenRequest(mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                .param("grant_type", "authorization_code")
                .param("code", callback.get("code"))
                .param("redirect_uri", REDIRECT_URI)
                .param("code_verifier", verifier)));
        String userId = jdbc.sql("SELECT id FROM app_user WHERE username = :username").param("username", username)
                .query(String.class).single();
        return new LoggedIn(userId, asid, tokens, session);
    }

    record LoggedIn(String userId, String asid, JsonNode tokens, MockHttpSession browser) {
    }

    JsonNode tokenRequest(org.springframework.test.web.servlet.ResultActions actions) throws Exception {
        return JSON.readTree(actions.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    String csrfToken(MockHttpSession session) throws Exception {
        String page = mockMvc.perform(get("/login").session(session))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        Matcher matcher = CSRF.matcher(page);
        assertThat(matcher.find()).as("登入頁必須有 CSRF 欄位").isTrue();
        return matcher.group(1);
    }

    static URI authorizeUrl(String challenge) {
        return UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", "web-bff")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid profile")
                .queryParam("state", "state-123")
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .encode().build().toUri();
    }

    static String randomVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {

        /**
         * 可推移的時鐘：Starter 的 Clock Bean 以 @ConditionalOnMissingBean 讓位給它。
         */
        @Bean
        MutableClock clock() {
            return new MutableClock();
        }

        /**
         * 應用程式自訂的 claim；刻意使用 List.of()，確認刷新時仍能讀回（customizer 會轉換集合）。
         */
        @Bean
        TokenClaimsContributor tenantsContributor() {
            return (context, user) -> {
                if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) && user.isPresent()) {
                    context.getClaims().claim("tenants", java.util.List.of("tenant-a", "tenant-b"));
                }
            };
        }
    }
}
