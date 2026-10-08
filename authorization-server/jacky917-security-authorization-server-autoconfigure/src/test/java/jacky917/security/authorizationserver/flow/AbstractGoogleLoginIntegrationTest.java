package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.support.FakeOidcProvider;
import jacky917.security.authorizationserver.support.TestDatabases;
import jacky917.security.authorizationserver.user.NewUser;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 以 Google 登入（由 {@link FakeOidcProvider} 模擬）：Spring 的 oauth2Login 實際換 code、驗證 ID Token，
 * 再由本專案找到或建立使用者、建立登入 Session、轉換 principal（D16），最後完成授權碼流程
 * （詳細設計 §5.3、T-FED-01／02／04／06）。
 */
@SpringBootTest(classes = AbstractGoogleLoginIntegrationTest.TestApplication.class, properties = {
        "jacky917.security.authorization-server.issuer=http://localhost:9000",
        "jacky917.security.authorization-server.keys.encryption-key=" + TestDatabases.TEST_ENCRYPTION_KEY,
        "jacky917.security.authorization-server.clients.web-bff.secret=bff-secret",
        "jacky917.security.authorization-server.clients.web-bff.redirect-uris=" + AbstractGoogleLoginIntegrationTest.REDIRECT_URI,
        "jacky917.security.authorization-server.clients.web-bff.scopes=openid,profile,email",
        "spring.security.oauth2.client.registration.google.client-id=" + FakeOidcProvider.CLIENT_ID,
        "spring.security.oauth2.client.registration.google.client-secret=google-secret",
        "spring.security.oauth2.client.registration.google.scope=openid,profile,email"
})
@AutoConfigureMockMvc
abstract class AbstractGoogleLoginIntegrationTest {

    static final String REDIRECT_URI = "https://app.example.com/login/oauth2/code/jacky917";
    /**
     * 每個測試類別各自啟動與關閉（@DynamicPropertySource 的值在 context 建立時才讀取，晚於 @BeforeAll）。
     */
    static FakeOidcProvider GOOGLE;

    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    MockMvc mockMvc;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    JwtDecoder jwtDecoder;

    @Autowired
    UserAccountService users;

    @BeforeAll
    static void startGoogle() {
        GOOGLE = FakeOidcProvider.start();
    }

    @AfterAll
    static void stopGoogle() {
        GOOGLE.close();
    }

    static void provider(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.provider.google.authorization-uri", () -> GOOGLE.baseUrl() + "/authorize");
        registry.add("spring.security.oauth2.client.provider.google.token-uri", () -> GOOGLE.baseUrl() + "/token");
        registry.add("spring.security.oauth2.client.provider.google.jwk-set-uri", () -> GOOGLE.baseUrl() + "/jwks");
        registry.add("spring.security.oauth2.client.provider.google.user-info-uri", () -> GOOGLE.baseUrl() + "/userinfo");
    }

    @Test
    @DisplayName("登入頁顯示「使用 Google 登入」")
    void loginPageShowsProvider() throws Exception {
        String page = mockMvc.perform(get("/login").header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("href=\"/oauth2/authorization/google\"").contains("使用 Google 登入");
    }

    @Test
    @DisplayName("全新的 Google 帳號：建立使用者與連結，Token 的 sub 為新使用者 ID、idp=google、amr=fed（T-FED-01）")
    void newGoogleAccountCreatesUser() throws Exception {
        String subject = "google-" + UUID.randomUUID();
        String email = subject + "@gmail.com";
        Flow flow = logInWithGoogle(subject, email, true, "Google User");
        String userId = jdbc.sql("SELECT user_id FROM user_federated_identity WHERE provider = 'google' AND provider_subject = :s")
                .param("s", subject).query(String.class).single();

        Map<String, Object> user = jdbc.sql("SELECT username, password_hash, email, display_name FROM app_user WHERE id = :id")
                .param("id", userId).query().singleRow();
        assertThat(user.get("username")).isNull();
        assertThat(user.get("password_hash")).isNull();
        assertThat(user).containsEntry("email", email).containsEntry("display_name", "Google User");
        assertThat(users.loadAuthorities(userId).roles()).containsExactly("USER");
        assertThat(jdbc.sql("SELECT raw_attributes FROM user_federated_identity WHERE user_id = :id").param("id", userId)
                .query(String.class).single()).contains("\"sub\"").doesNotContainIgnoringCase("token");

        Map<String, Object> session = jdbc.sql("SELECT login_method, idp, amr FROM auth_session WHERE session_id = :id")
                .param("id", flow.asid()).query().singleRow();
        assertThat(session).containsEntry("login_method", "FEDERATED").containsEntry("idp", "google").containsEntry("amr", "fed");
        assertThat(jdbc.sql("SELECT login_method, idp, session_id FROM login_audit WHERE event_type = 'LOGIN' "
                        + "AND user_id = :user").param("user", userId).query().singleRow())
                .as("登入稽核").containsEntry("login_method", "FEDERATED").containsEntry("idp", "google")
                .containsEntry("session_id", flow.asid());

        JsonNode tokens = flow.exchange(this);
        Jwt access = jwtDecoder.decode(tokens.get("access_token").asString());
        assertThat(access.getSubject()).isEqualTo(userId);
        assertThat(access.getClaimAsString("idp")).isEqualTo("google");
        assertThat(access.getClaimAsString("asid")).isEqualTo(flow.asid());
        Jwt id = jwtDecoder.decode(tokens.get("id_token").asString());
        assertThat(id.getSubject()).isEqualTo(userId);
        assertThat(id.getClaimAsStringList("amr")).containsExactly("fed");
        assertThat(id.getClaimAsString("email")).isEqualTo(email);
        assertThat(id.getClaims()).containsKey("auth_time");
    }

    @Test
    @DisplayName("已連結的 Google 帳號再次登入：同一位使用者，不重複建立（T-FED-02）")
    void linkedAccountLogsInSameUser() throws Exception {
        String subject = "google-" + UUID.randomUUID();
        logInWithGoogle(subject, subject + "@gmail.com", true, "First Name").exchange(this);
        JsonNode tokens = logInWithGoogle(subject, subject + "@gmail.com", true, "New Name").exchange(this);
        String userId = jdbc.sql("SELECT user_id FROM user_federated_identity WHERE provider_subject = :s")
                .param("s", subject).query(String.class).single();
        assertThat(jwtDecoder.decode(tokens.get("access_token").asString()).getSubject()).isEqualTo(userId);
        assertThat(jdbc.sql("SELECT display_name FROM user_federated_identity WHERE provider_subject = :s")
                .param("s", subject).query(String.class).single()).isEqualTo("New Name");
    }

    @Test
    @DisplayName("email_verified=false：不儲存 Email、不與其他帳號比對，各自建立使用者（T-FED-04）")
    void unverifiedEmailIsNotStoredOrMatched() throws Exception {
        String email = "shared-" + UUID.randomUUID() + "@example.com";
        String first = "google-" + UUID.randomUUID();
        String second = "google-" + UUID.randomUUID();
        logInWithGoogle(first, email, false, "First").exchange(this);
        logInWithGoogle(second, email, false, "Second").exchange(this);
        assertThat(jdbc.sql("SELECT u.email FROM app_user u JOIN user_federated_identity f ON f.user_id = u.id "
                        + "WHERE f.provider_subject IN (:subjects)").param("subjects", Set.of(first, second))
                .query(String.class).list()).hasSize(2).containsOnlyNulls();
    }

    @Test
    @DisplayName("已驗證的 Email 屬於既有帳號：拒絕（連結確認於之後的版本提供），不建立使用者")
    void verifiedEmailOfExistingAccountIsRejected() throws Exception {
        String email = "owner-" + UUID.randomUUID() + "@example.com";
        users.createUser(new NewUser(null, email, true, "correct horse battery", null, Set.of()));
        int before = jdbc.sql("SELECT COUNT(*) FROM app_user").query(Integer.class).single();
        String location = attemptGoogleLogin("google-" + UUID.randomUUID(), email, true, "Attacker");
        assertThat(location).isEqualTo("/login?error=account_exists");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM app_user").query(Integer.class).single()).isEqualTo(before);
    }

    @Test
    @DisplayName("使用者已停用：拒絕登入並回到登入頁（T-FED-06）")
    void disabledUserIsRejected() throws Exception {
        String subject = "google-" + UUID.randomUUID();
        logInWithGoogle(subject, subject + "@gmail.com", true, "Soon Disabled").exchange(this);
        jdbc.sql("UPDATE app_user SET status = 'DISABLED' WHERE id = (SELECT user_id FROM user_federated_identity "
                + "WHERE provider_subject = :s)").param("s", subject).update();
        int before = rejectedAudits();
        assertThat(attemptGoogleLogin(subject, subject + "@gmail.com", true, "Soon Disabled"))
                .isEqualTo("/login?error=federation");
        assertThat(rejectedAudits()).as("稽核記錄 USER_CANNOT_LOG_IN").isEqualTo(before + 1);
    }

    private int rejectedAudits() {
        return jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE event_type = 'LOGIN' AND idp = 'google' "
                + "AND failure_reason = 'USER_CANNOT_LOG_IN'").query(Integer.class).single();
    }

    /**
     * 完整的 Google 登入，回到授權請求後取得授權碼。
     */
    Flow logInWithGoogle(String subject, String email, boolean verified, String name) throws Exception {
        Flow flow = startFlow();
        String location = googleCallback(flow, subject, email, verified, name);
        assertThat(location).startsWith("http://localhost/oauth2/authorize");
        flow.asid = (String) flow.session.getAttribute(AuthSessionService.SESSION_ATTRIBUTE);
        assertThat(flow.asid).isNotNull();
        MvcResult code = mockMvc.perform(get(URI.create(location)).session(flow.session))
                .andExpect(status().is3xxRedirection()).andReturn();
        flow.code = UriComponentsBuilder.fromUriString(code.getResponse().getRedirectedUrl()).build()
                .getQueryParams().getFirst("code");
        assertThat(flow.code).isNotNull();
        return flow;
    }

    String attemptGoogleLogin(String subject, String email, boolean verified, String name) throws Exception {
        Flow flow = startFlow();
        String location = googleCallback(flow, subject, email, verified, name);
        // 被拒絕後仍是未登入：再次發出授權請求會導向登入頁
        mockMvc.perform(get(flow.authorizeUrl).session(flow.session).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
        return location;
    }

    private Flow startFlow() throws Exception {
        Flow flow = new Flow();
        mockMvc.perform(get(flow.authorizeUrl).session(flow.session).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
        return flow;
    }

    private String googleCallback(Flow flow, String subject, String email, boolean verified, String name) throws Exception {
        // 前往 Google：Spring 產生 state 與 nonce
        String toGoogle = mockMvc.perform(get("/oauth2/authorization/google").session(flow.session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(toGoogle).startsWith(GOOGLE.baseUrl() + "/authorize");
        // 網址中的參數是編碼過的（state 可能含 "="），必須先解碼
        Map<String, String> request = UriComponentsBuilder.fromUriString(toGoogle).build().getQueryParams().toSingleValueMap();
        String state = URLDecoder.decode(request.get("state"), StandardCharsets.UTF_8);
        String providerCode = GOOGLE.prepare(subject, email, verified, name,
                URLDecoder.decode(request.get("nonce"), StandardCharsets.UTF_8));

        // Google 導回：Spring 以 code 換 token、驗證 ID Token，接著由本專案處理登入
        URI callback = UriComponentsBuilder.fromPath("/login/oauth2/code/google")
                .queryParam("code", providerCode).queryParam("state", state).encode().build().toUri();
        return mockMvc.perform(get(callback).session(flow.session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }

    static final class Flow {
        final MockHttpSession session = new MockHttpSession();
        final String verifier = randomVerifier();
        final URI authorizeUrl = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code").queryParam("client_id", "web-bff")
                .queryParam("redirect_uri", REDIRECT_URI).queryParam("scope", "openid email")
                .queryParam("state", "s").queryParam("code_challenge", challenge(verifier))
                .queryParam("code_challenge_method", "S256").encode().build().toUri();
        String asid;
        String code;

        String asid() {
            return asid;
        }

        JsonNode exchange(AbstractGoogleLoginIntegrationTest test) throws Exception {
            return JSON.readTree(test.mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                            .param("grant_type", "authorization_code").param("code", code)
                            .param("redirect_uri", REDIRECT_URI).param("code_verifier", verifier))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        }

        private static String randomVerifier() {
            byte[] bytes = new byte[32];
            new SecureRandom().nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }

        private static String challenge(String verifier) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
                return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            } catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
    }
}
