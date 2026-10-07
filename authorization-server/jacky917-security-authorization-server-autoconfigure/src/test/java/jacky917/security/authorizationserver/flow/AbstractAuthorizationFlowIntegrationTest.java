package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.support.TestDatabases;
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
 * 以 MockMvc 模擬瀏覽器與 BFF 走完授權碼流程：授權請求 → 登入頁（從 HTML 取得 CSRF token）→ 登入
 * → 授權碼 → 以 PKCE 換 Token。子類別分別以 SQLite 與 PostgreSQL 執行（詳細設計 T-LOGIN-01、
 * T-CLIENT-01、T-CLIENT-02、T-TOKEN-03 的基本部分）。
 */
@SpringBootTest(classes = AbstractAuthorizationFlowIntegrationTest.TestApplication.class, properties = {
        "jacky917.security.authorization-server.issuer=http://localhost:9000",
        "jacky917.security.authorization-server.keys.encryption-key=" + TestDatabases.TEST_ENCRYPTION_KEY,
        "jacky917.security.authorization-server.bootstrap-admin.username=admin",
        "jacky917.security.authorization-server.bootstrap-admin.password=" + AbstractAuthorizationFlowIntegrationTest.PASSWORD,
        "jacky917.security.authorization-server.clients.web-bff.secret=bff-secret",
        "jacky917.security.authorization-server.clients.web-bff.redirect-uris=" + AbstractAuthorizationFlowIntegrationTest.REDIRECT_URI,
        "jacky917.security.authorization-server.clients.web-bff.scopes=openid,profile",
        "jacky917.security.authorization-server.clients.report-batch.secret=batch-secret",
        "jacky917.security.authorization-server.clients.report-batch.grant-types=client_credentials",
        "jacky917.security.authorization-server.clients.report-batch.scopes=report.generate",
        "jacky917.security.authorization-server.clients.suspended.secret=suspended-secret",
        "jacky917.security.authorization-server.clients.suspended.grant-types=client_credentials",
        "jacky917.security.authorization-server.clients.suspended.scopes=report.generate"
})
@AutoConfigureMockMvc
abstract class AbstractAuthorizationFlowIntegrationTest {

    static final String PASSWORD = "correct horse battery";
    static final String REDIRECT_URI = "https://app.example.com/login/oauth2/code/jacky917";

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");
    private static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    MockMvc mockMvc;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    JwtDecoder jwtDecoder;

    @Test
    @DisplayName("授權碼 + PKCE 完整流程：登入後建立 auth_session，換到的 Access Token 的 sub 為使用者 ID")
    void authorizationCodeFlow() throws Exception {
        String verifier = randomVerifier();
        MockHttpSession session = new MockHttpSession();

        // 1. 未登入的瀏覽器發出授權請求 → 導向登入頁
        URI authorize = authorizeUrl(challenge(verifier));
        mockMvc.perform(get(authorize).session(session).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));

        // 2. 登入頁有表單與 CSRF token；3. 送出帳密 → 回到原本的授權請求
        String csrf = csrfToken(session);
        MvcResult login = mockMvc.perform(post("/login").session(session)
                        .param("username", "admin").param("password", PASSWORD).param("_csrf", csrf))
                .andExpect(status().is3xxRedirection()).andReturn();
        String savedRequest = login.getResponse().getRedirectedUrl();
        assertThat(savedRequest).startsWith("http://localhost/oauth2/authorize");

        String userId = jdbc.sql("SELECT id FROM app_user WHERE username = 'admin'").query(String.class).single();
        Map<String, Object> authSession = jdbc.sql("SELECT session_id, login_method, idp, amr, status FROM auth_session "
                + "WHERE user_id = :user").param("user", userId).query().singleRow();
        assertThat(authSession).containsEntry("login_method", "PASSWORD").containsEntry("idp", "local")
                .containsEntry("amr", "pwd").containsEntry("status", "ACTIVE");
        assertThat(session.getAttribute(AuthSessionService.SESSION_ATTRIBUTE)).isEqualTo(authSession.get("session_id"));

        // 4. 已登入 → 授權碼導回 client
        // 以 URI 傳入：字串會被當成 URI 樣板再編碼一次
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
        assertThat(tokens.has("refresh_token")).isTrue();
        assertThat(tokens.has("id_token")).isTrue();
        Jwt accessToken = jwtDecoder.decode(tokens.get("access_token").asString());
        assertThat(accessToken.getSubject()).isEqualTo(userId);
        assertThat(accessToken.getIssuer().toString()).isEqualTo("http://localhost:9000");
        assertThat(accessToken.getHeaders()).containsKey("kid");
    }

    @Test
    @DisplayName("密碼錯誤 → /login?error；頁面依語言顯示相同的錯誤訊息")
    void wrongPassword() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String csrf = csrfToken(session);
        mockMvc.perform(post("/login").session(session)
                        .param("username", "admin").param("password", "wrong password!").param("_csrf", csrf))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?error"));
        String page = mockMvc.perform(get("/login?error").header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("帳號或密碼錯誤").contains("lang=\"zh-TW\"");
        String english = mockMvc.perform(get("/login?error").header(HttpHeaders.ACCEPT_LANGUAGE, "en"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(english).contains("Incorrect username or password.");
    }

    @Test
    @DisplayName("登入頁不可被嵌入 iframe，並帶內容安全政策")
    void loginPageHeaders() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy",
                        org.hamcrest.Matchers.containsString("frame-ancestors 'none'")));
    }

    @Test
    @DisplayName("沒有 PKCE 的授權請求被拒絕（T-CLIENT-02）")
    void authorizationRequestWithoutPkceIsRejected() throws Exception {
        String url = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code").queryParam("client_id", "web-bff")
                .queryParam("redirect_uri", REDIRECT_URI).queryParam("scope", "openid").queryParam("state", "s")
                .build().toUriString();
        MvcResult result = mockMvc.perform(get(url).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection()).andReturn();
        assertThat(result.getResponse().getRedirectedUrl()).startsWith(REDIRECT_URI).contains("error=invalid_request");
    }

    @Test
    @DisplayName("未註冊的 redirect_uri：直接回 400，不重導")
    void unregisteredRedirectUriIsNotFollowed() throws Exception {
        String url = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code").queryParam("client_id", "web-bff")
                .queryParam("redirect_uri", "https://evil.example.com/callback").queryParam("scope", "openid")
                .queryParam("code_challenge", challenge(randomVerifier())).queryParam("code_challenge_method", "S256")
                .build().toUriString();
        mockMvc.perform(get(url).accept(MediaType.TEXT_HTML)).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("client_credentials：Access Token 的 sub 為 client_id（T-TOKEN-03 的基本部分）")
    void clientCredentials() throws Exception {
        JsonNode tokens = tokenRequest(mockMvc.perform(post("/oauth2/token").with(httpBasic("report-batch", "batch-secret"))
                .param("grant_type", "client_credentials").param("scope", "report.generate")));
        assertThat(tokens.has("refresh_token")).isFalse();
        Jwt accessToken = jwtDecoder.decode(tokens.get("access_token").asString());
        assertThat(accessToken.getSubject()).isEqualTo("report-batch");
        assertThat(accessToken.getClaimAsStringList("scope")).containsExactly("report.generate");
    }

    @Test
    @DisplayName("停權的 client 換 Token：401 invalid_client（T-CLIENT-01）")
    void suspendedClientIsRejected() throws Exception {
        jdbc.sql("UPDATE client_profile SET status = 'SUSPENDED' WHERE registered_client_id = "
                + "(SELECT id FROM oauth2_registered_client WHERE client_id = 'suspended')").update();
        String body = mockMvc.perform(post("/oauth2/token").with(httpBasic("suspended", "suspended-secret"))
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        assertThat(body).contains("invalid_client");
    }

    @Test
    @DisplayName("OIDC discovery 的 issuer 與設定相同；JWKS 只有公鑰")
    void discoveryAndJwks() throws Exception {
        JsonNode discovery = JSON.readTree(mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(discovery.get("issuer").asString()).isEqualTo("http://localhost:9000");
        JsonNode jwks = JSON.readTree(mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(jwks.get("keys")).hasSize(1);
        assertThat(jwks.get("keys").get(0).has("d")).isFalse();
    }

    private JsonNode tokenRequest(org.springframework.test.web.servlet.ResultActions actions) throws Exception {
        return JSON.readTree(actions.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private String csrfToken(MockHttpSession session) throws Exception {
        String page = mockMvc.perform(get("/login").session(session))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        Matcher matcher = CSRF.matcher(page);
        assertThat(matcher.find()).as("登入頁必須有 CSRF 欄位").isTrue();
        return matcher.group(1);
    }

    private static URI authorizeUrl(String challenge) {
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

    private static String randomVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class TestApplication {
    }
}
