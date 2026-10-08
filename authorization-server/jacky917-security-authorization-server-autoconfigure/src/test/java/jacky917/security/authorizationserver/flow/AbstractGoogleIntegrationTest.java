package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.support.FakeOidcProvider;
import jacky917.security.authorizationserver.support.TestDatabases;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import jacky917.security.authorizationserver.support.MutableClock;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
/**
 * 以假的 Google（{@link FakeOidcProvider}）執行第三方登入的整合測試共用設定與工具。另有一個 registration
 * {@code google-work} 指向同一個假提供者，用來測試「以另一個已連結的提供者確認連結」。
 */
@SpringBootTest(classes = AbstractGoogleIntegrationTest.TestApplication.class, properties = {
        "jacky917.security.authorization-server.issuer=http://localhost:9000",
        "jacky917.security.authorization-server.keys.encryption-key=" + TestDatabases.TEST_ENCRYPTION_KEY,
        "jacky917.security.authorization-server.clients.web-bff.secret=bff-secret",
        "jacky917.security.authorization-server.clients.web-bff.redirect-uris=" + AbstractGoogleIntegrationTest.REDIRECT_URI,
        "jacky917.security.authorization-server.clients.web-bff.scopes=openid,profile,email",
        "spring.security.oauth2.client.registration.google.client-id=" + FakeOidcProvider.CLIENT_ID,
        "spring.security.oauth2.client.registration.google.client-secret=google-secret",
        "spring.security.oauth2.client.registration.google.scope=openid,profile,email",
        "spring.security.oauth2.client.registration.google-work.client-name=Google Work",
        "spring.security.oauth2.client.registration.google-work.client-id=" + FakeOidcProvider.CLIENT_ID,
        "spring.security.oauth2.client.registration.google-work.client-secret=google-secret",
        "spring.security.oauth2.client.registration.google-work.scope=openid,profile,email",
        "spring.security.oauth2.client.registration.google-work.authorization-grant-type=authorization_code",
        "spring.security.oauth2.client.registration.google-work.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
        "spring.security.oauth2.client.provider.google-work.user-name-attribute=sub"
})
@AutoConfigureMockMvc
abstract class AbstractGoogleIntegrationTest {

    static final String REDIRECT_URI = "https://app.example.com/login/oauth2/code/jacky917";

    /**
     * 每個測試類別各自啟動與關閉（@DynamicPropertySource 的值在 context 建立時才讀取，晚於 @BeforeAll）。
     */
    static FakeOidcProvider GOOGLE;

    static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    MockMvc mockMvc;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    JwtDecoder jwtDecoder;

    @Autowired
    UserAccountService users;

    @Autowired
    MutableClock clock;

    @org.junit.jupiter.api.AfterEach
    void resetClock() {
        clock.reset();
    }

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
        for (String endpoint : new String[]{"authorization-uri:/authorize", "token-uri:/token", "jwk-set-uri:/jwks",
                "user-info-uri:/userinfo"}) {
            String[] parts = endpoint.split(":");
            registry.add("spring.security.oauth2.client.provider.google-work." + parts[0], () -> GOOGLE.baseUrl() + parts[1]);
        }
    }

    int rejectedAudits() {
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

    Flow startFlow() throws Exception {
        Flow flow = new Flow();
        mockMvc.perform(get(flow.authorizeUrl).session(flow.session).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
        return flow;
    }

    String googleCallback(Flow flow, String subject, String email, boolean verified, String name) throws Exception {
        return providerCallback(flow.session, "google", subject, email, verified, name);
    }

    /**
     * 以指定的瀏覽器 Session 與 registration（{@code google} 或 {@code google-work}）完成一次提供者登入，
     * 回傳登入服務最後的重導網址。
     */
    String providerCallback(MockHttpSession session, String registrationId, String subject, String email,
                            boolean verified, String name) throws Exception {
        return providerCallback(GOOGLE, session, registrationId, subject, email, verified, name);
    }

    /**
     * 以指定的假 OIDC 提供者完成一次登入。
     */
    String providerCallback(FakeOidcProvider provider, MockHttpSession session, String registrationId, String subject,
                            String email, boolean verified, String name) throws Exception {
        // 前往提供者：Spring 產生 state 與 nonce
        String toGoogle = mockMvc.perform(get("/oauth2/authorization/" + registrationId).session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(toGoogle).startsWith(provider.baseUrl() + "/authorize");
        // 網址中的參數是編碼過的（state 可能含 "="），必須先解碼
        Map<String, String> request = UriComponentsBuilder.fromUriString(toGoogle).build().getQueryParams().toSingleValueMap();
        String state = URLDecoder.decode(request.get("state"), StandardCharsets.UTF_8);
        String providerCode = provider.prepare(subject, email, verified, name,
                URLDecoder.decode(request.get("nonce"), StandardCharsets.UTF_8));

        // Google 導回：Spring 以 code 換 token、驗證 ID Token，接著由本專案處理登入
        URI callback = UriComponentsBuilder.fromPath("/login/oauth2/code/" + registrationId)
                .queryParam("code", providerCode).queryParam("state", state).encode().build().toUri();
        return mockMvc.perform(get(callback).session(session))
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

        JsonNode exchange(AbstractGoogleIntegrationTest test) throws Exception {
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

        /**
         * 可推移的時鐘：測試待確認連結的到期。
         */
        @Bean
        MutableClock clock() {
            return new MutableClock();
        }
    }
}
