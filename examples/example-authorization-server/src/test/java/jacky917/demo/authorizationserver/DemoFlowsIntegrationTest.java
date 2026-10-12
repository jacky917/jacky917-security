package jacky917.demo.authorizationserver;

import jacky917.security.authorizationserver.mfa.Totp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 以範例的 {@code application.yml}（不是測試自己的設定）走完 demo 的流程：admin 首次登入時的強制變更密碼與強制
 * 啟用兩步驟驗證、註冊與 Email 驗證、忘記密碼（信件寫在日誌中，由 {@link CapturedOutput} 讀出連結）、
 * 第三方應用程式與管理 API 的示範 client。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
@DisplayName("範例登入服務的 demo 流程（使用範例的設定檔）")
class DemoFlowsIntegrationTest {

    private static final String DEMO_PASSWORD = "demo-password-123";
    private static final String ADMIN_PASSWORD = "admin-password-123";
    private static final String BFF_CALLBACK = "http://localhost:8082/login/oauth2/code/jacky917";
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");
    private static final Pattern SECRET = Pattern.compile("<code>([A-Z2-7 ]+)</code>");

    @Autowired
    MockMvc mockMvc;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    RegisteredClientRepository clients;

    @Test
    @DisplayName("admin 首次登入：先強制啟用兩步驟驗證（mfa.required-roles），再強制變更密碼，最後回到授權請求")
    void adminFirstLogin() throws Exception {
        String verifier = verifier();
        URI authorize = authorizeUrl(verifier);
        MockHttpSession browser = new MockHttpSession();
        mockMvc.perform(get(authorize).session(browser).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
        mockMvc.perform(post("/login").session(browser).param("username", "admin").param("password", ADMIN_PASSWORD)
                        .param("_csrf", csrf(browser, "/login")))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/mfa/setup"));

        String setup = page(browser, "/jacky917/mfa/setup");
        Matcher secret = SECRET.matcher(setup);
        assertThat(secret.find()).as("啟用頁顯示金鑰").isTrue();
        String code = Totp.code(secret.group(1).replace(" ", ""), Totp.step(Instant.now()));
        String codes = mockMvc.perform(post("/jacky917/mfa/setup").session(browser).param("code", code)
                        .param("_csrf", csrf(setup)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(codes).as("顯示復原碼，繼續的連結指向變更密碼頁").contains("/jacky917/account/password");

        // 強制變更密碼之前，授權請求也被導向變更頁
        mockMvc.perform(get(authorize).session(browser).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account/password"));
        String changed = mockMvc.perform(post("/jacky917/account/password").session(browser)
                        .param("currentPassword", ADMIN_PASSWORD).param("newPassword", "a brand new admin password")
                        .param("confirmPassword", "a brand new admin password")
                        .param("_csrf", csrf(browser, "/jacky917/account/password")))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(changed).startsWith("http://localhost/oauth2/authorize");

        String callback = mockMvc.perform(get(URI.create(changed)).session(browser))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertThat(callback).startsWith(BFF_CALLBACK + "?code=");
        assertThat(jdbc.sql("SELECT amr FROM auth_session s JOIN app_user u ON u.id = s.user_id "
                + "WHERE u.username = 'admin' AND s.status = 'ACTIVE'").query(String.class).list()).contains("pwd,otp");
    }

    @Test
    @DisplayName("註冊與 Email 驗證：信件寫在日誌中；以日誌的連結與註冊時的密碼驗證後可以登入")
    void registrationWithMailsInTheLog(CapturedOutput output) throws Exception {
        MockHttpSession browser = new MockHttpSession();
        String sent = mockMvc.perform(post("/jacky917/register").session(browser)
                        .param("email", "carol@example.com").param("displayName", "Carol")
                        .param("password", DEMO_PASSWORD).param("confirmPassword", DEMO_PASSWORD)
                        .param("_csrf", csrf(browser, "/jacky917/register")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(sent).doesNotContain("name=\"password\"");

        String token = linkToken(output, "http://localhost:9000/jacky917/verify-email?token=");
        MockHttpSession verifying = new MockHttpSession();
        String verified = mockMvc.perform(post("/jacky917/verify-email").session(verifying).param("token", token)
                        .param("password", DEMO_PASSWORD)
                        .param("_csrf", csrf(verifying, "/jacky917/verify-email?token=" + token)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(verified).doesNotContain("name=\"token\"");
        assertThat(jdbc.sql("SELECT email_verified FROM app_user WHERE email = 'carol@example.com'")
                .query(Boolean.class).single()).isTrue();

        MockHttpSession login = new MockHttpSession();
        mockMvc.perform(post("/login").session(login).param("username", "carol@example.com")
                        .param("password", DEMO_PASSWORD).param("_csrf", csrf(login, "/login")))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/signed-in"));
    }

    @Test
    @DisplayName("忘記密碼：重設連結寫在日誌中；以連結設定新密碼後，舊密碼失效、新密碼可以登入")
    void forgottenPasswordWithMailsInTheLog(CapturedOutput output) throws Exception {
        MockHttpSession browser = new MockHttpSession();
        mockMvc.perform(post("/jacky917/password/forgot").session(browser).param("email", "bob@example.com")
                        .param("_csrf", csrf(browser, "/jacky917/password/forgot")))
                .andExpect(status().isOk());
        String token = linkToken(output, "http://localhost:9000/jacky917/password/reset?token=");

        MockHttpSession resetting = new MockHttpSession();
        mockMvc.perform(post("/jacky917/password/reset").session(resetting).param("token", token)
                        .param("newPassword", "bob's brand new password")
                        .param("confirmPassword", "bob's brand new password")
                        .param("_csrf", csrf(resetting, "/jacky917/password/reset?token=" + token)))
                .andExpect(status().isOk());

        MockHttpSession oldPassword = new MockHttpSession();
        mockMvc.perform(post("/login").session(oldPassword).param("username", "bob").param("password", DEMO_PASSWORD)
                        .param("_csrf", csrf(oldPassword, "/login")))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?error"));
        MockHttpSession newPassword = new MockHttpSession();
        mockMvc.perform(post("/login").session(newPassword).param("username", "bob")
                        .param("password", "bob's brand new password").param("_csrf", csrf(newPassword, "/login")))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/signed-in"));
    }

    @Test
    @DisplayName("示範 client：partner-demo 是要求同意的第三方 client，scope bb.read 對應權限 bb；admin-demo 可以呼叫管理 API")
    void demoClients() throws Exception {
        RegisteredClient partner = clients.findByClientId("partner-demo");
        assertThat(partner).isNotNull();
        assertThat(partner.getClientSettings().isRequireAuthorizationConsent()).isTrue();
        assertThat(partner.getScopes()).contains("bb.read");
        assertThat(jdbc.sql("SELECT p.code FROM app_scope_permission sp JOIN app_permission p ON p.id = sp.permission_id "
                + "WHERE sp.scope_code = 'bb.read'").query(String.class).list()).containsExactly("bb");
        assertThat(jdbc.sql("SELECT privacy_policy_url FROM client_profile WHERE registered_client_id = :id")
                .param("id", partner.getId()).query(String.class).single()).isEqualTo("http://localhost:8082/privacy.html");

        String basic = Base64.getEncoder().encodeToString(("admin-demo:admin-secret-for-local-demo")
                .getBytes(StandardCharsets.UTF_8));
        String token = mockMvc.perform(post("/oauth2/token").header(HttpHeaders.AUTHORIZATION, "Basic " + basic)
                        .param("grant_type", "client_credentials").param("scope", "as:user:read"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String accessToken = token.replaceAll(".*\"access_token\":\"([^\"]+)\".*", "$1");
        mockMvc.perform(get("/admin/api/users").param("query", "alice")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/admin/api/roles").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isForbidden());
    }

    // ---- 共用工具 ----

    /**
     * 等待背景寄出的信件出現在日誌中，回傳連結中的 token。
     */
    private static String linkToken(CapturedOutput output, String linkPrefix) throws InterruptedException {
        Pattern link = Pattern.compile(Pattern.quote(linkPrefix) + "([A-Za-z0-9_%-]+)");
        Instant deadline = Instant.now().plus(Duration.ofSeconds(10));
        while (Instant.now().isBefore(deadline)) {
            Matcher matcher = link.matcher(output.getOut());
            String token = null;
            while (matcher.find()) {
                token = matcher.group(1);
            }
            if (token != null) {
                return token;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("No mail with " + linkPrefix + " in the log");
    }

    private String page(MockHttpSession browser, String path) throws Exception {
        return mockMvc.perform(get(path).session(browser)).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    private String csrf(MockHttpSession browser, String path) throws Exception {
        return csrf(page(browser, path));
    }

    private static String csrf(String page) {
        Matcher matcher = CSRF.matcher(page);
        assertThat(matcher.find()).as("頁面有 CSRF 欄位").isTrue();
        return matcher.group(1);
    }

    private static URI authorizeUrl(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code").queryParam("client_id", "web-bff")
                .queryParam("redirect_uri", BFF_CALLBACK).queryParam("scope", "openid profile")
                .queryParam("state", "demo").queryParam("code_challenge",
                        Base64.getUrlEncoder().withoutPadding().encodeToString(digest))
                .queryParam("code_challenge_method", "S256").encode().build().toUri();
    }

    private static String verifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
