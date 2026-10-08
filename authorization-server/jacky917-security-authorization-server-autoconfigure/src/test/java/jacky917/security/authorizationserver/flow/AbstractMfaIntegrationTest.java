package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.mfa.Totp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 兩步驟驗證（第 3、4 階段設計 §7）：在帳號頁啟用、登入時的第二步、復原碼、錯誤次數、角色要求啟用、管理員重設。
 * 角色 {@code SECURE_OPERATOR} 必須使用兩步驟驗證。
 */
@TestPropertySource(properties = "jacky917.security.authorization-server.mfa.required-roles=SECURE_OPERATOR")
abstract class AbstractMfaIntegrationTest extends AbstractFlowIntegrationTest {

    private static final Pattern SECRET = Pattern.compile("<code>([A-Z2-7 ]+)</code>");
    private static final Pattern CODE = Pattern.compile("<code>([a-z2-9]{5}-[a-z2-9]{5})</code>");

    @Autowired
    JwtEncoder jwtEncoder;

    @BeforeEach
    void createRequiredRole() {
        if (jdbc.sql("SELECT COUNT(*) FROM app_role WHERE code = 'SECURE_OPERATOR'").query(Integer.class).single() == 0) {
            Timestamp now = Timestamp.from(Instant.now());
            jdbc.sql("INSERT INTO app_role (id, code, name, built_in, created_at, updated_at) "
                            + "VALUES ('0192a6f4-0000-7000-8000-00000000mfa1', 'SECURE_OPERATOR', 'Secure', :no, :now, :now)")
                    .param("no", false).param("now", now).update();
        }
    }

    @Test
    @DisplayName("在帳號頁啟用後，密碼登入要求驗證碼；第二步之前授權端點視為未登入；通過後 amr 為 pwd、otp（T-MFA-01、06）")
    void requiresTheCodeAfterThePassword() throws Exception {
        String userId = createUser("mfa-user", null);
        String secret = enableOnAccountPage("mfa-user").secret();
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'MFA_ENABLED'")
                .param("user", userId).query(Integer.class).single()).isEqualTo(1);

        String verifier = randomVerifier();
        MockHttpSession browser = passwordStep("mfa-user", verifier);
        mockMvc.perform(get(authorizeUrl(challenge(verifier))).session(browser).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
        assertThat(jdbc.sql("SELECT COUNT(*) FROM auth_session WHERE user_id = :user").param("user", userId)
                .query(Integer.class).single()).as("第二步之前只有啟用時的登入 Session").isEqualTo(1);
        assertThat(page(browser, "/jacky917/mfa")).contains("兩步驟驗證");

        clock.advance(Duration.ofSeconds(30));
        String location = mfa(browser, Totp.code(secret, Totp.step(clock.instant())));
        assertThat(location).startsWith("http://localhost/oauth2/authorize");
        Jwt idToken = exchange(browser, location, verifier);
        assertThat(idToken.getClaimAsStringList("amr")).containsExactly("pwd", "otp");
    }

    @Test
    @DisplayName("同一個驗證碼不能用兩次；復原碼只能用一次；帳號頁可停用（T-MFA-02）")
    void codesWorkOnlyOnce() throws Exception {
        createUser("replay-user", null);
        Enabled enabled = enableOnAccountPage("replay-user");
        clock.advance(Duration.ofSeconds(30));
        String code = Totp.code(enabled.secret(), Totp.step(clock.instant()));
        String verifier = randomVerifier();
        MockHttpSession first = passwordStep("replay-user", verifier);
        assertThat(mfa(first, code)).startsWith("http://localhost/oauth2/authorize");

        MockHttpSession second = passwordStep("replay-user", randomVerifier());
        assertThat(mfaPage(second, code)).contains("驗證碼錯誤或已使用過");
        String recovery = enabled.recoveryCodes().get(0);
        assertThat(mfa(second, recovery.toUpperCase())).as("復原碼不分大小寫").startsWith("http://localhost/oauth2/authorize");
        MockHttpSession third = passwordStep("replay-user", randomVerifier());
        assertThat(mfaPage(third, recovery)).contains("驗證碼錯誤或已使用過");

        String account = page(first, "/jacky917/account/mfa");
        assertThat(account).contains("剩餘的復原碼： 9");
        clock.advance(Duration.ofSeconds(30));
        mockMvc.perform(post("/jacky917/account/mfa/disable").session(first).with(csrf())
                        .param("code", Totp.code(enabled.secret(), Totp.step(clock.instant()))))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account?notice=mfa_disabled"));
        assertThat(jdbc.sql("SELECT COUNT(*) FROM user_mfa_totp u JOIN app_user a ON a.id = u.user_id "
                + "WHERE a.username = 'replay-user'").query(Integer.class).single()).isZero();
    }

    @Test
    @DisplayName("錯誤 5 次：回到登入頁、稽核 MFA_FAILED、計入帳號鎖定（T-MFA-03）")
    void endsTheLoginAfterFiveWrongCodes() throws Exception {
        String userId = createUser("guessing-user", null);
        enableOnAccountPage("guessing-user");
        MockHttpSession browser = passwordStep("guessing-user", randomVerifier());
        for (int i = 0; i < 4; i++) {
            assertThat(mfaPage(browser, "000000")).contains("驗證碼錯誤或已使用過");
        }
        assertThat(mfa(browser, "000000")).isEqualTo("/login?error=mfa");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'LOGIN' "
                + "AND failure_reason = 'MFA_FAILED'").param("user", userId).query(Integer.class).single()).isEqualTo(5);
        assertThat(jdbc.sql("SELECT locked_until FROM app_user WHERE id = :id").param("id", userId)
                .query(Timestamp.class).optional()).as("達到 login-protection.max-failures").isPresent();
        mockMvc.perform(get("/jacky917/mfa").session(browser)).andExpect(header().string(HttpHeaders.LOCATION, "/login"));
    }

    @Test
    @DisplayName("角色要求但尚未啟用：登入時先啟用，顯示復原碼後繼續授權請求；不能停用（T-MFA-05）")
    void requiredRolesTurnItOnDuringLogin() throws Exception {
        String userId = createUser("operator", null, "SECURE_OPERATOR");
        String verifier = randomVerifier();
        MockHttpSession browser = new MockHttpSession();
        browser = startLogin(browser, verifier);
        String location = mockMvc.perform(post("/login").session(browser).param("username", "operator")
                .param("password", PASSWORD).param("_csrf", csrfToken(browser))).andReturn().getResponse()
                .getRedirectedUrl();
        assertThat(location).isEqualTo("/jacky917/mfa/setup");
        String setup = page(browser, "/jacky917/mfa/setup");
        assertThat(setup).contains("您的帳號必須使用兩步驟驗證").contains("data:image/svg+xml;base64,");
        String secret = secretOf(setup);

        String codes = mockMvc.perform(post("/jacky917/mfa/setup").session(browser).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW")
                        .param("code", Totp.code(secret, Totp.step(clock.instant()))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(recoveryCodesOf(codes)).hasSize(10);
        Matcher next = Pattern.compile("href=\"(http://localhost/oauth2/authorize[^\"]+)\"").matcher(codes);
        assertThat(next.find()).isTrue();
        Jwt idToken = exchange(browser, next.group(1).replace("&amp;", "&"), verifier);
        assertThat(idToken.getClaimAsStringList("amr")).containsExactly("pwd", "otp");

        String account = page(browser, "/jacky917/account/mfa");
        assertThat(account).contains("無法停用").doesNotContain("/jacky917/account/mfa/disable");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM user_mfa_totp WHERE user_id = :user").param("user", userId)
                .query(Integer.class).single()).isEqualTo(1);
    }

    @Test
    @DisplayName("管理員重設：GET 顯示狀態，DELETE 停用並稽核；之後登入不再要求驗證碼")
    void administratorsCanReset() throws Exception {
        String userId = createUser("lost-phone", null);
        enableOnAccountPage("lost-phone");
        String admin = mint(Map.of("aud", List.of("jacky917-api"), "asid", "admin-session",
                "permissions", List.of("as:user:read", "as:user:write")));
        String status = mockMvc.perform(get("/admin/api/users/" + userId + "/mfa")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + admin))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(JSON.readTree(status).get("enabled").asBoolean()).isTrue();
        assertThat(JSON.readTree(status).get("remainingRecoveryCodes").asInt()).isEqualTo(10);
        mockMvc.perform(delete("/admin/api/users/" + userId + "/mfa").header(HttpHeaders.AUTHORIZATION, "Bearer " + admin))
                .andExpect(status().isNoContent());
        mockMvc.perform(delete("/admin/api/users/" + userId + "/mfa").header(HttpHeaders.AUTHORIZATION, "Bearer " + admin))
                .andExpect(status().isNotFound());
        assertThat(jdbc.sql("SELECT COUNT(*) FROM admin_audit_log WHERE action = 'USER_MFA_RESET' AND target_id = :id")
                .param("id", userId).query(Integer.class).single()).isEqualTo(1);
        logInAndExchangeCode("lost-phone");
    }

    // ---- 共用工具 ----

    record Enabled(String secret, List<String> recoveryCodes) {
    }

    /**
     * 以一般登入取得已登入的瀏覽器，在帳號頁啟用兩步驟驗證。
     */
    Enabled enableOnAccountPage(String username) throws Exception {
        MockHttpSession browser = logInAndExchangeCode(username).browser();
        String setup = page(browser, "/jacky917/account/mfa");
        String secret = secretOf(setup);
        String result = mockMvc.perform(post("/jacky917/account/mfa").session(browser).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW").param("code", "123"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(result).contains("驗證碼錯誤或已使用過");
        String codes = mockMvc.perform(post("/jacky917/account/mfa").session(browser).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW")
                        .param("code", Totp.code(secret, Totp.step(clock.instant()))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        List<String> recoveryCodes = recoveryCodesOf(codes);
        assertThat(recoveryCodes).hasSize(10).doesNotHaveDuplicates();
        return new Enabled(secret, recoveryCodes);
    }

    MockHttpSession startLogin(MockHttpSession browser, String verifier) throws Exception {
        MvcResult toLogin = mockMvc.perform(get(authorizeUrl(challenge(verifier))).session(browser)
                .accept(MediaType.TEXT_HTML)).andExpect(header().string(HttpHeaders.LOCATION, "/login")).andReturn();
        return (MockHttpSession) toLogin.getRequest().getSession();
    }

    /**
     * 授權請求 → 登入頁 → 送出密碼，確認被導向第二步。
     */
    MockHttpSession passwordStep(String username, String verifier) throws Exception {
        MockHttpSession browser = startLogin(new MockHttpSession(), verifier);
        mockMvc.perform(post("/login").session(browser).param("username", username).param("password", PASSWORD)
                .param("_csrf", csrfToken(browser))).andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/mfa"));
        return browser;
    }

    String mfa(MockHttpSession browser, String code) throws Exception {
        return mockMvc.perform(post("/jacky917/mfa").session(browser).with(csrf()).param("code", code))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }

    String mfaPage(MockHttpSession browser, String code) throws Exception {
        return mockMvc.perform(post("/jacky917/mfa").session(browser).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW").param("code", code))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    Jwt exchange(MockHttpSession browser, String authorizeUrl, String verifier) throws Exception {
        String callback = mockMvc.perform(get(URI.create(authorizeUrl)).session(browser))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        String code = UriComponentsBuilder.fromUriString(callback).build().getQueryParams().getFirst("code");
        JsonNode tokens = tokenRequest(mockMvc.perform(post("/oauth2/token").with(httpBasic("web-bff", "bff-secret"))
                .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", REDIRECT_URI)
                .param("code_verifier", verifier)));
        return jwtDecoder.decode(tokens.get("id_token").asString());
    }

    String page(MockHttpSession browser, String path) throws Exception {
        return mockMvc.perform(get(path).session(browser).header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    String mint(Map<String, Object> claims) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuer("http://localhost:9000").subject("someone")
                .issuedAt(now).expiresAt(now.plusSeconds(300));
        claims.forEach(builder::claim);
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(),
                builder.build())).getTokenValue();
    }

    static String secretOf(String page) {
        Matcher matcher = SECRET.matcher(page);
        assertThat(matcher.find()).as("頁面必須顯示金鑰").isTrue();
        return matcher.group(1).replace(" ", "");
    }

    static List<String> recoveryCodesOf(String page) {
        List<String> codes = new ArrayList<>();
        Matcher matcher = CODE.matcher(page);
        while (matcher.find()) {
            codes.add(matcher.group(1));
        }
        return codes;
    }
}
