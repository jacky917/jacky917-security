package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.account.AccountMail;
import jacky917.security.authorizationserver.account.AccountMailer;
import jacky917.security.authorizationserver.user.NewUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 帳號自助功能（第 3、4 階段設計 §5）：變更密碼、強制變更密碼、忘記密碼、註冊與 Email 驗證。寄出的信件由
 * {@link CapturingMailer} 收集。
 */
@Import(AbstractAccountSelfServiceIntegrationTest.Mail.class)
@TestPropertySource(properties = "jacky917.security.authorization-server.account.registration.enabled=true")
abstract class AbstractAccountSelfServiceIntegrationTest extends AbstractFlowIntegrationTest {

    static final String NEW_PASSWORD = "a completely new password";

    @Autowired
    CapturingMailer mailer;

    @BeforeEach
    void clearMails() {
        mailer.sent.clear();
    }

    // ---- 工作 22：變更密碼 ----

    @Test
    @DisplayName("變更密碼：其他裝置的 Refresh Token 失效，目前的裝置不受影響；寄出通知；稽核（T-ACCT-01、T-REFRESH-05）")
    void changesThePassword() throws Exception {
        String userId = createUserWithEmail("changer", "changer@example.com");
        LoggedIn laptop = logInAndExchangeCode("changer");
        LoggedIn phone = logInAndExchangeCode("changer");

        String location = changePassword(phone.browser(), PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
        assertThat(location).isEqualTo("/jacky917/account?notice=password_changed");
        assertSession(laptop.asid(), "REVOKED", "PASSWORD_CHANGED");
        assertRefreshRefused(laptop);
        assertSession(phone.asid(), "ACTIVE", null);
        assertThat(refresh(phone).has("access_token")).as("進行變更的裝置仍可刷新").isTrue();
        assertThat(mailer.sent).singleElement().satisfies(mail -> {
            assertThat(mail.type()).isEqualTo(AccountMail.Type.PASSWORD_CHANGED);
            assertThat(mail.to()).isEqualTo("changer@example.com");
            assertThat(mail.link()).isEqualTo("http://localhost:9000/jacky917/password/forgot");
        });
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'PASSWORD_CHANGED' "
                + "AND success = :ok").param("user", userId).param("ok", true).query(Integer.class).single()).isEqualTo(1);
        assertThat(page(phone.browser(), location)).contains("密碼已變更").contains("/jacky917/account/password");
    }

    @Test
    @DisplayName("變更密碼的錯誤：目前的密碼錯誤（計入失敗次數）、兩次輸入不同、太短、與目前相同")
    void refusesInvalidChanges() throws Exception {
        String userId = createUser("bad-changer", null);
        LoggedIn session = logInAndExchangeCode("bad-changer");
        assertThat(changePasswordPage(session.browser(), "wrong password!", NEW_PASSWORD, NEW_PASSWORD))
                .contains("目前的密碼錯誤");
        assertThat(jdbc.sql("SELECT failed_login_count FROM app_user WHERE id = :id").param("id", userId)
                .query(Integer.class).single()).isEqualTo(1);
        assertThat(changePasswordPage(session.browser(), PASSWORD, NEW_PASSWORD, NEW_PASSWORD + "x"))
                .contains("兩次輸入的新密碼不同");
        assertThat(changePasswordPage(session.browser(), PASSWORD, "short", "short")).contains("不符合下方的規則");
        assertThat(changePasswordPage(session.browser(), PASSWORD, PASSWORD, PASSWORD)).contains("不能與目前的密碼相同");
        assertThat(mailer.sent).isEmpty();
    }

    @Test
    @DisplayName("必須變更密碼的登入：授權端點與其他頁面都導向變更頁；變更後繼續原本的授權請求並取得授權碼（T-ACCT-02）")
    void forcesThePasswordChange() throws Exception {
        String userId = createUser("must-change", null);
        jdbc.sql("UPDATE app_user SET password_change_required = :required WHERE id = :id")
                .param("required", true).param("id", userId).update();
        MockHttpSession browser = new MockHttpSession();
        String verifier = randomVerifier();
        URI authorize = authorizeUrl(challenge(verifier));
        mockMvc.perform(get(authorize).session(browser).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
        mockMvc.perform(post("/login").session(browser).with(csrf()).param("username", "must-change")
                .param("password", PASSWORD)).andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account/password"));

        mockMvc.perform(get(authorize).session(browser).accept(MediaType.TEXT_HTML))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account/password"));
        mockMvc.perform(get("/jacky917/account").session(browser))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account/password"));
        assertThat(page(browser, "/jacky917/account/password")).contains("繼續之前，請先設定新密碼");

        String location = changePassword(browser, PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
        assertThat(location).startsWith("http://localhost/oauth2/authorize");
        MvcResult code = mockMvc.perform(get(URI.create(location)).session(browser))
                .andExpect(status().is3xxRedirection()).andReturn();
        assertThat(UriComponentsBuilder.fromUriString(code.getResponse().getRedirectedUrl()).build().getQueryParams()
                .getFirst("code")).isNotNull();
        assertThat(jdbc.sql("SELECT password_change_required FROM app_user WHERE id = :id").param("id", userId)
                .query(Boolean.class).single()).isFalse();
    }

    // ---- 工作 23：忘記密碼 ----

    @Test
    @DisplayName("忘記密碼：只對已驗證的 Email 寄信；未驗證、不存在的 Email 不寄；畫面相同；登入頁有連結（T-ACCT-03）")
    void sendsResetLinksOnlyToVerifiedEmails() throws Exception {
        createUserWithEmail("forgetful", "forgetful@example.com");
        users.createUser(new NewUser("unverified-forgetful", "unverified@example.com", false, PASSWORD, null, Set.of()));
        assertThat(page(new MockHttpSession(), "/login")).contains("/jacky917/password/forgot").contains("忘記密碼");

        String verified = forgot("forgetful@example.com");
        String unverified = forgot("unverified@example.com");
        String unknown = forgot("nobody@example.com");
        assertThat(verified).contains("如果有帳號使用此 Email");
        assertThat(unverified).isEqualTo(verified.replace("forgetful@example.com", "unverified@example.com"));
        assertThat(unknown).contains("如果有帳號使用此 Email");
        assertThat(mailer.sent).singleElement().satisfies(mail -> {
            assertThat(mail.type()).isEqualTo(AccountMail.Type.PASSWORD_RESET);
            assertThat(mail.to()).isEqualTo("forgetful@example.com");
            assertThat(mail.link()).startsWith("http://localhost:9000/jacky917/password/reset?token=");
        });
    }

    @Test
    @DisplayName("重設密碼：開啟連結不使用 token；設定後撤銷所有 Session、清除暫時鎖定、舊密碼失效；token 只能用一次（T-ACCT-04）")
    void resetsThePassword() throws Exception {
        String userId = createUserWithEmail("resetter", "resetter@example.com");
        LoggedIn device = logInAndExchangeCode("resetter");
        jdbc.sql("UPDATE app_user SET locked_until = :until, failed_login_count = 4 WHERE id = :id")
                .param("until", java.sql.Timestamp.from(clock.instant().plusSeconds(600))).param("id", userId).update();
        forgot("resetter@example.com");
        String token = tokenOf(mailer.sent.get(0));

        assertThat(page(new MockHttpSession(), "/jacky917/password/reset?token=" + token)).contains("name=\"token\"");
        assertThat(page(new MockHttpSession(), "/jacky917/password/reset?token=" + token)).as("開啟兩次仍有效")
                .contains("name=\"newPassword\"");
        assertThat(reset(token, NEW_PASSWORD, NEW_PASSWORD + "!")).contains("兩次輸入的新密碼不同");
        assertThat(reset(token, "short", "short")).contains("不符合下方的規則");
        assertThat(reset(token, NEW_PASSWORD, NEW_PASSWORD)).contains("密碼已設定");

        assertSession(device.asid(), "REVOKED", "PASSWORD_CHANGED");
        assertThat(reset(token, NEW_PASSWORD + "2", NEW_PASSWORD + "2")).as("只能使用一次").contains("此連結已失效");
        mockMvc.perform(post("/login").session(new MockHttpSession()).with(csrf()).param("username", "resetter")
                .param("password", PASSWORD)).andExpect(header().string(HttpHeaders.LOCATION, "/login?error"));
        mockMvc.perform(post("/login").session(new MockHttpSession()).with(csrf()).param("username", "resetter")
                .param("password", NEW_PASSWORD)).andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/signed-in"));
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'PASSWORD_RESET'")
                .param("user", userId).query(Integer.class).single()).isEqualTo(1);
    }

    @Test
    @DisplayName("重設連結：過期後失效；60 秒內重複要求只寄一封（T-ACCT-04、T-ACCT-07）")
    void resetLinksExpireAndAreThrottled() throws Exception {
        createUserWithEmail("throttled", "throttled@example.com");
        forgot("throttled@example.com");
        forgot("throttled@example.com");
        assertThat(mailer.sent).hasSize(1);
        String token = tokenOf(mailer.sent.get(0));
        clock.advance(java.time.Duration.ofMinutes(61));
        assertThat(page(new MockHttpSession(), "/jacky917/password/reset?token=" + token)).contains("此連結已失效");
        forgot("throttled@example.com");
        assertThat(mailer.sent).as("間隔超過 60 秒可以再寄").hasSize(2);
    }

    // ---- 工作 24：註冊與 Email 驗證 ----

    @Test
    @DisplayName("註冊：登入頁有連結；驗證前無法登入；開啟連結不使用 token；密碼錯誤不能驗證；驗證後可登入；稽核（T-ACCT-05）")
    void registersAndVerifiesTheEmail() throws Exception {
        assertThat(page(new MockHttpSession(), "/login")).contains("/jacky917/register").contains("建立帳號");
        assertThat(page(new MockHttpSession(), "/jacky917/register")).contains("name=\"confirmPassword\"");

        assertThat(register("New.User@example.com", "新使用者", PASSWORD, PASSWORD)).contains("我們已寄出連結到此 Email");
        String userId = jdbc.sql("SELECT id FROM app_user WHERE email = 'New.User@example.com'").query(String.class)
                .single();
        assertThat(mailer.sent).singleElement().satisfies(mail -> {
            assertThat(mail.type()).isEqualTo(AccountMail.Type.EMAIL_VERIFICATION);
            assertThat(mail.to()).isEqualTo("New.User@example.com");
            assertThat(mail.displayName()).isEqualTo("新使用者");
            assertThat(mail.link()).startsWith("http://localhost:9000/jacky917/verify-email?token=");
        });
        mockMvc.perform(post("/login").session(new MockHttpSession()).with(csrf())
                        .param("username", "new.user@example.com").param("password", PASSWORD))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?error"));

        String token = tokenOf(mailer.sent.get(0));
        assertThat(page(new MockHttpSession(), "/jacky917/verify-email?token=" + token)).contains("name=\"password\"");
        assertThat(page(new MockHttpSession(), "/jacky917/verify-email?token=" + token)).as("開啟兩次仍有效")
                .contains("name=\"token\"");
        assertThat(verify(token, "not the password")).contains("這不是建立帳號時設定的密碼");
        assertThat(verify(token, PASSWORD)).contains("Email 已確認");
        assertThat(verify(token, PASSWORD)).as("只能使用一次").contains("此連結已失效");

        mockMvc.perform(post("/login").session(new MockHttpSession()).with(csrf())
                        .param("username", "new.user@example.com").param("password", PASSWORD))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/signed-in"));
        assertThat(users.loadAuthorities(userId).roles()).containsExactly("USER");
        assertThat(jdbc.sql("SELECT event_type FROM login_audit WHERE user_id = :user AND success = :ok "
                        + "AND event_type IN ('USER_REGISTERED', 'EMAIL_VERIFIED') ORDER BY id")
                .param("user", userId).param("ok", true).query(String.class).list())
                .containsExactly("USER_REGISTERED", "EMAIL_VERIFIED");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'EMAIL_VERIFIED' "
                + "AND success = :ok").param("user", userId).param("ok", false).query(Integer.class).single())
                .as("密碼錯誤的驗證").isEqualTo(1);
    }

    @Test
    @DisplayName("註冊既有帳號的 Email：畫面相同、不變更資料，寄出「帳號已存在」通知與重設連結（T-ACCT-06）")
    void registeringAnExistingEmailRevealsNothing() throws Exception {
        String ownerId = createUserWithEmail("owner", "owner@example.com");
        String existing = register("OWNER@example.com", null, NEW_PASSWORD, NEW_PASSWORD);
        String fresh = register("fresh@example.com", null, NEW_PASSWORD, NEW_PASSWORD);
        // 每個瀏覽器的 CSRF token 不同，其餘內容必須完全相同
        assertThat(existing.replaceAll("name=\"_csrf\" value=\"[^\"]+\"", ""))
                .isEqualTo(fresh.replace("fresh@example.com", "OWNER@example.com")
                        .replaceAll("name=\"_csrf\" value=\"[^\"]+\"", ""));

        assertThat(jdbc.sql("SELECT COUNT(*) FROM app_user WHERE LOWER(email) = 'owner@example.com'")
                .query(Integer.class).single()).isEqualTo(1);
        mockMvc.perform(post("/login").session(new MockHttpSession()).with(csrf()).param("username", "owner")
                .param("password", PASSWORD)).andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/signed-in"));
        assertThat(mailer.sent).hasSize(2).first().satisfies(mail -> {
            assertThat(mail.type()).isEqualTo(AccountMail.Type.ACCOUNT_EXISTS);
            assertThat(mail.to()).isEqualTo("OWNER@example.com");
            assertThat(mail.link()).startsWith("http://localhost:9000/jacky917/password/reset?token=");
        });
        assertThat(reset(tokenOf(mailer.sent.get(0)), NEW_PASSWORD, NEW_PASSWORD)).as("通知中的連結可重設密碼")
                .contains("密碼已設定");
        assertThat(jdbc.sql("SELECT COUNT(*) FROM login_audit WHERE user_id = :user AND event_type = 'USER_REGISTERED'")
                .param("user", ownerId).query(Integer.class).single()).isZero();
    }

    @Test
    @DisplayName("未完成的註冊可被取代：只保留一個帳號；先前的連結配上先前的密碼無法驗證，新的密碼才能（T-ACCT-06）")
    void replacesUnfinishedRegistrations() throws Exception {
        register("taken@example.com", "第一次", PASSWORD, PASSWORD);
        String first = tokenOf(mailer.sent.get(0));
        // 60 秒內再註冊：取代密碼，但不再寄信；先前的連結仍在，卻只接受新的密碼
        register("taken@example.com", "第二次", NEW_PASSWORD, NEW_PASSWORD);
        assertThat(mailer.sent).hasSize(1);
        assertThat(verify(first, PASSWORD)).contains("這不是建立帳號時設定的密碼");

        clock.advance(java.time.Duration.ofSeconds(61));
        register("taken@example.com", "第三次", PASSWORD + "3", PASSWORD + "3");
        assertThat(mailer.sent).hasSize(2);
        assertThat(verify(first, NEW_PASSWORD)).as("被新的連結取代").contains("此連結已失效");
        String latest = tokenOf(mailer.sent.get(1));
        assertThat(verify(latest, PASSWORD + "3")).contains("Email 已確認");
        assertThat(jdbc.sql("SELECT display_name FROM app_user WHERE email = 'taken@example.com'").query(String.class)
                .list()).containsExactly("第三次");

        // 已驗證的帳號不再被取代
        clock.advance(java.time.Duration.ofSeconds(61));
        register("taken@example.com", "攻擊者", NEW_PASSWORD, NEW_PASSWORD);
        assertThat(mailer.sent.get(2).type()).isEqualTo(AccountMail.Type.ACCOUNT_EXISTS);
        mockMvc.perform(post("/login").session(new MockHttpSession()).with(csrf())
                        .param("username", "taken@example.com").param("password", PASSWORD + "3"))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/signed-in"));
    }

    @Test
    @DisplayName("註冊表單的錯誤與重新寄送：Email 格式、兩次輸入不同、密碼太短；重新寄送只對未完成的註冊寄信")
    void refusesInvalidRegistrationsAndResends() throws Exception {
        assertThat(register("not-an-email", null, PASSWORD, PASSWORD)).contains("請輸入 Email");
        assertThat(register("a@example.com", null, PASSWORD, PASSWORD + "x")).contains("兩次輸入的密碼不同");
        assertThat(register("a@example.com", "名".repeat(129), PASSWORD, PASSWORD)).contains("名稱太長");
        assertThat(register("a@example.com", null, "short", "short")).contains("密碼不符合下方的規則")
                .contains("value=\"a@example.com\"");
        assertThat(mailer.sent).isEmpty();

        register("pending@example.com", null, PASSWORD, PASSWORD);
        createUserWithEmail("verified", "verified@example.com");
        clock.advance(java.time.Duration.ofSeconds(61));
        assertThat(resend("pending@example.com")).contains("我們已寄出連結到此 Email");
        assertThat(resend("verified@example.com")).contains("我們已寄出連結到此 Email");
        assertThat(resend("nobody@example.com")).contains("我們已寄出連結到此 Email");
        assertThat(mailer.sent).extracting(AccountMail::to).containsExactly("pending@example.com", "pending@example.com");
    }

    // ---- 共用工具 ----

    String forgot(String email) throws Exception {
        return mockMvc.perform(post("/jacky917/password/forgot").session(new MockHttpSession()).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW").param("email", email))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    String reset(String token, String newPassword, String confirm) throws Exception {
        return mockMvc.perform(post("/jacky917/password/reset").session(new MockHttpSession()).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW").param("token", token)
                        .param("newPassword", newPassword).param("confirmPassword", confirm))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    String register(String email, String displayName, String password, String confirm) throws Exception {
        var request = post("/jacky917/register").session(new MockHttpSession()).with(csrf())
                .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW").param("email", email).param("password", password)
                .param("confirmPassword", confirm);
        if (displayName != null) {
            request.param("displayName", displayName);
        }
        return mockMvc.perform(request).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString(StandardCharsets.UTF_8);
    }

    String resend(String email) throws Exception {
        return mockMvc.perform(post("/jacky917/verify-email/resend").session(new MockHttpSession()).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW").param("email", email))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    String verify(String token, String password) throws Exception {
        return mockMvc.perform(post("/jacky917/verify-email").session(new MockHttpSession()).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW").param("token", token).param("password", password))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    static String tokenOf(AccountMail mail) {
        return UriComponentsBuilder.fromUriString(mail.link()).build().getQueryParams().getFirst("token");
    }

    String createUserWithEmail(String username, String email) {
        return users.createUser(new NewUser(username, email, true, PASSWORD, null, Set.of())).id();
    }

    String changePassword(MockHttpSession browser, String current, String newPassword, String confirm) throws Exception {
        return mockMvc.perform(post("/jacky917/account/password").session(browser).with(csrf())
                        .param("currentPassword", current).param("newPassword", newPassword)
                        .param("confirmPassword", confirm))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }

    String changePasswordPage(MockHttpSession browser, String current, String newPassword, String confirm)
            throws Exception {
        return mockMvc.perform(post("/jacky917/account/password").session(browser).with(csrf())
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW")
                        .param("currentPassword", current).param("newPassword", newPassword)
                        .param("confirmPassword", confirm))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    String page(MockHttpSession browser, String path) throws Exception {
        return mockMvc.perform(get(path).session(browser).header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /**
     * 收集寄出的信件，不實際寄送。
     */
    static class CapturingMailer implements AccountMailer {

        final List<AccountMail> sent = new CopyOnWriteArrayList<>();

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public void send(AccountMail mail) {
            sent.add(mail);
        }
    }

    @TestConfiguration
    static class Mail {

        @Bean
        CapturingMailer accountMailer() {
            return new CapturingMailer();
        }
    }
}
