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

    // ---- 共用工具 ----

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
