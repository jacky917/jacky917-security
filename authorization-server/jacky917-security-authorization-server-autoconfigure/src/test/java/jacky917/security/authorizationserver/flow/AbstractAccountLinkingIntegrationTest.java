package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.user.NewUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 帳號連結（詳細設計 §5.3、D06）：Email 屬於既有帳號時要求確認（以密碼或另一個已連結的提供者），以及帳號頁的
 * 連結與解除連結。
 */
abstract class AbstractAccountLinkingIntegrationTest extends AbstractGoogleIntegrationTest {

    private static final String PASSWORD = "correct horse battery";

    @Test
    @DisplayName("以原帳號密碼確認：密碼錯誤計入失敗；正確後連結、登入（amr=fed,pwd）並繼續授權；之後以 Google 直接登入同一位使用者")
    void confirmWithPassword() throws Exception {
        String email = "owner-" + UUID.randomUUID() + "@example.com";
        String ownerId = users.createUser(new NewUser("owner-" + UUID.randomUUID().toString().substring(0, 8), email,
                true, PASSWORD, "Owner", Set.of())).id();
        String subject = "google-" + UUID.randomUUID();
        Flow flow = startFlow();
        assertThat(googleCallback(flow, subject, email, true, "Owner at Google")).isEqualTo("/jacky917/link-account");

        String page = mockMvc.perform(get("/jacky917/link-account").session(flow.session)
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("連結您的 Google 帳號").contains(email).contains("name=\"password\"");

        assertThat(confirm(flow.session, "wrong password!")).isEqualTo("/jacky917/link-account?error");
        assertThat(jdbc.sql("SELECT failed_login_count FROM app_user WHERE id = :id").param("id", ownerId)
                .query(Integer.class).single()).isEqualTo(1);
        assertThat(linkedProviders(ownerId)).isEmpty();

        String location = confirm(flow.session, PASSWORD);
        assertThat(location).startsWith("http://localhost/oauth2/authorize");
        assertThat(linkedProviders(ownerId)).containsExactly("google");
        assertThat(audits(ownerId)).contains("ACCOUNT_LINKED:google");
        String asid = (String) flow.session.getAttribute(AuthSessionService.SESSION_ATTRIBUTE);
        assertThat(jdbc.sql("SELECT login_method, idp, amr FROM auth_session WHERE session_id = :id").param("id", asid)
                .query().singleRow()).containsEntry("login_method", "FEDERATED").containsEntry("idp", "google")
                .containsEntry("amr", "fed,pwd");
        flow.code = codeFrom(location, flow.session);
        assertThat(jwtDecoder.decode(flow.exchange(this).get("access_token").asString()).getSubject()).isEqualTo(ownerId);

        Flow again = logInWithGoogle(subject, email, true, "Owner at Google");
        Jwt token = jwtDecoder.decode(again.exchange(this).get("access_token").asString());
        assertThat(token.getSubject()).as("已連結：直接登入同一位使用者").isEqualTo(ownerId);
    }

    @Test
    @DisplayName("取消或超過 10 分鐘：不建立連結，也不建立新使用者")
    void cancelOrExpire() throws Exception {
        String email = "cancel-" + UUID.randomUUID() + "@example.com";
        String ownerId = users.createUser(new NewUser(null, email, true, PASSWORD, null, Set.of())).id();
        Flow cancelled = startFlow();
        googleCallback(cancelled, "google-" + UUID.randomUUID(), email, true, "Someone");
        mockMvc.perform(post("/jacky917/link-account/cancel").session(cancelled.session).with(csrf()))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login"));
        mockMvc.perform(get("/jacky917/link-account").session(cancelled.session))
                .andExpect(header().string(HttpHeaders.LOCATION, "/login?error=federation"));

        Flow expired = startFlow();
        googleCallback(expired, "google-" + UUID.randomUUID(), email, true, "Someone");
        clock.advance(Duration.ofMinutes(11));
        assertThat(confirm(expired.session, PASSWORD)).isEqualTo("/login?error=federation");
        assertThat(linkedProviders(ownerId)).isEmpty();
    }

    @Test
    @DisplayName("以另一個已連結的提供者確認：只有 Google 的使用者以 google-work 登入，再以 Google 登入後完成連結")
    void confirmWithLinkedProvider() throws Exception {
        String email = "fed-" + UUID.randomUUID() + "@gmail.com";
        String googleSubject = "google-" + UUID.randomUUID();
        logInWithGoogle(googleSubject, email, true, "Fed Owner");
        String ownerId = jdbc.sql("SELECT user_id FROM user_federated_identity WHERE provider_subject = :s")
                .param("s", googleSubject).query(String.class).single();

        Flow flow = startFlow();
        assertThat(providerCallback(flow.session, "google-work", "work-" + UUID.randomUUID(), email, true, "Work"))
                .isEqualTo("/jacky917/link-account");
        String page = mockMvc.perform(get("/jacky917/link-account").session(flow.session)
                        .header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).as("沒有密碼：只能以已連結的提供者確認").doesNotContain("name=\"password\"")
                .contains("href=\"/oauth2/authorization/google\"");

        String location = providerCallback(flow.session, "google", googleSubject, email, true, "Fed Owner");
        assertThat(location).startsWith("http://localhost/oauth2/authorize");
        assertThat(linkedProviders(ownerId)).containsExactlyInAnyOrder("google", "google-work");
    }

    @Test
    @DisplayName("帳號頁連結 Google：保留原本的登入並回到帳號頁；解除連結後可再以密碼登入")
    void linkAndUnlinkFromAccountPage() throws Exception {
        String username = "linker-" + UUID.randomUUID().toString().substring(0, 8);
        String userId = users.createUser(new NewUser(username, null, false, PASSWORD, "Linker", Set.of())).id();
        MockHttpSession browser = logInWithPassword(username);
        String subject = "google-" + UUID.randomUUID();

        mockMvc.perform(post("/jacky917/account/link/google").session(browser).with(csrf()))
                .andExpect(header().string(HttpHeaders.LOCATION, "/oauth2/authorization/google"));
        assertThat(providerCallback(browser, "google", subject, subject + "@gmail.com", true, "Linker G"))
                .isEqualTo("/jacky917/account");
        assertThat(linkedProviders(userId)).containsExactly("google");
        assertThat(audits(userId)).contains("ACCOUNT_LINKED:google");

        String page = mockMvc.perform(get("/jacky917/account").session(browser).header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).as("仍以原本的使用者登入").contains("Linker").contains("/jacky917/account/unlink/google");

        mockMvc.perform(post("/jacky917/account/unlink/google").session(browser).with(csrf()))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account"));
        assertThat(linkedProviders(userId)).isEmpty();
        assertThat(audits(userId)).contains("ACCOUNT_UNLINKED:google");
    }

    @Test
    @DisplayName("帳號頁連結已屬於其他使用者的 Google 帳號：拒絕（linked_elsewhere），原連結不變")
    void cannotLinkAnAccountOfSomeoneElse() throws Exception {
        String subject = "google-" + UUID.randomUUID();
        logInWithGoogle(subject, subject + "@gmail.com", true, "First Owner");
        String username = "second-" + UUID.randomUUID().toString().substring(0, 8);
        String secondId = users.createUser(new NewUser(username, null, false, PASSWORD, null, Set.of())).id();
        MockHttpSession browser = logInWithPassword(username);
        mockMvc.perform(post("/jacky917/account/link/google").session(browser).with(csrf()));
        assertThat(providerCallback(browser, "google", subject, subject + "@gmail.com", true, "First Owner"))
                .isEqualTo("/jacky917/account?error=linked_elsewhere");
        assertThat(linkedProviders(secondId)).isEmpty();
        assertThat(jdbc.sql("SELECT COUNT(*) FROM user_federated_identity WHERE provider_subject = :s")
                .param("s", subject).query(Integer.class).single()).isEqualTo(1);
    }

    @Test
    @DisplayName("只有 Google 的使用者不能解除唯一的登入方式（last_method）")
    void cannotUnlinkTheOnlyLoginMethod() throws Exception {
        String subject = "google-" + UUID.randomUUID();
        Flow flow = logInWithGoogle(subject, subject + "@gmail.com", true, "Only Google");
        String userId = jdbc.sql("SELECT user_id FROM user_federated_identity WHERE provider_subject = :s")
                .param("s", subject).query(String.class).single();
        mockMvc.perform(post("/jacky917/account/unlink/google").session(flow.session).with(csrf()))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/account?error=last_method"));
        assertThat(linkedProviders(userId)).containsExactly("google");
    }

    private String confirm(MockHttpSession session, String password) throws Exception {
        return mockMvc.perform(post("/jacky917/link-account").session(session).with(csrf()).param("password", password))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }

    private MockHttpSession logInWithPassword(String username) throws Exception {
        MockHttpSession browser = new MockHttpSession();
        mockMvc.perform(post("/login").session(browser).with(csrf()).param("username", username).param("password", PASSWORD))
                .andExpect(header().string(HttpHeaders.LOCATION, "/jacky917/signed-in"));
        return browser;
    }

    private String codeFrom(String authorizeLocation, MockHttpSession session) throws Exception {
        MvcResult code = mockMvc.perform(get(URI.create(authorizeLocation)).session(session).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection()).andReturn();
        return UriComponentsBuilder.fromUriString(code.getResponse().getRedirectedUrl()).build()
                .getQueryParams().getFirst("code");
    }

    private List<String> linkedProviders(String userId) {
        return jdbc.sql("SELECT provider FROM user_federated_identity WHERE user_id = :user ORDER BY provider")
                .param("user", userId).query(String.class).list();
    }

    private List<String> audits(String userId) {
        return jdbc.sql("SELECT event_type, idp FROM login_audit WHERE user_id = :user ORDER BY id")
                .param("user", userId).query((rs, n) -> rs.getString(1) + ":" + rs.getString(2)).list();
    }
}
