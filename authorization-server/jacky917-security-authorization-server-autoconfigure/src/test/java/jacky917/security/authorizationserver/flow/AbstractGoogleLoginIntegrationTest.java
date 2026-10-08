package jacky917.security.authorizationserver.flow;

import jacky917.security.authorizationserver.support.FakeOidcProvider;
import jacky917.security.authorizationserver.user.NewUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
/**
 * 以 Google 登入（由 {@link FakeOidcProvider} 模擬）：Spring 的 oauth2Login 實際換 code、驗證 ID Token，
 * 再由本專案找到或建立使用者、建立登入 Session、轉換 principal（D16），最後完成授權碼流程
 * （詳細設計 §5.3、T-FED-01／02／04／06）。
 */
abstract class AbstractGoogleLoginIntegrationTest extends AbstractGoogleIntegrationTest {

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
    @DisplayName("已驗證的 Email 屬於既有帳號：不建立使用者，導向連結確認頁（D06-C，確認流程見 AbstractAccountLinkingIntegrationTest）")
    void verifiedEmailOfExistingAccountAsksToLink() throws Exception {
        String email = "owner-" + UUID.randomUUID() + "@example.com";
        users.createUser(new NewUser(null, email, true, "correct horse battery", null, Set.of()));
        int before = jdbc.sql("SELECT COUNT(*) FROM app_user").query(Integer.class).single();
        String location = attemptGoogleLogin("google-" + UUID.randomUUID(), email, true, "Attacker");
        assertThat(location).isEqualTo("/jacky917/link-account");
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
}
