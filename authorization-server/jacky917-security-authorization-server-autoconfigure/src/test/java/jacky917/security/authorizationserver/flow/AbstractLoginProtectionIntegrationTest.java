package jacky917.security.authorizationserver.flow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * 登入保護（詳細設計 §5.1）：連續失敗鎖定、IP 限流、登入稽核。每個測試使用不同的 IP，避免互相影響限流。
 */
@TestPropertySource(properties = "jacky917.security.authorization-server.login-protection.max-failures-per-ip-per-minute=3")
abstract class AbstractLoginProtectionIntegrationTest extends AbstractFlowIntegrationTest {

    private static final String SIGNED_IN = "/jacky917/signed-in";

    @Test
    @DisplayName("連續 5 次密碼錯誤：鎖定 15 分鐘（正確密碼也無法登入、不延長鎖定），到期後可以登入")
    void consecutiveFailuresLockTheAccount() throws Exception {
        String userId = createUser("lock-user", null);
        for (int i = 1; i <= 4; i++) {
            assertThat(logIn("lock-user", "wrong password!", "10.1.0." + i)).isEqualTo("/login?error");
        }
        assertThat(user(userId)).containsEntry("failed_login_count", 4).containsEntry("locked_until", null);

        assertThat(logIn("lock-user", "wrong password!", "10.1.0.5")).isEqualTo("/login?error");
        Instant lockedUntil = ((Timestamp) user(userId).get("locked_until")).toInstant();
        assertThat(Duration.between(clock.instant(), lockedUntil)).isBetween(Duration.ofMinutes(14), Duration.ofMinutes(15));
        assertThat(user(userId)).as("鎖定時計數歸零").containsEntry("failed_login_count", 0);
        assertThat(audits(userId)).containsExactly("LOGIN:BAD_CREDENTIALS", "LOGIN:BAD_CREDENTIALS",
                "LOGIN:BAD_CREDENTIALS", "LOGIN:BAD_CREDENTIALS", "LOGIN:BAD_CREDENTIALS", "ACCOUNT_LOCKED:null");

        assertThat(logIn("lock-user", PASSWORD, "10.1.0.6")).as("鎖定期間正確密碼也失敗").isEqualTo("/login?error");
        assertThat(logIn("lock-user", "wrong password!", "10.1.0.7")).isEqualTo("/login?error");
        assertThat(((Timestamp) user(userId).get("locked_until")).toInstant()).as("鎖定不延長").isEqualTo(lockedUntil);
        assertThat(audits(userId)).endsWith("LOGIN:LOCKED", "LOGIN:LOCKED");

        clock.advance(Duration.ofMinutes(16));
        assertThat(logIn("lock-user", PASSWORD, "10.1.0.8")).isEqualTo(SIGNED_IN);
    }

    @Test
    @DisplayName("登入成功時失敗次數歸零；成功登入寫入 LOGIN 稽核（含登入 Session）")
    void successResetsTheFailureCount() throws Exception {
        String userId = createUser("reset-user", null);
        for (int i = 1; i <= 3; i++) {
            logIn("reset-user", "wrong password!", "10.3.0." + i);
        }
        assertThat(user(userId)).containsEntry("failed_login_count", 3);
        assertThat(logIn("reset-user", PASSWORD, "10.3.0.4")).isEqualTo(SIGNED_IN);
        assertThat(user(userId)).containsEntry("failed_login_count", 0);
        Map<String, Object> success = jdbc.sql("SELECT session_id, login_method, idp, ip_address FROM login_audit "
                        + "WHERE user_id = :user AND event_type = 'LOGIN' AND success = :ok")
                .param("user", userId).param("ok", true).query().singleRow();
        assertThat(success).containsEntry("login_method", "PASSWORD").containsEntry("idp", "local")
                .containsEntry("ip_address", "10.3.0.4");
        assertThat(success.get("session_id")).isNotNull();
    }

    @Test
    @DisplayName("同一個 IP 最近一分鐘失敗 3 次後：正確密碼也被拒絕（rate_limited，不檢查密碼）；其他 IP 不受影響；一分鐘後恢復")
    void failuresFromOneIpAreRateLimited() throws Exception {
        String userId = createUser("rate-user", null);
        for (int i = 1; i <= 3; i++) {
            assertThat(logIn("nobody-" + i, "wrong password!", "10.2.0.1")).isEqualTo("/login?error");
        }
        assertThat(logIn("rate-user", PASSWORD, "10.2.0.1")).isEqualTo("/login?error=rate_limited");
        assertThat(user(userId)).as("沒有檢查密碼，也不計入帳號的失敗").containsEntry("failed_login_count", 0);
        assertThat(jdbc.sql("SELECT username_attempted FROM login_audit WHERE ip_address = '10.2.0.1' "
                + "AND failure_reason = 'RATE_LIMITED'").query(String.class).list()).containsExactly("rate-user");

        assertThat(logIn("rate-user", PASSWORD, "10.2.0.2")).as("其他 IP").isEqualTo(SIGNED_IN);
        clock.advance(Duration.ofSeconds(61));
        assertThat(logIn("rate-user", PASSWORD, "10.2.0.1")).as("一分鐘後").isEqualTo(SIGNED_IN);

        String page = mockMvc.perform(get("/login?error=rate_limited").header(HttpHeaders.ACCEPT_LANGUAGE, "zh-TW"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(page).contains("嘗試次數過多");
    }

    @Test
    @DisplayName("不存在的帳號：稽核記錄 UNKNOWN_USER 與輸入的帳號；頁面訊息與密碼錯誤相同")
    void unknownUserIsAudited() throws Exception {
        assertThat(logIn("ghost", "wrong password!", "10.4.0.1")).isEqualTo("/login?error");
        Map<String, Object> row = jdbc.sql("SELECT user_id, username_attempted, failure_reason FROM login_audit "
                + "WHERE ip_address = '10.4.0.1'").query().singleRow();
        assertThat(row).containsEntry("user_id", null).containsEntry("username_attempted", "ghost")
                .containsEntry("failure_reason", "UNKNOWN_USER");
    }

    @Test
    @DisplayName("停用的帳號：正確密碼也失敗，稽核記錄 DISABLED，不計入失敗次數")
    void disabledUserIsAudited() throws Exception {
        String userId = createUser("disabled-login", null);
        jdbc.sql("UPDATE app_user SET status = 'DISABLED' WHERE id = :id").param("id", userId).update();
        assertThat(logIn("disabled-login", PASSWORD, "10.5.0.1")).isEqualTo("/login?error");
        assertThat(audits(userId)).containsExactly("LOGIN:DISABLED");
        assertThat(user(userId)).containsEntry("failed_login_count", 0);
    }

    private String logIn(String username, String password, String ip) throws Exception {
        return mockMvc.perform(post("/login").session(new MockHttpSession()).with(csrf()).with(remoteAddr(ip))
                        .param("username", username).param("password", password))
                .andReturn().getResponse().getRedirectedUrl();
    }

    private Map<String, Object> user(String userId) {
        Map<String, Object> row = jdbc.sql("SELECT failed_login_count, locked_until FROM app_user WHERE id = :id")
                .param("id", userId).query().singleRow();
        // PostgreSQL 與 SQLite 回傳的數字型別不同
        row.put("failed_login_count", ((Number) row.get("failed_login_count")).intValue());
        if (row.get("locked_until") != null && !(row.get("locked_until") instanceof Timestamp)) {
            row.put("locked_until", new Timestamp(((Number) row.get("locked_until")).longValue()));
        }
        return row;
    }

    private List<String> audits(String userId) {
        return jdbc.sql("SELECT event_type, failure_reason FROM login_audit WHERE user_id = :user ORDER BY id")
                .param("user", userId).query((rs, n) -> rs.getString(1) + ":" + rs.getString(2)).list();
    }

    private static RequestPostProcessor remoteAddr(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }
}
