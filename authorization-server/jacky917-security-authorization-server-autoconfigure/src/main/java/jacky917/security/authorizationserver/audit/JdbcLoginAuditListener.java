package jacky917.security.authorizationserver.audit;

import jacky917.security.authorizationserver.support.Columns;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;

/**
 * Writes {@link LoginAuditEvent}s to {@code login_audit}.
 * <p>
 * 把 {@code LoginAuditEvent} 寫入 {@code login_audit}。
 * <p>
 * A failed write is logged and otherwise ignored: auditing never breaks a
 * login, a logout or a token request (detailed design §8.1).
 * <p>
 * 寫入失敗只記錄錯誤日誌，不影響其他流程：稽核不會讓登入、登出或 token 請求
 * 失敗（詳細設計 §8.1）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class JdbcLoginAuditListener {

    private final JdbcClient jdbc;

    /**
     * Creates the listener.
     * <p>
     * 建立 listener。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public JdbcLoginAuditListener(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Writes one event.
     * <p>
     * 寫入一筆事件。
     *
     * @param event  the event
     *               <br>事件
     */
    @EventListener
    public void onLoginAuditEvent(LoginAuditEvent event) {
        try {
            jdbc.sql("""
                            INSERT INTO login_audit (occurred_at, event_type, user_id, username_attempted, login_method, idp,
                                registered_client_id, session_id, success, failure_reason, ip_address, user_agent)
                            VALUES (:at, :type, :user, :username, :method, :idp, :client, :session, :success, :reason,
                                :ip, :agent)""")
                    .param("at", Timestamp.from(event.occurredAt()))
                    .param("type", event.type().name())
                    .param("user", event.userId())
                    .param("username", Columns.truncate(event.usernameAttempted(), Columns.USERNAME_ATTEMPTED))
                    .param("method", event.loginMethod())
                    .param("idp", event.idp())
                    .param("client", event.registeredClientId())
                    .param("session", event.sessionId())
                    .param("success", event.success())
                    .param("reason", Columns.truncate(event.failureReason(), Columns.FAILURE_REASON))
                    .param("ip", Columns.truncate(event.ipAddress(), Columns.IP_ADDRESS))
                    .param("agent", Columns.truncate(event.userAgent(), Columns.USER_AGENT))
                    .update();
        } catch (RuntimeException ex) {
            log.error("Cannot write the {} audit event of user {}", event.type(), event.userId(), ex);
        }
    }
}
