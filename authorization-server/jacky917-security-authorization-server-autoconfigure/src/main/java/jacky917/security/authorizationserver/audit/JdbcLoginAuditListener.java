package jacky917.security.authorizationserver.audit;

import jacky917.security.authorizationserver.support.Columns;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;

/**
 * Writes {@link LoginAuditEvent}s to {@code login_audit}.
 * <p>
 * 把 {@code LoginAuditEvent} 寫入 {@code login_audit}。
 * <p>
 * A database error does not fail the login, logout or token request that
 * published the event (detailed design §8.1). Instead the whole event,
 * except the typed login name, is logged as an error so it can be
 * recovered from the log, and a {@link LoginAuditWriteFailedEvent} is
 * published so the failure can be alerted on. IP rate limiting counts the
 * failed logins written here, so it does not see the lost ones. Any other
 * exception is a bug and is not caught.
 * <p>
 * 資料庫錯誤不會讓發布事件的登入、登出或 token 請求失敗（詳細設計 §8.1）；改為
 * 把整個事件（不含輸入的帳號）記錄為錯誤日誌，以便從日誌補回，並發布
 * {@code LoginAuditWriteFailedEvent} 以便告警。IP 限流計算的是寫入此處的登入
 * 失敗，因此看不到遺失的紀錄。其他例外屬於程式錯誤，不會被捕捉。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class JdbcLoginAuditListener {

    private final JdbcClient jdbc;
    private final ApplicationEventPublisher events;

    /**
     * Creates the listener.
     * <p>
     * 建立 listener。
     *
     * @param jdbc    the JDBC client of the authorization server database
     *                <br>Authorization Server 資料庫的 JDBC client
     * @param events  publishes a {@link LoginAuditWriteFailedEvent} when a
     *                write fails
     *                <br>寫入失敗時發布 {@code LoginAuditWriteFailedEvent}
     */
    public JdbcLoginAuditListener(JdbcClient jdbc, ApplicationEventPublisher events) {
        this.jdbc = jdbc;
        this.events = events;
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
                    .param("method", event.loginMethod() == null ? null : event.loginMethod().name())
                    .param("idp", event.idp())
                    .param("client", event.registeredClientId())
                    .param("session", event.sessionId())
                    .param("success", event.success())
                    .param("reason", event.failureReason() == null ? null : event.failureReason().name())
                    .param("ip", Columns.truncate(event.ipAddress(), Columns.IP_ADDRESS))
                    .param("agent", Columns.truncate(event.userAgent(), Columns.USER_AGENT))
                    .update();
        } catch (DataAccessException ex) {
            // 不記錄輸入的帳號（可能是誤填的密碼）；其餘欄位足以從日誌補回紀錄
            log.error("Cannot write audit event type={} success={} user={} method={} idp={} client={} session={} "
                            + "reason={} ip={} at={}; IP rate limiting does not see it", event.type(), event.success(),
                    event.userId(), event.loginMethod(), event.idp(), event.registeredClientId(), event.sessionId(),
                    event.failureReason(), event.ipAddress(), event.occurredAt(), ex);
            events.publishEvent(new LoginAuditWriteFailedEvent(event.type()));
        }
    }
}
