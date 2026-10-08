package jacky917.security.authorizationserver.audit;

import java.util.Objects;

/**
 * Published when a {@link LoginAuditEvent} could not be written to
 * {@code login_audit}, so the failure can be counted and alerted on: while
 * writes fail, the audit is incomplete and IP rate limiting does not see the
 * failed logins.
 * <p>
 * {@code LoginAuditEvent} 無法寫入 {@code login_audit} 時發布，以便計數與告警：
 * 寫入失敗期間稽核紀錄不完整，IP 限流也看不到這些登入失敗。
 *
 * @param type  the type of the event that was lost
 *              <br>遺失之事件的種類
 * @author Jacky
 * @since 2.1.0
 */
public record LoginAuditWriteFailedEvent(LoginAuditEventType type) {

    /**
     * Creates the event.
     * <p>
     * 建立事件。
     */
    public LoginAuditWriteFailedEvent {
        Objects.requireNonNull(type, "type");
    }
}
