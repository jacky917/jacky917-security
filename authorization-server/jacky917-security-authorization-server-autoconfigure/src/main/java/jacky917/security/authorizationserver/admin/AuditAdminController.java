package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the security audit ({@code login_audit}) and the administration
 * audit ({@code admin_audit_log}), newest first (phase 3 and 4 design §4.2).
 * <p>
 * 讀取安全稽核（{@code login_audit}）與管理稽核（{@code admin_audit_log}），
 * 新的在前（第 3、4 階段設計 §4.2）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@RestController
@RequestMapping("/admin/api/audit")
public class AuditAdminController {

    private final JdbcClient jdbc;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public AuditAdminController(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Lists security audit events.
     * <p>
     * 列出安全稽核事件。
     *
     * @param userId  only this user, or {@code null}
     *                <br>只列出此使用者；{@code null} 表示不限
     * @param type    only this event type, or {@code null}
     *                <br>只列出此事件種類；{@code null} 表示不限
     * @param from    only events at or after this time, or {@code null}
     *                <br>只列出此時間（含）之後的事件；{@code null} 表示不限
     * @param to      only events before this time, or {@code null}
     *                <br>只列出此時間之前的事件；{@code null} 表示不限
     * @param page    the zero-based page number
     *                <br>頁碼，從 0 開始
     * @param size    the page size, 1 to 200
     *                <br>每頁筆數，1～200
     * @return the events, newest first
     *         <br>事件，新的在前
     */
    @GetMapping("/logins")
    public PageResult<LoginAuditEntry> logins(@RequestParam(required = false) @Nullable String userId,
                                              @RequestParam(required = false) @Nullable LoginAuditEventType type,
                                              @RequestParam(required = false) @Nullable Instant from,
                                              @RequestParam(required = false) @Nullable Instant to,
                                              @RequestParam(defaultValue = "0") int page,
                                              @RequestParam(defaultValue = "50") int size) {
        PageResult.check(page, size);
        Filter filter = new Filter()
                .add("user_id = :user", "user", userId)
                .add("event_type = :type", "type", type == null ? null : type.name())
                .add("occurred_at >= :from", "from", from == null ? null : Timestamp.from(from))
                .add("occurred_at < :to", "to", to == null ? null : Timestamp.from(to));
        long total = filter.bind(jdbc.sql("SELECT COUNT(*) FROM login_audit" + filter.where()))
                .query(Long.class).single();
        List<LoginAuditEntry> items = filter.bind(jdbc.sql("""
                        SELECT id, occurred_at, event_type, user_id, username_attempted, login_method, idp,
                            registered_client_id, session_id, success, failure_reason, ip_address, user_agent
                        FROM login_audit""" + filter.where() + " ORDER BY occurred_at DESC, id DESC LIMIT :size OFFSET :offset"))
                .param("size", size).param("offset", (long) page * size)
                .query(AuditAdminController::loginEntry).list();
        return new PageResult<>(items, page, size, total);
    }

    /**
     * Lists administration actions.
     * <p>
     * 列出管理操作。
     *
     * @param targetType      only this kind of target, or {@code null}
     *                        <br>只列出此對象種類；{@code null} 表示不限
     * @param targetId        only this target, or {@code null}
     *                        <br>只列出此對象；{@code null} 表示不限
     * @param operatorUserId  only actions of this user, or {@code null}
     *                        <br>只列出此使用者的操作；{@code null} 表示不限
     * @param from            only actions at or after this time, or
     *                        {@code null}
     *                        <br>只列出此時間（含）之後的操作；{@code null}
     *                        表示不限
     * @param to              only actions before this time, or {@code null}
     *                        <br>只列出此時間之前的操作；{@code null} 表示不限
     * @param page            the zero-based page number
     *                        <br>頁碼，從 0 開始
     * @param size            the page size, 1 to 200
     *                        <br>每頁筆數，1～200
     * @return the actions, newest first
     *         <br>操作，新的在前
     */
    @GetMapping("/admin")
    public PageResult<AdminAuditEntry> adminActions(
            @RequestParam(required = false) @Nullable AdminAuditTarget targetType,
            @RequestParam(required = false) @Nullable String targetId,
            @RequestParam(required = false) @Nullable String operatorUserId,
            @RequestParam(required = false) @Nullable Instant from,
            @RequestParam(required = false) @Nullable Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        PageResult.check(page, size);
        Filter filter = new Filter()
                .add("target_type = :type", "type", targetType == null ? null : targetType.name())
                .add("target_id = :target", "target", targetId)
                .add("operator_user_id = :operator", "operator", operatorUserId)
                .add("occurred_at >= :from", "from", from == null ? null : Timestamp.from(from))
                .add("occurred_at < :to", "to", to == null ? null : Timestamp.from(to));
        long total = filter.bind(jdbc.sql("SELECT COUNT(*) FROM admin_audit_log" + filter.where()))
                .query(Long.class).single();
        List<AdminAuditEntry> items = filter.bind(jdbc.sql("""
                        SELECT id, occurred_at, operator_user_id, operator_client, action, target_type, target_id,
                            before_value, after_value, ip_address
                        FROM admin_audit_log""" + filter.where() + " ORDER BY occurred_at DESC, id DESC LIMIT :size OFFSET :offset"))
                .param("size", size).param("offset", (long) page * size)
                .query(AuditAdminController::adminEntry).list();
        return new PageResult<>(items, page, size, total);
    }

    private static LoginAuditEntry loginEntry(ResultSet rs, int rowNum) throws SQLException {
        return new LoginAuditEntry(rs.getLong("id"), rs.getTimestamp("occurred_at").toInstant(),
                rs.getString("event_type"), rs.getString("user_id"), rs.getString("username_attempted"),
                rs.getString("login_method"), rs.getString("idp"), rs.getString("registered_client_id"),
                rs.getString("session_id"), rs.getBoolean("success"), rs.getString("failure_reason"),
                rs.getString("ip_address"), rs.getString("user_agent"));
    }

    private static AdminAuditEntry adminEntry(ResultSet rs, int rowNum) throws SQLException {
        return new AdminAuditEntry(rs.getLong("id"), rs.getTimestamp("occurred_at").toInstant(),
                rs.getString("operator_user_id"), rs.getString("operator_client"), rs.getString("action"),
                rs.getString("target_type"), rs.getString("target_id"), rs.getString("before_value"),
                rs.getString("after_value"), rs.getString("ip_address"));
    }

    /**
     * Optional conditions joined with {@code AND}; a condition whose value is
     * {@code null} is left out.
     * <p>
     * 以 {@code AND} 連接的選用條件；值為 {@code null} 的條件不加入。
     */
    static final class Filter {

        private final List<String> conditions = new ArrayList<>();
        private final Map<String, Object> params = new LinkedHashMap<>();

        Filter add(String condition, String name, @Nullable Object value) {
            if (value != null) {
                conditions.add(condition);
                params.put(name, value);
            }
            return this;
        }

        String where() {
            return conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions);
        }

        JdbcClient.StatementSpec bind(JdbcClient.StatementSpec statement) {
            return statement.params(params);
        }
    }

    /**
     * One security audit event.
     * <p>
     * 一筆安全稽核事件。
     *
     * @param id                  the row id
     *                            <br>資料列 ID
     * @param occurredAt          when it happened
     *                            <br>發生時間
     * @param type                the event type
     *                            <br>事件種類
     * @param userId              the user, or {@code null}
     *                            <br>使用者，或 {@code null}
     * @param usernameAttempted   the login typed on a failed login, or
     *                            {@code null}
     *                            <br>登入失敗時輸入的帳號，或 {@code null}
     * @param loginMethod         {@code PASSWORD} or {@code FEDERATED}, or
     *                            {@code null}
     *                            <br>{@code PASSWORD} 或 {@code FEDERATED}，或
     *                            {@code null}
     * @param idp                 the identity provider, or {@code null}
     *                            <br>身分提供者，或 {@code null}
     * @param registeredClientId  the client, or {@code null}
     *                            <br>client，或 {@code null}
     * @param sessionId           the login session, or {@code null}
     *                            <br>登入 Session，或 {@code null}
     * @param success             whether the action succeeded
     *                            <br>動作是否成功
     * @param failureReason       why it failed, or {@code null}
     *                            <br>失敗原因，或 {@code null}
     * @param ipAddress           the client IP address, or {@code null}
     *                            <br>用戶端 IP，或 {@code null}
     * @param userAgent           the user agent, or {@code null}
     *                            <br>User-Agent，或 {@code null}
     */
    public record LoginAuditEntry(long id, Instant occurredAt, String type, @Nullable String userId,
                                  @Nullable String usernameAttempted, @Nullable String loginMethod,
                                  @Nullable String idp, @Nullable String registeredClientId,
                                  @Nullable String sessionId, boolean success, @Nullable String failureReason,
                                  @Nullable String ipAddress, @Nullable String userAgent) {
    }

    /**
     * One administration action.
     * <p>
     * 一筆管理操作。
     *
     * @param id              the row id
     *                        <br>資料列 ID
     * @param occurredAt      when it happened
     *                        <br>發生時間
     * @param operatorUserId  the user who did it, or {@code null} for a
     *                        client acting for itself
     *                        <br>操作的使用者；client 以自身身分操作時為
     *                        {@code null}
     * @param operatorClient  the client used, or {@code null}
     *                        <br>使用的 client，或 {@code null}
     * @param action          what was done
     *                        <br>做了什麼
     * @param targetType      what kind of thing changed
     *                        <br>變更的對象種類
     * @param targetId        the changed thing, or {@code null}
     *                        <br>變更的對象，或 {@code null}
     * @param before          the state before as JSON, or {@code null}
     *                        <br>變更前的狀態（JSON），或 {@code null}
     * @param after           the state after as JSON, or {@code null}
     *                        <br>變更後的狀態（JSON），或 {@code null}
     * @param ipAddress       the client IP address, or {@code null}
     *                        <br>用戶端 IP，或 {@code null}
     */
    public record AdminAuditEntry(long id, Instant occurredAt, @Nullable String operatorUserId,
                                  @Nullable String operatorClient, String action, String targetType,
                                  @Nullable String targetId, @Nullable String before, @Nullable String after,
                                  @Nullable String ipAddress) {
    }
}
