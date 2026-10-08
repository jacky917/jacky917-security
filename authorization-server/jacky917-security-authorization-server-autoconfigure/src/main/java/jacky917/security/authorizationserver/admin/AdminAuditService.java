package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.support.Columns;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;

/**
 * Writes administration actions to {@code admin_audit_log} (data model
 * §8.3, phase 3 and 4 design D25).
 * <p>
 * 把管理操作寫入 {@code admin_audit_log}（資料模型 §8.3、第 3、4 階段設計 D25）。
 * <p>
 * Call it inside the transaction that makes the change, so the record is
 * committed or rolled back together with it. The snapshots are written as
 * JSON; callers must leave out secrets such as password hashes and client
 * secrets.
 * <p>
 * 請在進行變更的交易中呼叫，紀錄會與變更一起提交或回滾。快照以 JSON 寫入；
 * 呼叫端必須排除密碼雜湊、client secret 等機密。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AdminAuditService {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final JdbcClient jdbc;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc   the JDBC client of the authorization server database
     *               <br>Authorization Server 資料庫的 JDBC client
     * @param clock  the clock
     *               <br>時鐘
     */
    public AdminAuditService(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    /**
     * Records an action of the current operator ({@link AdminOperator#current()}).
     * <p>
     * 記錄目前操作者（{@code AdminOperator#current()}）的一個操作。
     *
     * @param action      what was done, for example {@code USER_CREATED}
     *                    <br>做了什麼，例如 {@code USER_CREATED}
     * @param targetType  what kind of thing changed
     *                    <br>變更的對象種類
     * @param targetId    the changed thing, or {@code null}
     *                    <br>變更的對象，或 {@code null}
     * @param before      the state before, serializable to JSON, or
     *                    {@code null}
     *                    <br>變更前的狀態（可序列化為 JSON），或 {@code null}
     * @param after       the state after, or {@code null}
     *                    <br>變更後的狀態，或 {@code null}
     */
    public void record(String action, AdminAuditTarget targetType, @Nullable String targetId, @Nullable Object before,
                       @Nullable Object after) {
        AdminOperator operator = AdminOperator.current();
        jdbc.sql("""
                        INSERT INTO admin_audit_log (occurred_at, operator_user_id, operator_client, action, target_type,
                            target_id, before_value, after_value, ip_address)
                        VALUES (:at, :user, :client, :action, :type, :target, :before, :after, :ip)""")
                .param("at", Timestamp.from(clock.instant()))
                .param("user", operator.userId())
                .param("client", operator.clientId())
                .param("action", action)
                .param("type", targetType.name())
                .param("target", targetId)
                .param("before", json(before))
                .param("after", json(after))
                .param("ip", Columns.truncate(operator.ipAddress(), Columns.IP_ADDRESS))
                .update();
    }

    private static @Nullable String json(@Nullable Object value) {
        return value == null ? null : JSON.writeValueAsString(value);
    }
}
