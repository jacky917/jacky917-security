package jacky917.security.authorizationserver.observability;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.keys.SigningKey;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import jacky917.security.authorizationserver.maintenance.DataCleanupEvent;
import jacky917.security.authorizationserver.refresh.RefreshTokenRejectedEvent;
import jacky917.security.authorizationserver.token.AccessTokenIssuedEvent;
import org.jspecify.annotations.Nullable;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Micrometer metrics of the authorization server (detailed design §8.2).
 * <p>
 * Authorization Server 的 Micrometer metrics（詳細設計 §8.2）。
 * <table>
 *   <caption>Metrics / metrics</caption>
 *   <tr><th>Name</th><th>Type</th><th>Tags</th></tr>
 *   <tr><td>{@code jacky917.as.login}</td><td>counter</td><td>{@code idp},
 *       {@code result} ({@code success} or the failure reason)</td></tr>
 *   <tr><td>{@code jacky917.as.token.issued}</td><td>counter</td>
 *       <td>{@code grant_type}, {@code client_id}</td></tr>
 *   <tr><td>{@code jacky917.as.refresh.reuse_detected}</td><td>counter</td>
 *       <td>{@code client_id}</td></tr>
 *   <tr><td>{@code jacky917.as.refresh.grace_rejected}</td><td>counter</td>
 *       <td>{@code client_id}</td></tr>
 *   <tr><td>{@code jacky917.as.refresh.rejected}</td><td>counter</td>
 *       <td>{@code reason}</td></tr>
 *   <tr><td>{@code jacky917.as.session.active}</td><td>gauge</td><td>—</td></tr>
 *   <tr><td>{@code jacky917.as.signing_key.age}</td><td>gauge (days)</td>
 *       <td>—</td></tr>
 *   <tr><td>{@code jacky917.as.cleanup.deleted}</td><td>counter</td>
 *       <td>{@code table}</td></tr>
 * </table>
 * The counters come from the starter's application events; the gauges query
 * the database when the registry reads them. Alert when
 * {@code reuse_detected} is above zero, and when the key age exceeds the
 * rotation period plus two days (the rotation job is not running).
 * <p>
 * Counter 取自 starter 發布的 application event；gauge 在 registry 讀取時查詢
 * 資料庫。{@code reuse_detected} 大於零、或金鑰使用天數超過輪換週期加兩天
 * （輪換排程沒有執行）時應發出告警。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AuthorizationServerMetrics {

    private final MeterRegistry registry;
    private final RegisteredClientRepository clients;
    private final Map<String, String> clientIds = new ConcurrentHashMap<>();

    /**
     * Creates the metrics and registers the gauges.
     * <p>
     * 建立 metrics 並註冊 gauge。
     *
     * @param registry  the meter registry
     *                  <br>meter registry
     * @param clients   resolves the client id of an event's registered
     *                  client
     *                  <br>取得事件中 registered client 的 client id
     * @param jdbc      the JDBC client, for the active session count
     *                  <br>JDBC client，用於計算有效的登入 Session
     * @param keys      the signing key store, for the key age
     *                  <br>簽章金鑰儲存，用於金鑰的使用天數
     * @param clock     the clock
     *                  <br>時鐘
     */
    public AuthorizationServerMetrics(MeterRegistry registry, RegisteredClientRepository clients, JdbcClient jdbc,
                                      SigningKeyStore keys, Clock clock) {
        this.registry = registry;
        this.clients = clients;
        Gauge.builder("jacky917.as.session.active", () -> jdbc.sql(
                                "SELECT COUNT(*) FROM auth_session WHERE status = 'ACTIVE' AND expires_at > :now")
                        .param("now", Timestamp.from(clock.instant())).query(Integer.class).single())
                .description("Active login sessions").register(registry);
        Gauge.builder("jacky917.as.signing_key.age", () -> keys.findActive().map(key -> ageInDays(key, clock.instant()))
                        .orElse(Double.NaN))
                .description("Days since the active signing key started signing").baseUnit("days").register(registry);
    }

    /**
     * Counts logins.
     * <p>
     * 計算登入次數。
     *
     * @param event  the audit event
     *               <br>稽核事件
     */
    @EventListener
    public void onLogin(LoginAuditEvent event) {
        if (event.type() == LoginAuditEventType.LOGIN) {
            String result = event.success() ? "success"
                    : event.failureReason() == null ? "failure" : event.failureReason().toLowerCase(Locale.ROOT);
            registry.counter("jacky917.as.login", "idp", event.idp() == null ? "unknown" : event.idp(),
                    "result", result).increment();
        }
    }

    /**
     * Counts issued access tokens.
     * <p>
     * 計算簽發的 Access Token。
     *
     * @param event  the event
     *               <br>事件
     */
    @EventListener
    public void onAccessTokenIssued(AccessTokenIssuedEvent event) {
        registry.counter("jacky917.as.token.issued", "grant_type", event.grantType(), "client_id", event.clientId())
                .increment();
    }

    /**
     * Counts refused refreshes.
     * <p>
     * 計算被拒絕的刷新。
     *
     * @param event  the event
     *               <br>事件
     */
    @EventListener
    public void onRefreshRejected(RefreshTokenRejectedEvent event) {
        registry.counter("jacky917.as.refresh.rejected", "reason", event.reason().name().toLowerCase(Locale.ROOT))
                .increment();
        switch (event.reason()) {
            case REUSE_DETECTED -> registry.counter("jacky917.as.refresh.reuse_detected", "client_id",
                    clientId(event.registeredClientId())).increment();
            case CONCURRENT -> registry.counter("jacky917.as.refresh.grace_rejected", "client_id",
                    clientId(event.registeredClientId())).increment();
            default -> {
                // 其他原因只計入 jacky917.as.refresh.rejected
            }
        }
    }

    /**
     * Counts the rows deleted by the scheduled cleanup.
     * <p>
     * 計算排程清理刪除的筆數。
     *
     * @param event  the event
     *               <br>事件
     */
    @EventListener
    public void onCleanup(DataCleanupEvent event) {
        registry.counter("jacky917.as.cleanup.deleted", "table", event.target()).increment(event.count());
    }

    private String clientId(@Nullable String registeredClientId) {
        if (registeredClientId == null) {
            return "unknown";
        }
        // client 很少變動：以 registered client id 快取 client id
        return clientIds.computeIfAbsent(registeredClientId, id -> {
            RegisteredClient client = clients.findById(id);
            return client == null ? "unknown" : client.getClientId();
        });
    }

    static double ageInDays(SigningKey key, Instant now) {
        Instant since = key.activatedAt() == null ? key.createdAt() : key.activatedAt();
        return Duration.between(since, now).toMinutes() / (24.0 * 60);
    }
}
