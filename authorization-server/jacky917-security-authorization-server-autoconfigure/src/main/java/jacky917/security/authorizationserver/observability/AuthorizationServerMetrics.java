package jacky917.security.authorizationserver.observability;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginAuditWriteFailedEvent;
import jacky917.security.authorizationserver.keys.SigningKey;
import jacky917.security.authorizationserver.keys.SigningKeyStore;
import jacky917.security.authorizationserver.maintenance.DataCleanupEvent;
import jacky917.security.authorizationserver.maintenance.MaintenanceFailedEvent;
import jacky917.security.authorizationserver.refresh.RefreshTokenRejectedEvent;
import jacky917.security.authorizationserver.token.AccessTokenIssuedEvent;
import lombok.extern.slf4j.Slf4j;
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
 *       <td>{@code grant_type}, {@code client_id} (the OAuth
 *       {@code client_id}); counts signing attempts, so a token whose
 *       authorization then fails to be saved is counted too</td></tr>
 *   <tr><td>{@code jacky917.as.refresh.reuse_detected}</td><td>counter</td>
 *       <td>{@code client_id}</td></tr>
 *   <tr><td>{@code jacky917.as.refresh.grace_rejected}</td><td>counter</td>
 *       <td>{@code client_id}</td></tr>
 *   <tr><td>{@code jacky917.as.refresh.rejected}</td><td>counter</td>
 *       <td>{@code reason}; only the refusals of the reuse detector, not
 *       those of Spring Authorization Server such as an expired token</td></tr>
 *   <tr><td>{@code jacky917.as.session.active}</td><td>gauge</td><td>—</td></tr>
 *   <tr><td>{@code jacky917.as.signing_key.age}</td><td>gauge (days)</td>
 *       <td>— ; infinite when there is no {@code ACTIVE} key</td></tr>
 *   <tr><td>{@code jacky917.as.cleanup.deleted}</td><td>counter</td>
 *       <td>{@code target}, a {@code CleanupTarget} tag; rows deleted, or
 *       marked expired for {@code expired_sessions}</td></tr>
 *   <tr><td>{@code jacky917.as.audit.write_failures}</td><td>counter</td>
 *       <td>{@code type}</td></tr>
 *   <tr><td>{@code jacky917.as.maintenance.failures}</td><td>counter</td>
 *       <td>{@code task}, the job or {@code cleanup.<target>}</td></tr>
 * </table>
 * The counters come from the starter's application events; the gauges query
 * the database when the registry reads them. A metric that cannot be
 * recorded is logged and never fails the request that published the event.
 * Alert when {@code reuse_detected}, {@code audit.write_failures} or
 * {@code maintenance.failures} is above zero, and when the key age exceeds
 * the rotation period plus two days (the rotation job is not running). IP
 * rate limiting counts the failed logins in {@code login_audit}, so it does
 * not see the attempts whose audit could not be written.
 * <p>
 * Counter 取自 starter 發布的 application event；gauge 在 registry 讀取時查詢
 * 資料庫。無法記錄的 metric 只記錄日誌，不會讓發布事件的請求失敗。
 * {@code reuse_detected}、{@code audit.write_failures} 或
 * {@code maintenance.failures} 大於零，或金鑰使用天數超過輪換週期加兩天（輪換
 * 排程沒有執行）時應發出告警。IP 限流計算的是 {@code login_audit} 中的登入失敗，
 * 因此看不到稽核寫入失敗的嘗試。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
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
        // 沒有 ACTIVE 金鑰時為無限大，讓「使用天數超過門檻」的告警也會觸發
        Gauge.builder("jacky917.as.signing_key.age", () -> keys.findActive().map(key -> ageInDays(key, clock.instant()))
                        .orElse(Double.POSITIVE_INFINITY))
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
        if (event.type() != LoginAuditEventType.LOGIN) {
            return;
        }
        record("jacky917.as.login", () -> {
            String result = event.success() ? "success"
                    : event.failureReason() == null ? "failure" : event.failureReason().name().toLowerCase(Locale.ROOT);
            registry.counter("jacky917.as.login", "idp", event.idp() == null ? "unknown" : event.idp(),
                    "result", result).increment();
        });
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
        record("jacky917.as.token.issued", () -> registry.counter("jacky917.as.token.issued",
                "grant_type", event.grantType(), "client_id", event.clientId()).increment());
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
        record("jacky917.as.refresh.rejected", () -> {
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
        });
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
        record("jacky917.as.cleanup.deleted", () -> registry.counter("jacky917.as.cleanup.deleted",
                "target", event.target().tag()).increment(event.count()));
    }

    /**
     * Counts audit events that could not be written.
     * <p>
     * 計算無法寫入的稽核事件。
     *
     * @param event  the event
     *               <br>事件
     */
    @EventListener
    public void onAuditWriteFailed(LoginAuditWriteFailedEvent event) {
        record("jacky917.as.audit.write_failures", () -> registry.counter("jacky917.as.audit.write_failures",
                "type", event.type().name().toLowerCase(Locale.ROOT)).increment());
    }

    /**
     * Counts failed scheduled jobs and cleanup steps.
     * <p>
     * 計算失敗的排程工作與清理步驟。
     *
     * @param event  the event
     *               <br>事件
     */
    @EventListener
    public void onMaintenanceFailed(MaintenanceFailedEvent event) {
        record("jacky917.as.maintenance.failures", () -> registry.counter("jacky917.as.maintenance.failures",
                "task", event.task()).increment());
    }

    /**
     * Records a metric; a failure is logged and never reaches the code that
     * published the event, such as a token request.
     * <p>
     * 記錄 metric；失敗只記錄日誌，不會影響發布事件的程式（例如 token 請求）。
     */
    private static void record(String name, Runnable recording) {
        try {
            recording.run();
        } catch (RuntimeException ex) {
            log.warn("Cannot record the metric {}", name, ex);
        }
    }

    private String clientId(@Nullable String registeredClientId) {
        if (registeredClientId == null) {
            return "unknown";
        }
        String cached = clientIds.get(registeredClientId);
        if (cached != null) {
            return cached;
        }
        RegisteredClient client;
        try {
            client = clients.findById(registeredClientId);
        } catch (RuntimeException ex) {
            // 查詢失敗時不快取，下一次再試
            log.warn("Cannot look up client {} for a metric tag", registeredClientId, ex);
            return "unknown";
        }
        // client 很少變動：以 registered client id 快取 client id
        String clientId = client == null ? "unknown" : client.getClientId();
        clientIds.put(registeredClientId, clientId);
        return clientId;
    }

    static double ageInDays(SigningKey key, Instant now) {
        return Duration.between(key.signingSince(), now).toMinutes() / (24.0 * 60);
    }
}
