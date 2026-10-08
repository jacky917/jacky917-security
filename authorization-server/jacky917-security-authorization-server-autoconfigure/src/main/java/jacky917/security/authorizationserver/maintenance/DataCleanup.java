package jacky917.security.authorizationserver.maintenance;

import jacky917.security.authorizationserver.keys.SigningKeyStore;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.IntSupplier;

/**
 * Deletes expired data (data model §14.1, detailed design §5.8).
 * <p>
 * 刪除過期的資料（資料模型 §14.1、詳細設計 §5.8）。
 * <p>
 * Rows are deleted at most {@code batchSize} at a time, each batch in its
 * own statement, so no lock is held for long. Every method returns the
 * number of rows it deleted or changed.
 * <p>
 * 每次最多刪除 {@code batchSize} 筆，每批是獨立的陳述式，不會長時間持有鎖。
 * 每個方法回傳刪除或變更的筆數。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class DataCleanup {

    /**
     * How long revoked and expired login sessions are kept.
     * <p>
     * 已撤銷與已過期之登入 Session 的保留期間。
     */
    public static final Duration SESSION_RETENTION = Duration.ofDays(30);

    /**
     * How long used or expired action tokens are kept after they expire.
     * <p>
     * 已使用或已過期之操作 token 在到期後的保留期間。
     */
    public static final Duration ACTION_TOKEN_RETENTION = Duration.ofDays(7);

    /**
     * How long retired signing keys are kept.
     * <p>
     * 已退役簽章金鑰的保留期間。
     */
    public static final Duration RETIRED_KEY_RETENTION = Duration.ofDays(365);

    /**
     * How long an authorization without any token (a user who left the
     * consent screen) is kept.
     * <p>
     * 沒有任何 token 的授權（使用者在同意畫面離開）的保留期間。
     */
    public static final Duration PENDING_AUTHORIZATION_RETENTION = Duration.ofHours(1);

    private final JdbcClient jdbc;
    private final SigningKeyStore keys;
    private final int batchSize;
    private final Duration loginAuditRetention;
    private final Duration adminAuditRetention;
    private final Clock clock;

    /**
     * Creates the cleanup.
     * <p>
     * 建立清理。
     *
     * @param jdbc                 the JDBC client of the authorization server
     *                             database
     *                             <br>Authorization Server 資料庫的 JDBC client
     * @param keys                 the signing key store
     *                             <br>簽章金鑰儲存
     * @param batchSize            rows per statement
     *                             <br>每個陳述式的筆數
     * @param loginAuditRetention  how long {@code login_audit} is kept
     *                             <br>{@code login_audit} 的保留期間
     * @param adminAuditRetention  how long {@code admin_audit_log} is kept
     *                             <br>{@code admin_audit_log} 的保留期間
     * @param clock                the clock
     *                             <br>時鐘
     */
    public DataCleanup(JdbcClient jdbc, SigningKeyStore keys, int batchSize, Duration loginAuditRetention,
                       Duration adminAuditRetention, Clock clock) {
        this.jdbc = jdbc;
        this.keys = keys;
        this.batchSize = batchSize;
        this.loginAuditRetention = loginAuditRetention;
        this.adminAuditRetention = adminAuditRetention;
        this.clock = clock;
    }

    /**
     * Deletes authorizations whose tokens have all expired, and
     * authorizations that never got a token and are older than an hour.
     * Their session links go with them.
     * <p>
     * 刪除所有 token 皆已過期的授權，以及從未取得 token 且超過一小時的授權；其
     * Session 連結一併刪除。
     *
     * @return the number of deleted authorizations
     *         <br>刪除的授權數
     */
    public int deleteExpiredAuthorizations() {
        Timestamp now = Timestamp.from(clock.instant());
        // 官方表沒有建立時間：還沒有 token 的授權以 session_authorization.created_at 判斷存在多久。
        // 「所有過期時間都是 NULL」的授權可能正在等使用者同意，不能以第一個條件刪除
        int expired = inBatches(() -> jdbc.sql("""
                        DELETE FROM oauth2_authorization WHERE id IN (
                            SELECT id FROM oauth2_authorization
                            WHERE COALESCE(authorization_code_expires_at, access_token_expires_at,
                                           refresh_token_expires_at, oidc_id_token_expires_at) IS NOT NULL
                              AND (authorization_code_expires_at IS NULL OR authorization_code_expires_at < :now)
                              AND (access_token_expires_at IS NULL OR access_token_expires_at < :now)
                              AND (refresh_token_expires_at IS NULL OR refresh_token_expires_at < :now)
                              AND (oidc_id_token_expires_at IS NULL OR oidc_id_token_expires_at < :now)
                            LIMIT :batch)""")
                .param("now", now).param("batch", batchSize).update());
        Timestamp pendingCutoff = Timestamp.from(clock.instant().minus(PENDING_AUTHORIZATION_RETENTION));
        int pending = inBatches(() -> jdbc.sql("""
                        DELETE FROM oauth2_authorization WHERE id IN (
                            SELECT a.id FROM oauth2_authorization a
                            JOIN session_authorization sa ON sa.authorization_id = a.id
                            WHERE a.authorization_code_value IS NULL AND a.access_token_value IS NULL
                              AND a.refresh_token_value IS NULL AND sa.created_at < :cutoff
                            LIMIT :batch)""")
                .param("cutoff", pendingCutoff).param("batch", batchSize).update());
        return expired + pending;
    }

    /**
     * Deletes rotated refresh tokens past their retention.
     * <p>
     * 刪除超過保留期間的已輪換 Refresh Token。
     *
     * @return the number of deleted rows
     *         <br>刪除的筆數
     */
    public int deleteExpiredRefreshTokenHistory() {
        Timestamp now = Timestamp.from(clock.instant());
        return inBatches(() -> jdbc.sql("""
                        DELETE FROM refresh_token_history WHERE token_hash IN (
                            SELECT token_hash FROM refresh_token_history WHERE expires_at < :now LIMIT :batch)""")
                .param("now", now).param("batch", batchSize).update());
    }

    /**
     * Marks active login sessions past their absolute lifetime as
     * {@code EXPIRED} and deletes their authorizations.
     * <p>
     * 把超過絕對有效期的有效登入 Session 改為 {@code EXPIRED}，並刪除其授權。
     *
     * @return the number of expired sessions
     *         <br>改為過期的 Session 數
     */
    public int expireSessions() {
        Timestamp now = Timestamp.from(clock.instant());
        jdbc.sql("""
                        DELETE FROM oauth2_authorization WHERE id IN (
                            SELECT sa.authorization_id FROM session_authorization sa
                            JOIN auth_session s ON s.session_id = sa.session_id
                            WHERE s.status = 'ACTIVE' AND s.expires_at < :now)""")
                .param("now", now).update();
        return jdbc.sql("UPDATE auth_session SET status = 'EXPIRED' WHERE status = 'ACTIVE' AND expires_at < :now")
                .param("now", now).update();
    }

    /**
     * Deletes revoked and expired login sessions older than 30 days.
     * <p>
     * 刪除已撤銷或已過期超過 30 天的登入 Session。
     *
     * @return the number of deleted sessions
     *         <br>刪除的 Session 數
     */
    public int deleteOldSessions() {
        Timestamp cutoff = Timestamp.from(clock.instant().minus(SESSION_RETENTION));
        return inBatches(() -> jdbc.sql("""
                        DELETE FROM auth_session WHERE session_id IN (
                            SELECT session_id FROM auth_session
                            WHERE (status = 'REVOKED' AND revoked_at < :cutoff)
                               OR (status = 'EXPIRED' AND expires_at < :cutoff)
                            LIMIT :batch)""")
                .param("cutoff", cutoff).param("batch", batchSize).update());
    }

    /**
     * Deletes action tokens that expired more than 7 days ago.
     * <p>
     * 刪除到期超過 7 天的操作 token。
     *
     * @return the number of deleted tokens
     *         <br>刪除的 token 數
     */
    public int deleteOldActionTokens() {
        Timestamp cutoff = Timestamp.from(clock.instant().minus(ACTION_TOKEN_RETENTION));
        return inBatches(() -> jdbc.sql("""
                        DELETE FROM user_action_token WHERE token_hash IN (
                            SELECT token_hash FROM user_action_token WHERE expires_at < :cutoff LIMIT :batch)""")
                .param("cutoff", cutoff).param("batch", batchSize).update());
    }

    /**
     * Deletes audit rows past their retention.
     * <p>
     * 刪除超過保留期間的稽核紀錄。
     *
     * @return the number of deleted rows of both audit tables
     *         <br>兩張稽核表刪除的筆數合計
     */
    public int deleteOldAudits() {
        Timestamp loginCutoff = Timestamp.from(clock.instant().minus(loginAuditRetention));
        Timestamp adminCutoff = Timestamp.from(clock.instant().minus(adminAuditRetention));
        int login = inBatches(() -> jdbc.sql("""
                        DELETE FROM login_audit WHERE id IN (
                            SELECT id FROM login_audit WHERE occurred_at < :cutoff LIMIT :batch)""")
                .param("cutoff", loginCutoff).param("batch", batchSize).update());
        int admin = inBatches(() -> jdbc.sql("""
                        DELETE FROM admin_audit_log WHERE id IN (
                            SELECT id FROM admin_audit_log WHERE occurred_at < :cutoff LIMIT :batch)""")
                .param("cutoff", adminCutoff).param("batch", batchSize).update());
        return login + admin;
    }

    /**
     * Deletes signing keys retired more than a year ago.
     * <p>
     * 刪除退役超過一年的簽章金鑰。
     *
     * @return the number of deleted keys
     *         <br>刪除的金鑰數
     */
    public int deleteOldSigningKeys() {
        return keys.deleteRetiredBefore(clock.instant().minus(RETIRED_KEY_RETENTION));
    }

    /**
     * Runs every cleanup once, for example from an administration task.
     * <p>
     * 執行每一項清理一次，例如供管理工作使用。
     *
     * @return the number of deleted or changed rows per cleanup
     *         <br>每一項清理刪除或變更的筆數
     */
    public Map<String, Integer> runAll() {
        Map<String, Integer> result = new LinkedHashMap<>();
        result.put("authorizations", deleteExpiredAuthorizations());
        result.put("refresh_token_history", deleteExpiredRefreshTokenHistory());
        result.put("expired_sessions", expireSessions());
        result.put("sessions", deleteOldSessions());
        result.put("action_tokens", deleteOldActionTokens());
        result.put("audits", deleteOldAudits());
        result.put("signing_keys", deleteOldSigningKeys());
        return result;
    }

    private int inBatches(IntSupplier batch) {
        int total = 0;
        int deleted;
        do {
            deleted = batch.getAsInt();
            total += deleted;
        } while (deleted >= batchSize);
        return total;
    }
}
