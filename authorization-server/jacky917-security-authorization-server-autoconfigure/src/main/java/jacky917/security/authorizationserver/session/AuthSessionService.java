package jacky917.security.authorizationserver.session;

import jacky917.security.authorizationserver.support.Columns;
import jacky917.security.authorizationserver.support.UuidV7;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Creates, reads and revokes login sessions ({@code auth_session}).
 * <p>
 * 建立、讀取與撤銷登入 Session（{@code auth_session}）。
 * <p>
 * Revoking a session also deletes every authorization issued from it in the
 * same transaction, so its refresh tokens stop working at once (data model
 * §10.2). Access tokens already issued stay valid until they expire.
 * <p>
 * 撤銷 Session 時，在同一個交易中刪除由它簽發的所有授權，Refresh Token 因此
 * 立即失效（資料模型 §10.2）。已簽發的 Access Token 仍有效至到期。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class AuthSessionService {

    /**
     * HTTP session attribute that holds the login session id ({@code asid})
     * of the authorization server's own browser session.
     * <p>
     * Authorization Server 自己的瀏覽器 Session 中，存放登入 Session ID
     * （{@code asid}）的屬性名稱。
     */
    public static final String SESSION_ATTRIBUTE = AuthSessionService.class.getName() + ".ASID";

    private static final RowMapper<AuthSession> ROW_MAPPER = (rs, rowNum) -> new AuthSession(
            rs.getString("session_id"),
            rs.getString("user_id"),
            AuthSessionStatus.valueOf(rs.getString("status")),
            LoginMethod.valueOf(rs.getString("login_method")),
            rs.getString("idp"),
            rs.getString("amr"),
            rs.getTimestamp("created_at").toInstant(),
            rs.getTimestamp("last_seen_at").toInstant(),
            rs.getTimestamp("expires_at").toInstant(),
            rs.getTimestamp("revoked_at") == null ? null : rs.getTimestamp("revoked_at").toInstant(),
            rs.getString("ip_address"),
            rs.getString("user_agent"));

    private final JdbcClient jdbc;
    private final TransactionOperations transactions;
    private final Duration maxAge;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc          the JDBC client of the authorization server database
     *                      <br>Authorization Server 資料庫的 JDBC client
     * @param transactions  revokes a session and deletes its authorizations
     *                      together
     *                      <br>在同一個交易中撤銷 Session 並刪除其授權
     * @param maxAge        the absolute lifetime of a session
     *                      <br>Session 的絕對有效期
     * @param clock         the clock for timestamps
     *                      <br>用於時間戳記的時鐘
     */
    public AuthSessionService(JdbcClient jdbc, TransactionOperations transactions, Duration maxAge, Clock clock) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.maxAge = maxAge;
        this.clock = clock;
    }

    /**
     * Creates an active session for a successful login.
     * <p>
     * 為成功的登入建立 Session。
     *
     * @param userId     the user id
     *                   <br>使用者 ID
     * @param method     how the user logged in
     *                   <br>登入方式
     * @param idp        the identity provider, {@code local} for passwords
     *                   <br>身分提供者；密碼登入為 {@code local}
     * @param amr        authentication methods, for example {@code pwd}
     *                   <br>驗證方式，例如 {@code pwd}
     * @param ipAddress  the client IP address, or {@code null}
     *                   <br>用戶端 IP，或 {@code null}
     * @param userAgent  the browser user agent, or {@code null}
     *                   <br>瀏覽器 User-Agent，或 {@code null}
     * @return the new session
     *         <br>新的 Session
     */
    public AuthSession create(String userId, LoginMethod method, String idp, String amr,
                              @Nullable String ipAddress, @Nullable String userAgent) {
        Instant now = clock.instant();
        String sessionId = UuidV7.next(clock);
        jdbc.sql("INSERT INTO auth_session (session_id, user_id, status, login_method, idp, amr, ip_address, user_agent, "
                        + "created_at, last_seen_at, expires_at) VALUES (:id, :user, 'ACTIVE', :method, :idp, :amr, :ip, "
                        + ":agent, :now, :now, :expires)")
                .param("id", sessionId)
                .param("user", userId)
                .param("method", method.name())
                .param("idp", idp)
                .param("amr", amr)
                .param("ip", Columns.truncate(ipAddress, Columns.IP_ADDRESS))
                .param("agent", Columns.truncate(userAgent, Columns.USER_AGENT))
                .param("now", Timestamp.from(now))
                .param("expires", Timestamp.from(now.plus(maxAge)))
                .update();
        return find(sessionId).orElseThrow();
    }

    /**
     * Finds a session.
     * <p>
     * 查詢 Session。
     *
     * @param sessionId  the session id
     *                   <br>Session ID
     * @return the session, or empty
     *         <br>Session；不存在時為空
     */
    public Optional<AuthSession> find(String sessionId) {
        return jdbc.sql("SELECT session_id, user_id, status, login_method, idp, amr, created_at, last_seen_at, "
                        + "expires_at, revoked_at, ip_address, user_agent FROM auth_session WHERE session_id = :id")
                .param("id", sessionId).query(ROW_MAPPER).optional();
    }

    /**
     * Records that the session was just used, for the device list.
     * <p>
     * 記錄 Session 剛被使用，供裝置清單顯示。
     *
     * @param sessionId  the session id
     *                   <br>Session ID
     */
    public void touch(String sessionId) {
        jdbc.sql("UPDATE auth_session SET last_seen_at = :now WHERE session_id = :id AND status = 'ACTIVE'")
                .param("now", Timestamp.from(clock.instant())).param("id", sessionId).update();
    }

    /**
     * Revokes an active session and deletes every authorization issued from
     * it (data model §11.4). Does nothing if the session is not active.
     * <p>
     * 撤銷有效的 Session，並刪除由它簽發的所有授權（資料模型 §11.4）。Session
     * 不是 {@code ACTIVE} 時不做任何事。
     *
     * @param sessionId  the session id
     *                   <br>Session ID
     * @param reason     why it is revoked
     *                   <br>撤銷原因
     * @return {@code true} if the session was active and is now revoked
     *         <br>Session 原本有效且已被撤銷時為 {@code true}
     */
    public boolean revoke(String sessionId, RevokeReason reason) {
        Boolean revoked = transactions.execute(status -> {
            int updated = jdbc.sql("UPDATE auth_session SET status = 'REVOKED', revoked_at = :now, revoke_reason = :reason "
                            + "WHERE session_id = :id AND status = 'ACTIVE'")
                    .param("now", Timestamp.from(clock.instant()))
                    .param("reason", reason.name())
                    .param("id", sessionId)
                    .update();
            // session_authorization 由外鍵 ON DELETE CASCADE 一併刪除
            jdbc.sql("DELETE FROM oauth2_authorization WHERE id IN "
                            + "(SELECT authorization_id FROM session_authorization WHERE session_id = :id)")
                    .param("id", sessionId).update();
            return updated > 0;
        });
        return Boolean.TRUE.equals(revoked);
    }

    /**
     * Revokes every active session of a user, optionally keeping one, and
     * deletes their authorizations (data model §11.5).
     * <p>
     * 撤銷使用者所有有效的 Session（可保留其中一個），並刪除它們的授權（資料模型
     * §11.5）。
     *
     * @param userId           the user id
     *                         <br>使用者 ID
     * @param reason           why they are revoked
     *                         <br>撤銷原因
     * @param keepSessionId    the session to keep, for example the one that
     *                         changed the password, or {@code null} to revoke
     *                         all
     *                         <br>要保留的 Session（例如變更密碼的那一個）；
     *                         {@code null} 表示全部撤銷
     * @return the ids of the revoked sessions
     *         <br>被撤銷的 Session ID
     */
    public List<String> revokeAll(String userId, RevokeReason reason, @Nullable String keepSessionId) {
        List<String> revoked = transactions.execute(status -> {
            List<String> ids = jdbc.sql("SELECT session_id FROM auth_session WHERE user_id = :user AND status = 'ACTIVE'")
                    .param("user", userId).query(String.class).list().stream()
                    .filter(id -> !id.equals(keepSessionId)).toList();
            ids.forEach(id -> revoke(id, reason));
            return ids;
        });
        return revoked == null ? List.of() : revoked;
    }

    /**
     * Lists the active sessions of a user, most recently used first (data
     * model §11.6).
     * <p>
     * 列出使用者有效的 Session，最近使用的在前（資料模型 §11.6）。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the active, unexpired sessions; empty if there is none
     *         <br>有效且未到期的 Session；沒有時為空
     */
    public List<AuthSession> findActive(String userId) {
        return jdbc.sql("SELECT session_id, user_id, status, login_method, idp, amr, created_at, last_seen_at, "
                        + "expires_at, revoked_at, ip_address, user_agent FROM auth_session WHERE user_id = :user AND status = 'ACTIVE' "
                        + "AND expires_at > :now ORDER BY last_seen_at DESC")
                .param("user", userId).param("now", Timestamp.from(clock.instant())).query(ROW_MAPPER).list();
    }
}
