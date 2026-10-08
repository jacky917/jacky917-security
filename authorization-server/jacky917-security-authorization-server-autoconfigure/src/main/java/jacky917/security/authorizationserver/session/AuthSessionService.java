package jacky917.security.authorizationserver.session;

import jacky917.security.authorizationserver.support.Columns;
import jacky917.security.authorizationserver.support.UuidV7;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Creates and reads login sessions ({@code auth_session}).
 * <p>
 * 建立與讀取登入 Session（{@code auth_session}）。
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
            rs.getTimestamp("revoked_at") == null ? null : rs.getTimestamp("revoked_at").toInstant());

    private final JdbcClient jdbc;
    private final Duration maxAge;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc    the JDBC client of the authorization server database
     *                <br>Authorization Server 資料庫的 JDBC client
     * @param maxAge  the absolute lifetime of a session
     *                <br>Session 的絕對有效期
     * @param clock   the clock for timestamps
     *                <br>用於時間戳記的時鐘
     */
    public AuthSessionService(JdbcClient jdbc, Duration maxAge, Clock clock) {
        this.jdbc = jdbc;
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
                        + "expires_at, revoked_at FROM auth_session WHERE session_id = :id")
                .param("id", sessionId).query(ROW_MAPPER).optional();
    }

}
