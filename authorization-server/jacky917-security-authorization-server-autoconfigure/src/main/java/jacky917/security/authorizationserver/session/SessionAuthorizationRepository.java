package jacky917.security.authorizationserver.session;

import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * Reads and writes {@code session_authorization}, the link between an
 * OAuth2 authorization and the login session it came from.
 * <p>
 * 讀寫 {@code session_authorization}：OAuth2 授權與其來源登入 Session 之間的
 * 連結。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class SessionAuthorizationRepository {

    private final JdbcClient jdbc;

    /**
     * Creates the repository.
     * <p>
     * 建立 repository。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public SessionAuthorizationRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Returns the login session an authorization belongs to.
     * <p>
     * 回傳授權所屬的登入 Session。
     *
     * @param authorizationId  the {@code oauth2_authorization.id}
     *                         <br>{@code oauth2_authorization.id}
     * @return the session id ({@code asid}), or empty if not linked
     *         <br>Session ID（{@code asid}）；沒有連結時為空
     */
    public Optional<String> findSessionId(String authorizationId) {
        return jdbc.sql("SELECT session_id FROM session_authorization WHERE authorization_id = :id")
                .param("id", authorizationId).query(String.class).optional();
    }

    /**
     * Links an authorization to a login session, only if the session is
     * active, not expired, and belongs to the given user. An existing link
     * is kept.
     * <p>
     * 將授權連結到登入 Session；只有 Session 為 {@code ACTIVE}、尚未到期且屬於
     * 指定使用者時才會建立。已存在的連結維持不變。
     *
     * @param authorizationId     the {@code oauth2_authorization.id}
     *                            <br>{@code oauth2_authorization.id}
     * @param sessionId           the login session id
     *                            <br>登入 Session ID
     * @param userId              the user the authorization is for
     *                            <br>授權所屬的使用者
     * @param registeredClientId  the client of the authorization
     *                            <br>授權所屬的 client
     * @param now                 the current time
     *                            <br>目前時間
     * @return {@code true} if the link exists afterwards
     *         <br>結束時連結存在則為 {@code true}
     */
    public boolean link(String authorizationId, String sessionId, String userId, String registeredClientId,
                        Instant now) {
        // INSERT ... SELECT 必須帶 WHERE，SQLite 才能正確解析後面的 ON CONFLICT；兩種資料庫使用相同的 SQL
        jdbc.sql("""
                        INSERT INTO session_authorization (authorization_id, session_id, registered_client_id, created_at)
                        SELECT :authorization, session_id, :client, :now FROM auth_session
                        WHERE session_id = :session AND user_id = :user AND status = 'ACTIVE' AND expires_at > :now
                        ON CONFLICT (authorization_id) DO NOTHING""")
                .param("authorization", authorizationId)
                .param("client", registeredClientId)
                .param("now", Timestamp.from(now))
                .param("session", sessionId)
                .param("user", userId)
                .update();
        return findSessionId(authorizationId).isPresent();
    }
}
