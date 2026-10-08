package jacky917.security.authorizationserver.refresh;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Reads and writes {@code refresh_token_history}, the rotated refresh
 * tokens kept to detect reuse (data model §7.4).
 * <p>
 * 讀寫 {@code refresh_token_history}：為了偵測重用而保留的已輪換 Refresh
 * Token（資料模型 §7.4）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class RefreshTokenHistoryRepository {

    private static final RowMapper<RotatedRefreshToken> ROW_MAPPER = (rs, rowNum) -> new RotatedRefreshToken(
            rs.getString("token_hash"),
            rs.getString("authorization_id"),
            rs.getString("session_id"),
            rs.getString("user_id"),
            rs.getString("registered_client_id"),
            rs.getTimestamp("issued_at").toInstant(),
            rs.getTimestamp("rotated_at").toInstant(),
            rs.getTimestamp("expires_at").toInstant());

    private final JdbcClient jdbc;

    /**
     * Creates the repository.
     * <p>
     * 建立 repository。
     *
     * @param jdbc  the JDBC client of the authorization server database
     *              <br>Authorization Server 資料庫的 JDBC client
     */
    public RefreshTokenHistoryRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Returns the SHA-256 of a token as lowercase hex, the form stored in
     * {@code token_hash}.
     * <p>
     * 回傳 token 的 SHA-256（小寫十六進位），即 {@code token_hash} 中儲存的
     * 格式。
     *
     * @param token  the token value
     *               <br>token 值
     * @return 64 hex characters
     *         <br>64 個十六進位字元
     */
    public static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    /**
     * Stores a rotated token. A token that is already stored is kept as
     * is.
     * <p>
     * 儲存已輪換的 token。已存在的紀錄維持不變。
     *
     * @param token  the rotated token
     *               <br>已輪換的 token
     */
    public void save(RotatedRefreshToken token) {
        jdbc.sql("""
                        INSERT INTO refresh_token_history (token_hash, authorization_id, session_id, user_id,
                            registered_client_id, issued_at, rotated_at, expires_at)
                        VALUES (:hash, :authorization, :session, :user, :client, :issued, :rotated, :expires)
                        ON CONFLICT (token_hash) DO NOTHING""")
                .param("hash", token.tokenHash())
                .param("authorization", token.authorizationId())
                .param("session", token.sessionId())
                .param("user", token.userId())
                .param("client", token.registeredClientId())
                .param("issued", Timestamp.from(token.issuedAt()))
                .param("rotated", Timestamp.from(token.rotatedAt()))
                .param("expires", Timestamp.from(token.expiresAt()))
                .update();
    }

    /**
     * Finds a rotated token that is still remembered.
     * <p>
     * 查詢仍在保留期內的已輪換 token。
     *
     * @param tokenHash  the token hash from {@link #hash(String)}
     *                   <br>由 {@code hash(String)} 產生的雜湊
     * @param now        the current time; records that expired before it
     *                   are ignored
     *                   <br>目前時間；在此之前到期的紀錄視為不存在
     * @return the rotated token, or empty
     *         <br>已輪換的 token；不存在時為空
     */
    public Optional<RotatedRefreshToken> find(String tokenHash, Instant now) {
        return jdbc.sql("SELECT token_hash, authorization_id, session_id, user_id, registered_client_id, issued_at, "
                        + "rotated_at, expires_at FROM refresh_token_history WHERE token_hash = :hash AND expires_at > :now")
                .param("hash", tokenHash).param("now", Timestamp.from(now)).query(ROW_MAPPER).optional();
    }
}
