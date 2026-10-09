package jacky917.security.authorizationserver.account;

import jacky917.security.authorizationserver.support.Hashes;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * One-time tokens of the email links: email verification and password
 * reset ({@code user_action_token}, data model §4.3, phase 3 and 4 design
 * D28).
 * <p>
 * Email 連結的一次性 token：Email 驗證與重設密碼（{@code user_action_token}，
 * 資料模型 §4.3、第 3、4 階段設計 D28）。
 * <ul>
 *   <li>The token is a random value sent only in the email;
 *       {@code user_action_token} stores its SHA-256.
 *       <br>token 是只出現在信件中的隨機值；{@code user_action_token} 只存其
 *       SHA-256。</li>
 *   <li>Issuing a new token marks the user's earlier unused tokens of the
 *       same purpose as used, so only the latest link works.
 *       <br>發出新的 token 時，該使用者同一用途、尚未使用的 token 一律標記為
 *       已使用，只有最新的連結有效。</li>
 *   <li>At most one token per user and purpose is issued every
 *       {@link #COOLDOWN}, which limits how many mails anyone can trigger.
 *       <br>同一使用者、同一用途每 {@code COOLDOWN} 最多發出一個 token，限制
 *       任何人能觸發的信件數量。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ActionTokenService {

    /**
     * The shortest time between two tokens of the same user and purpose.
     * <p>
     * 同一使用者、同一用途兩個 token 之間的最短間隔。
     */
    public static final Duration COOLDOWN = Duration.ofSeconds(60);

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcClient jdbc;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc          the JDBC client of the authorization server database
     *                      <br>Authorization Server 資料庫的 JDBC client
     * @param transactions  replaces the earlier tokens in one transaction
     *                      <br>在同一個交易中取代先前的 token
     * @param clock         the clock
     *                      <br>時鐘
     */
    public ActionTokenService(JdbcClient jdbc, TransactionOperations transactions, Clock clock) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Issues a token, unless one of the same purpose was issued to the user
     * within {@link #COOLDOWN}.
     * <p>
     * 發出 token；若 {@code COOLDOWN} 內已對該使用者發出同一用途的 token，則不
     * 發出。
     *
     * @param userId    the user
     *                  <br>使用者
     * @param purpose   what the token is for
     *                  <br>token 的用途
     * @param validFor  how long the token works
     *                  <br>token 的有效期
     * @return the token to put in the link, or empty during the cooldown
     *         <br>放入連結的 token；在間隔時間內為空
     */
    public Optional<String> issue(String userId, Purpose purpose, Duration validFor) {
        Instant now = clock.instant();
        return transactions.execute(status -> {
            int recent = jdbc.sql("SELECT COUNT(*) FROM user_action_token WHERE user_id = :user AND purpose = :purpose "
                            + "AND created_at > :since")
                    .param("user", userId).param("purpose", purpose.name())
                    .param("since", Timestamp.from(now.minus(COOLDOWN))).query(Integer.class).single();
            if (recent > 0) {
                return Optional.empty();
            }
            jdbc.sql("UPDATE user_action_token SET used_at = :now WHERE user_id = :user AND purpose = :purpose "
                            + "AND used_at IS NULL")
                    .param("now", Timestamp.from(now)).param("user", userId).param("purpose", purpose.name()).update();
            byte[] bytes = new byte[32];
            RANDOM.nextBytes(bytes);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            jdbc.sql("INSERT INTO user_action_token (token_hash, user_id, purpose, expires_at, created_at) "
                            + "VALUES (:hash, :user, :purpose, :expires, :now)")
                    .param("hash", Hashes.sha256Hex(token)).param("user", userId).param("purpose", purpose.name())
                    .param("expires", Timestamp.from(now.plus(validFor))).param("now", Timestamp.from(now)).update();
            return Optional.of(token);
        });
    }

    /**
     * Returns the user of an unused, unexpired token, without using it.
     * <p>
     * 回傳尚未使用且未到期之 token 的使用者，但不使用它。
     *
     * @param token    the token from the link
     *                 <br>連結中的 token
     * @param purpose  what the token must be for
     *                 <br>token 必須符合的用途
     * @return the user id, or empty if the token is unknown, used or
     *         expired
     *         <br>使用者 ID；token 不存在、已使用或已到期時為空
     */
    public Optional<String> find(String token, Purpose purpose) {
        return jdbc.sql("SELECT user_id FROM user_action_token WHERE token_hash = :hash AND purpose = :purpose "
                        + "AND used_at IS NULL AND expires_at > :now")
                .param("hash", Hashes.sha256Hex(token)).param("purpose", purpose.name())
                .param("now", Timestamp.from(clock.instant())).query(String.class).optional();
    }

    /**
     * Uses a token, so it works only once. Call it in the transaction that
     * makes the change the token allows.
     * <p>
     * 使用 token，使其只能使用一次。請在進行 token 所允許之變更的交易中呼叫。
     *
     * @param token    the token from the link
     *                 <br>連結中的 token
     * @param purpose  what the token must be for
     *                 <br>token 必須符合的用途
     * @return the user id, or empty if the token was unknown, used or
     *         expired
     *         <br>使用者 ID；token 不存在、已使用或已到期時為空
     */
    public Optional<String> consume(String token, Purpose purpose) {
        Optional<String> userId = find(token, purpose);
        if (userId.isEmpty()) {
            return userId;
        }
        int used = jdbc.sql("UPDATE user_action_token SET used_at = :now WHERE token_hash = :hash AND purpose = :purpose "
                        + "AND used_at IS NULL AND expires_at > :now")
                .param("now", Timestamp.from(clock.instant())).param("hash", Hashes.sha256Hex(token))
                .param("purpose", purpose.name()).update();
        return used > 0 ? userId : Optional.empty();
    }

    /**
     * What a token is for ({@code user_action_token.purpose}).
     * <p>
     * token 的用途（{@code user_action_token.purpose}）。
     */
    public enum Purpose {

        /**
         * Verifies an email address.
         * <p>
         * 驗證 Email。
         */
        EMAIL_VERIFY,

        /**
         * Sets a new password.
         * <p>
         * 設定新密碼。
         */
        PASSWORD_RESET
    }
}
