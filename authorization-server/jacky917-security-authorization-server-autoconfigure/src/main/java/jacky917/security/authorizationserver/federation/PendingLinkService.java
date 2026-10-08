package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.support.Hashes;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Stores the external logins waiting for the user to confirm a link to an
 * existing account ({@code user_action_token} with purpose
 * {@code LINK_ACCOUNT}, data model §4.3).
 * <p>
 * 保存等待使用者確認連結到既有帳號的第三方登入（{@code user_action_token}，
 * 用途為 {@code LINK_ACCOUNT}，資料模型 §4.3）。
 * <p>
 * The token is a random value given to the browser; the database stores
 * only its SHA-256. A pending link expires after 10 minutes and can be used
 * once. Creating one marks the user's earlier pending links as used.
 * <p>
 * token 是交給瀏覽器的隨機值，資料庫只存其 SHA-256。待確認的連結 10 分鐘後
 * 到期，且只能使用一次。建立新的連結時，該使用者先前待確認的連結一律標記為
 * 已使用。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class PendingLinkService {

    /**
     * How long a pending link can be confirmed.
     * <p>
     * 待確認的連結可以確認的期限。
     */
    public static final Duration LIFETIME = Duration.ofMinutes(10);

    private static final JsonMapper JSON = JsonMapper.builder().build();
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
     * @param transactions  replaces the earlier pending links in one
     *                      transaction
     *                      <br>在同一個交易中取代先前待確認的連結
     * @param clock         the clock
     *                      <br>時鐘
     */
    public PendingLinkService(JdbcClient jdbc, TransactionOperations transactions, Clock clock) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Stores an external login waiting to be linked to a user.
     * <p>
     * 保存等待連結到使用者的第三方登入。
     *
     * @param userId  the existing user
     *                <br>既有使用者
     * @param info    the provider's user
     *                <br>提供者回報的使用者
     * @return the token to keep in the browser session
     *         <br>保存在瀏覽器 Session 中的 token
     */
    public String create(String userId, FederatedUserInfo info) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Instant now = clock.instant();
        transactions.executeWithoutResult(status -> {
            jdbc.sql("UPDATE user_action_token SET used_at = :now WHERE user_id = :user AND purpose = 'LINK_ACCOUNT' "
                            + "AND used_at IS NULL")
                    .param("now", Timestamp.from(now)).param("user", userId).update();
            jdbc.sql("INSERT INTO user_action_token (token_hash, user_id, purpose, payload, expires_at, created_at) "
                            + "VALUES (:hash, :user, 'LINK_ACCOUNT', :payload, :expires, :now)")
                    .param("hash", Hashes.sha256Hex(token))
                    .param("user", userId)
                    .param("payload", JSON.writeValueAsString(payload(info)))
                    .param("expires", Timestamp.from(now.plus(LIFETIME)))
                    .param("now", Timestamp.from(now))
                    .update();
        });
        return token;
    }

    /**
     * Finds an unused, unexpired pending link.
     * <p>
     * 查詢尚未使用且未到期的待確認連結。
     *
     * @param token  the token from {@link #create}
     *               <br>由 {@code create} 回傳的 token
     * @return the pending link, or empty
     *         <br>待確認的連結；不存在時為空
     */
    public Optional<PendingLink> find(String token) {
        return jdbc.sql("SELECT user_id, payload FROM user_action_token WHERE token_hash = :hash "
                        + "AND purpose = 'LINK_ACCOUNT' AND used_at IS NULL AND expires_at > :now")
                .param("hash", Hashes.sha256Hex(token))
                .param("now", Timestamp.from(clock.instant()))
                .query((rs, rowNum) -> new PendingLink(rs.getString("user_id"), info(rs.getString("payload"))))
                .optional();
    }

    /**
     * Marks a pending link as used, so it can be confirmed only once.
     * <p>
     * 把待確認的連結標記為已使用，使其只能確認一次。
     *
     * @param token  the token from {@link #create}
     *               <br>由 {@code create} 回傳的 token
     * @return {@code true} if it was unused and unexpired
     *         <br>原本尚未使用且未到期時為 {@code true}
     */
    public boolean consume(String token) {
        Instant now = clock.instant();
        return jdbc.sql("UPDATE user_action_token SET used_at = :now WHERE token_hash = :hash "
                        + "AND purpose = 'LINK_ACCOUNT' AND used_at IS NULL AND expires_at > :now")
                .param("now", Timestamp.from(now))
                .param("hash", Hashes.sha256Hex(token))
                .update() > 0;
    }

    private static Map<String, Object> payload(FederatedUserInfo info) {
        Map<String, Object> raw = new LinkedHashMap<>(info.rawAttributes());
        raw.keySet().removeIf(name -> name.toLowerCase(Locale.ROOT).contains("token"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("provider", info.provider());
        payload.put("provider_subject", info.subject());
        payload.put("email", info.email());
        payload.put("email_verified", info.emailVerified());
        payload.put("display_name", info.displayName());
        payload.put("avatar_url", info.avatarUrl());
        payload.put("locale", info.locale());
        payload.put("raw_attributes", raw);
        return payload;
    }

    private static FederatedUserInfo info(String payload) {
        Map<String, Object> values = JSON.readValue(payload, new TypeReference<Map<String, Object>>() { });
        @SuppressWarnings("unchecked")
        Map<String, Object> raw = (Map<String, Object>) values.getOrDefault("raw_attributes", Map.of());
        return new FederatedUserInfo((String) values.get("provider"), (String) values.get("provider_subject"),
                (String) values.get("email"), Boolean.TRUE.equals(values.get("email_verified")),
                (String) values.get("display_name"), (String) values.get("avatar_url"), (String) values.get("locale"),
                raw);
    }

    /**
     * An external login waiting to be linked.
     * <p>
     * 等待連結的第三方登入。
     *
     * @param userId  the existing user it will be linked to
     *                <br>將連結到的既有使用者
     * @param info    the provider's user
     *                <br>提供者回報的使用者
     */
    public record PendingLink(String userId, FederatedUserInfo info) {
    }
}
