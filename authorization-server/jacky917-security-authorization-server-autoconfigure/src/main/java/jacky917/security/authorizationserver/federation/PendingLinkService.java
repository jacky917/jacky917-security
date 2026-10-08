package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.support.Hashes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;
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
import java.util.Objects;
import java.util.Optional;

/**
 * Stores the external logins waiting for the user to confirm a link to an
 * existing account ({@code user_action_token} with purpose
 * {@code LINK_ACCOUNT}, data model §4.3).
 * <p>
 * 保存等待使用者確認連結到既有帳號的第三方登入（{@code user_action_token}，
 * 用途為 {@code LINK_ACCOUNT}，資料模型 §4.3）。
 * <p>
 * The token is a random value kept in the server-side browser session
 * ({@link #SESSION_ATTRIBUTE}), never sent to the browser itself;
 * {@code user_action_token} stores only its SHA-256. When the browser
 * sessions are stored in the database (Spring Session JDBC), the session
 * attributes, and so the plain token, are stored there too until the
 * session ends. A pending link expires after 10 minutes and can be used
 * once. Creating one marks the user's earlier pending links as used.
 * <p>
 * token 是保存在伺服器端瀏覽器 Session（{@code SESSION_ATTRIBUTE}）中的隨機值，
 * 不會送到瀏覽器；{@code user_action_token} 只存其 SHA-256。瀏覽器 Session
 * 存放在資料庫時（Spring Session JDBC），Session 屬性（包含 token 原文）也會
 * 存在資料庫中，直到 Session 結束。待確認的連結 10 分鐘後到期，且只能使用
 * 一次。建立新的連結時，該使用者先前待確認的連結一律標記為已使用。
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

    /**
     * Name of the browser session attribute holding the token of the
     * pending link.
     * <p>
     * 存放待確認連結 token 的瀏覽器 Session 屬性名稱。
     */
    public static final String SESSION_ATTRIBUTE = PendingLinkService.class.getName() + ".TOKEN";

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
     * @return the token to keep in the browser session with
     *         {@link #remember}
     *         <br>以 {@code remember} 保存在瀏覽器 Session 中的 token
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
     * Keeps the token of a pending link in the browser session, replacing
     * any earlier one.
     * <p>
     * 把待確認連結的 token 保存在瀏覽器 Session 中，取代先前的 token。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @param token    the token from {@link #create}
     *                 <br>由 {@code create} 回傳的 token
     */
    public static void remember(HttpServletRequest request, String token) {
        request.getSession().setAttribute(SESSION_ATTRIBUTE, token);
    }

    /**
     * Removes the token of a pending link from the browser session.
     * <p>
     * 從瀏覽器 Session 移除待確認連結的 token。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @return the removed token, or {@code null} if there was none
     *         <br>被移除的 token；沒有時為 {@code null}
     */
    public static @Nullable String forget(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object token = session.getAttribute(SESSION_ATTRIBUTE);
        session.removeAttribute(SESSION_ATTRIBUTE);
        return token instanceof String value ? value : null;
    }

    /**
     * Finds the unused, unexpired pending link whose token is in the
     * browser session.
     * <p>
     * 查詢 token 位於瀏覽器 Session 中、尚未使用且未到期的待確認連結。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @return the pending link, or empty if there is none or it expired
     *         <br>待確認的連結；沒有或已到期時為空
     */
    public Optional<PendingLink> find(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(SESSION_ATTRIBUTE) instanceof String token
                ? find(token) : Optional.empty();
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
                .query((rs, rowNum) -> new PendingLink(token, rs.getString("user_id"), info(rs.getString("payload"))))
                .optional();
    }

    /**
     * Uses a pending link and links it in the same transaction, so the link
     * is used only if linking succeeds.
     * <p>
     * 在同一個交易中使用待確認的連結並建立連結，因此只有連結成功時才會用掉它。
     *
     * @param pending  the pending link
     *                 <br>待確認的連結
     * @param linking  links the external account; any exception it throws
     *                 leaves the pending link unused and is rethrown
     *                 <br>連結外部帳號；它拋出的例外會讓待確認的連結維持未使用，
     *                 並重新拋出
     * @return {@code true} if the pending link was still usable and was
     *         linked; {@code false} if it had already been used or expired
     *         <br>待確認的連結仍可使用且已連結時為 {@code true}；已被使用或已
     *         到期時為 {@code false}
     */
    public boolean confirm(PendingLink pending, Runnable linking) {
        Boolean confirmed = transactions.execute(status -> {
            if (!consume(pending.token())) {
                return false;
            }
            linking.run();
            return true;
        });
        return Boolean.TRUE.equals(confirmed);
    }

    private boolean consume(String token) {
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
        String provider = Objects.requireNonNull((String) values.get("provider"), "provider");
        String subject = Objects.requireNonNull((String) values.get("provider_subject"), "provider_subject");
        return new FederatedUserInfo(provider, subject,
                (String) values.get("email"), Boolean.TRUE.equals(values.get("email_verified")),
                (String) values.get("display_name"), (String) values.get("avatar_url"), (String) values.get("locale"),
                raw);
    }

    /**
     * An external login waiting to be linked.
     * <p>
     * 等待連結的第三方登入。
     *
     * @param token   the token that identifies it
     *                <br>識別它的 token
     * @param userId  the existing user it will be linked to
     *                <br>將連結到的既有使用者
     * @param info    the provider's user
     *                <br>提供者回報的使用者
     */
    public record PendingLink(String token, String userId, FederatedUserInfo info) {
    }
}
