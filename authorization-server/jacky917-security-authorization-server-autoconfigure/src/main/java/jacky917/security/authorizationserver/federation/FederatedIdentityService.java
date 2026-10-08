package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.support.Columns;
import jacky917.security.authorizationserver.support.UuidV7;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Finds, creates and links the users of logins through identity providers
 * (detailed design §5.3).
 * <p>
 * 為透過身分提供者的登入找到、建立與連結使用者（詳細設計 §5.3）。
 * <ul>
 *   <li>A provider account already linked logs in its user, if the user is
 *       active.
 *       <br>已連結的提供者帳號登入其使用者（使用者必須為有效狀態）。</li>
 *   <li>A new provider account whose verified email belongs to an existing
 *       user is never linked automatically (D06): the login is rejected with
 *       {@code LINK_REQUIRED}, so the user can confirm by logging in to the
 *       existing account, or with {@code ACCOUNT_EXISTS} when linking is
 *       allowed only from the account page. Unverified emails are never
 *       matched.
 *       <br>新的提供者帳號若其已驗證的 Email 屬於既有使用者，一律不自動連結
 *       （D06）：以 {@code LINK_REQUIRED} 拒絕，讓使用者登入既有帳號確認連結；
 *       只允許從帳號頁連結時則以 {@code ACCOUNT_EXISTS} 拒絕。未驗證的 Email
 *       一律不比對。</li>
 *   <li>Otherwise a new user is created with the {@code USER} role.
 *       <br>其餘情況建立新使用者，並指派 {@code USER} 角色。</li>
 * </ul>
 * Provider tokens are never stored, and attributes whose names contain
 * {@code token} are removed before the raw attributes are saved.
 * <p>
 * 提供者的 token 一律不儲存；儲存原始屬性前，會移除名稱含 {@code token} 的欄位。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class FederatedIdentityService {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final JdbcClient jdbc;
    private final UserAccountService users;
    private final TransactionTemplate transactions;
    private final boolean confirmLinks;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc          the JDBC client of the authorization server database
     *                      <br>Authorization Server 資料庫的 JDBC client
     * @param users         the user account service
     *                      <br>使用者帳號服務
     * @param transactions  runs each login in one transaction
     *                      <br>每次登入在同一個交易中處理
     * @param confirmLinks  {@code true} to let users confirm a link by
     *                      logging in to the existing account, {@code false}
     *                      to allow links only from the account page
     *                      <br>{@code true} 表示讓使用者登入既有帳號確認連結，
     *                      {@code false} 表示只能從帳號頁連結
     * @param clock         the clock for timestamps
     *                      <br>用於時間戳記的時鐘
     */
    public FederatedIdentityService(JdbcClient jdbc, UserAccountService users, TransactionTemplate transactions,
                                    boolean confirmLinks, Clock clock) {
        this.jdbc = jdbc;
        this.users = users;
        this.transactions = transactions;
        this.confirmLinks = confirmLinks;
        this.clock = clock;
    }

    /**
     * Returns the user for a provider login, creating it on the first
     * login.
     * <p>
     * 回傳提供者登入對應的使用者；第一次登入時建立。
     *
     * @param info  the provider's user
     *              <br>提供者回報的使用者
     * @return the user to log in
     *         <br>要登入的使用者
     * @throws FederatedLoginRejectedException if the login cannot be
     *         accepted
     *         <br>無法接受此登入時
     */
    public UserAccount login(FederatedUserInfo info) {
        try {
            return transactions.execute(status -> loginInTransaction(info));
        } catch (DuplicateKeyException ex) {
            // Email 已被既有帳號使用（例如未驗證的 Email），或另一個請求同時建立了同一個連結
            Optional<String> linked = findLinkedUserId(info);
            if (linked.isPresent()) {
                return transactions.execute(status -> loginInTransaction(info));
            }
            throw new FederatedLoginRejectedException(FederatedLoginRejectedException.Reason.ACCOUNT_EXISTS,
                    "The email of " + info.provider() + " account " + info.subject() + " is already used");
        }
    }

    private UserAccount loginInTransaction(FederatedUserInfo info) {
        Instant now = clock.instant();
        Optional<String> linked = findLinkedUserId(info);
        if (linked.isPresent()) {
            // 暫時鎖定只阻擋密碼登入（DEC-092）
            UserAccount user = users.findById(linked.get()).filter(account -> account.status() == UserStatus.ACTIVE)
                    .orElseThrow(() -> new FederatedLoginRejectedException(
                            FederatedLoginRejectedException.Reason.USER_CANNOT_LOG_IN,
                            "User " + linked.get() + " linked to " + info.provider() + " cannot log in"));
            updateLink(info, now);
            return user;
        }
        Optional<UserAccount> owner = info.emailVerified() && info.email() != null
                ? users.findByVerifiedEmail(info.email()) : Optional.empty();
        if (owner.isPresent()) {
            throw new FederatedLoginRejectedException(confirmLinks
                    ? FederatedLoginRejectedException.Reason.LINK_REQUIRED
                    : FederatedLoginRejectedException.Reason.ACCOUNT_EXISTS, owner.get().id(),
                    "A user with the verified email of " + info.provider() + " account " + info.subject() + " exists");
        }
        UserAccount user = users.createFederatedUser(info);
        insertLink(user.id(), info, now);
        return user;
    }

    /**
     * Links a provider account to an existing user, after the user has
     * proved that they own the user account.
     * <p>
     * 在使用者證明擁有既有帳號之後，把提供者帳號連結到該使用者。
     *
     * @param userId  the existing user
     *                <br>既有使用者
     * @param info    the provider's user
     *                <br>提供者回報的使用者
     * @throws FederatedLoginRejectedException {@code LINKED_TO_ANOTHER_USER}
     *         if the provider account belongs to someone else;
     *         {@code PROVIDER_ALREADY_LINKED} if the user already has another
     *         account of this provider
     *         <br>提供者帳號屬於其他人時為 {@code LINKED_TO_ANOTHER_USER}；使用者已
     *         連結此提供者的另一個帳號時為 {@code PROVIDER_ALREADY_LINKED}
     */
    public void link(String userId, FederatedUserInfo info) {
        transactions.executeWithoutResult(status -> {
            Instant now = clock.instant();
            Optional<String> linked = findLinkedUserId(info);
            if (linked.isPresent()) {
                if (!linked.get().equals(userId)) {
                    throw new FederatedLoginRejectedException(FederatedLoginRejectedException.Reason.LINKED_TO_ANOTHER_USER,
                            info.provider() + " account " + info.subject() + " is linked to another user");
                }
                updateLink(info, now);
                return;
            }
            boolean hasProvider = jdbc.sql("SELECT COUNT(*) FROM user_federated_identity WHERE user_id = :user "
                            + "AND provider = :provider")
                    .param("user", userId).param("provider", info.provider()).query(Integer.class).single() > 0;
            if (hasProvider) {
                throw new FederatedLoginRejectedException(FederatedLoginRejectedException.Reason.PROVIDER_ALREADY_LINKED,
                        "User " + userId + " already has another " + info.provider() + " account linked");
            }
            insertLink(userId, info, now);
        });
    }

    /**
     * Lists the provider accounts linked to a user, oldest first.
     * <p>
     * 列出連結到使用者的提供者帳號，最早連結的在前。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the linked accounts; empty if there is none
     *         <br>已連結的帳號；沒有時為空
     */
    public List<LinkedIdentity> findLinked(String userId) {
        return jdbc.sql("SELECT provider, email, display_name, linked_at, last_login_at FROM user_federated_identity "
                        + "WHERE user_id = :user ORDER BY linked_at, provider")
                .param("user", userId)
                .query((rs, rowNum) -> new LinkedIdentity(rs.getString("provider"), rs.getString("email"),
                        rs.getString("display_name"), rs.getTimestamp("linked_at").toInstant(),
                        rs.getTimestamp("last_login_at") == null ? null : rs.getTimestamp("last_login_at").toInstant()))
                .list();
    }

    /**
     * Removes the link to a provider, unless it is the user's only way to
     * log in.
     * <p>
     * 移除與提供者的連結；若這是使用者唯一的登入方式則不移除。
     *
     * @param userId    the user id
     *                  <br>使用者 ID
     * @param provider  the registration id of the provider
     *                  <br>提供者的 registration id
     * @return {@code true} if the link was removed; {@code false} if it did
     *         not exist or is the only way to log in
     *         <br>已移除時為 {@code true}；連結不存在或是唯一的登入方式時為
     *         {@code false}
     */
    public boolean unlink(String userId, String provider) {
        Boolean removed = transactions.execute(status -> {
            boolean hasPassword = users.findById(userId).map(user -> user.passwordHash() != null).orElse(false);
            int links = jdbc.sql("SELECT COUNT(*) FROM user_federated_identity WHERE user_id = :user")
                    .param("user", userId).query(Integer.class).single();
            if (!hasPassword && links <= 1) {
                return false;
            }
            return jdbc.sql("DELETE FROM user_federated_identity WHERE user_id = :user AND provider = :provider")
                    .param("user", userId).param("provider", provider).update() > 0;
        });
        return Boolean.TRUE.equals(removed);
    }

    private void insertLink(String userId, FederatedUserInfo info, Instant now) {
        jdbc.sql("INSERT INTO user_federated_identity (id, user_id, provider, provider_subject, email, email_verified, "
                        + "display_name, avatar_url, raw_attributes, linked_at, last_login_at) VALUES (:id, :user, "
                        + ":provider, :subject, :email, :verified, :name, :avatar, :raw, :now, :now)")
                .param("id", UuidV7.next(clock))
                .param("user", userId)
                .param("provider", info.provider())
                .param("subject", info.subject())
                .param("email", info.email())
                .param("verified", info.emailVerified())
                .param("name", Columns.truncate(info.displayName(), Columns.DISPLAY_NAME))
                .param("avatar", Columns.truncate(info.avatarUrl(), Columns.AVATAR_URL))
                .param("raw", rawAttributes(info))
                .param("now", Timestamp.from(now))
                .update();
    }

    private Optional<String> findLinkedUserId(FederatedUserInfo info) {
        return jdbc.sql("SELECT user_id FROM user_federated_identity WHERE provider = :provider AND provider_subject = :subject")
                .param("provider", info.provider()).param("subject", info.subject()).query(String.class).optional();
    }

    private void updateLink(FederatedUserInfo info, Instant now) {
        jdbc.sql("UPDATE user_federated_identity SET email = :email, email_verified = :verified, display_name = :name, "
                        + "avatar_url = :avatar, raw_attributes = :raw, last_login_at = :now "
                        + "WHERE provider = :provider AND provider_subject = :subject")
                .param("email", info.email())
                .param("verified", info.emailVerified())
                .param("name", Columns.truncate(info.displayName(), Columns.DISPLAY_NAME))
                .param("avatar", Columns.truncate(info.avatarUrl(), Columns.AVATAR_URL))
                .param("raw", rawAttributes(info))
                .param("now", Timestamp.from(now))
                .param("provider", info.provider())
                .param("subject", info.subject())
                .update();
    }

    private static String rawAttributes(FederatedUserInfo info) {
        Map<String, Object> attributes = new LinkedHashMap<>(info.rawAttributes());
        attributes.keySet().removeIf(name -> name.toLowerCase(Locale.ROOT).contains("token"));
        return JSON.writeValueAsString(attributes);
    }

}
