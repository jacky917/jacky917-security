package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.support.Columns;
import jacky917.security.authorizationserver.support.UuidV7;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Finds or creates the user for a login through an identity provider
 * (detailed design §5.3, without the account linking confirmation).
 * <p>
 * 為透過身分提供者的登入找到或建立使用者（詳細設計 §5.3，不含帳號連結確認）。
 * <ul>
 *   <li>A provider account already linked logs in its user, if the user can
 *       log in.
 *       <br>已連結的提供者帳號登入其使用者（使用者必須可以登入）。</li>
 *   <li>A new provider account whose verified email belongs to an existing
 *       user is rejected: linking requires proof of the existing account,
 *       which a later version adds. Unverified emails are never matched.
 *       <br>新的提供者帳號若其已驗證的 Email 屬於既有使用者，一律拒絕：連結
 *       需要證明擁有既有帳號，此功能於之後的版本加入。未驗證的 Email 一律
 *       不比對。</li>
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
     * @param clock         the clock for timestamps
     *                      <br>用於時間戳記的時鐘
     */
    public FederatedIdentityService(JdbcClient jdbc, UserAccountService users, TransactionTemplate transactions,
                                    Clock clock) {
        this.jdbc = jdbc;
        this.users = users;
        this.transactions = transactions;
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
            UserAccount user = users.findById(linked.get()).filter(account -> account.canLogIn(now))
                    .orElseThrow(() -> new FederatedLoginRejectedException(
                            FederatedLoginRejectedException.Reason.USER_CANNOT_LOG_IN,
                            "User " + linked.get() + " linked to " + info.provider() + " cannot log in"));
            updateLink(info, now);
            return user;
        }
        if (info.emailVerified() && info.email() != null && users.findByVerifiedEmail(info.email()).isPresent()) {
            throw new FederatedLoginRejectedException(FederatedLoginRejectedException.Reason.ACCOUNT_EXISTS,
                    "A user with the verified email of " + info.provider() + " account " + info.subject() + " exists");
        }
        UserAccount user = users.createFederatedUser(info);
        jdbc.sql("INSERT INTO user_federated_identity (id, user_id, provider, provider_subject, email, email_verified, "
                        + "display_name, avatar_url, raw_attributes, linked_at, last_login_at) VALUES (:id, :user, "
                        + ":provider, :subject, :email, :verified, :name, :avatar, :raw, :now, :now)")
                .param("id", UuidV7.next(clock))
                .param("user", user.id())
                .param("provider", info.provider())
                .param("subject", info.subject())
                .param("email", info.email())
                .param("verified", info.emailVerified())
                .param("name", Columns.truncate(info.displayName(), Columns.DISPLAY_NAME))
                .param("avatar", Columns.truncate(info.avatarUrl(), Columns.AVATAR_URL))
                .param("raw", rawAttributes(info))
                .param("now", Timestamp.from(now))
                .update();
        return user;
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
