package jacky917.security.authorizationserver.user;

import jacky917.security.authorizationserver.federation.FederatedUserInfo;
import jacky917.security.authorizationserver.support.Columns;
import jacky917.security.authorizationserver.support.UuidV7;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * {@link UserAccountService} backed by {@code app_user} and the role
 * tables. The SQL is the same on every supported database.
 * <p>
 * 以 {@code app_user} 與角色相關表實作的 {@link UserAccountService}，在所有支援
 * 的資料庫上使用相同的 SQL。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class JdbcUserAccountService implements UserAccountService {

    private static final String COLUMNS = "id, username, email, email_verified, password_hash, display_name, "
            + "avatar_url, locale, status, locked_until, password_changed_at, last_login_at, created_at";

    private static final RowMapper<UserAccount> ROW_MAPPER = (rs, rowNum) -> new UserAccount(
            rs.getString("id"),
            rs.getString("username"),
            rs.getString("email"),
            rs.getBoolean("email_verified"),
            rs.getString("password_hash"),
            rs.getString("display_name"),
            rs.getString("avatar_url"),
            rs.getString("locale"),
            UserStatus.valueOf(rs.getString("status")),
            toInstant(rs.getTimestamp("locked_until")),
            toInstant(rs.getTimestamp("password_changed_at")),
            toInstant(rs.getTimestamp("last_login_at")),
            toInstant(rs.getTimestamp("created_at")));

    private final JdbcClient jdbc;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc             the JDBC client of the authorization server database
     *                         <br>Authorization Server 資料庫的 JDBC client
     * @param passwordEncoder  hashes new passwords
     *                         <br>雜湊新密碼
     * @param passwordPolicy   checks new passwords
     *                         <br>檢查新密碼
     * @param clock            the clock for timestamps
     *                         <br>用於時間戳記的時鐘
     */
    public JdbcUserAccountService(JdbcClient jdbc, PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy,
                                  Clock clock) {
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.clock = clock;
    }

    @Override
    public Optional<UserAccount> findById(String userId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM app_user WHERE id = :id").param("id", userId)
                .query(ROW_MAPPER).optional();
    }

    @Override
    public Optional<UserAccount> findByLogin(String usernameOrEmail) {
        if (!StringUtils.hasText(usernameOrEmail)) {
            return Optional.empty();
        }
        String login = usernameOrEmail.trim();
        // 帳號不可含 "@"，因此含 "@" 的輸入只可能是 Email，兩種查詢不會互相混淆
        if (login.contains("@")) {
            return findByVerifiedEmail(login);
        }
        return jdbc.sql("SELECT " + COLUMNS + " FROM app_user WHERE lower(username) = :login")
                .param("login", login.toLowerCase(Locale.ROOT)).query(ROW_MAPPER).optional();
    }

    @Override
    public Optional<UserAccount> findByVerifiedEmail(String email) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM app_user WHERE lower(email) = :email AND email_verified = :verified")
                .param("email", email.trim().toLowerCase(Locale.ROOT)).param("verified", true)
                .query(ROW_MAPPER).optional();
    }

    @Override
    @Transactional
    public UserAccount createUser(NewUser user) {
        if (user.username() != null) {
            validateUsername(user.username());
        }
        String passwordHash = null;
        if (user.rawPassword() != null) {
            passwordPolicy.check(user.rawPassword());
            passwordHash = passwordEncoder.encode(user.rawPassword());
        }
        Instant now = clock.instant();
        Timestamp at = Timestamp.from(now);
        String id = UuidV7.next(clock);
        jdbc.sql("INSERT INTO app_user (id, username, email, email_verified, password_hash, display_name, status, "
                        + "password_changed_at, created_at, updated_at) VALUES (:id, :username, :email, :verified, "
                        + ":hash, :name, 'ACTIVE', :changed, :at, :at)")
                .param("id", id)
                .param("username", user.username())
                .param("email", user.email())
                .param("verified", user.emailVerified())
                .param("hash", passwordHash)
                .param("name", user.displayName())
                .param("changed", passwordHash == null ? null : at)
                .param("at", at)
                .update();
        Set<String> roles = new LinkedHashSet<>();
        roles.add("USER");
        roles.addAll(user.roles());
        for (String role : roles) {
            int granted = jdbc.sql("INSERT INTO app_user_role (user_id, role_id, granted_at) "
                            + "SELECT :user, id, :at FROM app_role WHERE code = :code")
                    .param("user", id).param("at", at).param("code", role).update();
            if (granted == 0) {
                throw new IllegalArgumentException("Role " + role + " does not exist");
            }
        }
        return findById(id).orElseThrow();
    }

    @Override
    @Transactional
    public UserAccount createFederatedUser(FederatedUserInfo info) {
        Timestamp at = Timestamp.from(clock.instant());
        String id = UuidV7.next(clock);
        boolean storeEmail = info.emailVerified() && StringUtils.hasText(info.email());
        jdbc.sql("INSERT INTO app_user (id, email, email_verified, display_name, avatar_url, locale, status, created_at, "
                        + "updated_at) VALUES (:id, :email, :verified, :name, :avatar, :locale, 'ACTIVE', :at, :at)")
                .param("id", id)
                .param("email", storeEmail ? info.email() : null)
                .param("verified", storeEmail)
                .param("name", Columns.truncate(info.displayName(), Columns.DISPLAY_NAME))
                .param("avatar", Columns.truncate(info.avatarUrl(), Columns.AVATAR_URL))
                .param("locale", Columns.truncate(info.locale(), Columns.LOCALE))
                .param("at", at)
                .update();
        jdbc.sql("INSERT INTO app_user_role (user_id, role_id, granted_at) SELECT :user, id, :at FROM app_role "
                + "WHERE code = 'USER'").param("user", id).param("at", at).update();
        return findById(id).orElseThrow();
    }

    @Override
    public void recordLoginSuccess(String userId, Instant at) {
        Timestamp time = Timestamp.from(at);
        jdbc.sql("UPDATE app_user SET failed_login_count = 0, last_login_at = :at, updated_at = :at, "
                        + "row_version = row_version + 1 WHERE id = :id")
                .param("at", time).param("id", userId).update();
    }

    @Override
    public boolean recordLoginFailure(String userId, Instant at, int maxFailures, Duration lockDuration) {
        // SQLite 只保存到毫秒：先截斷，讀回後才能與寫入的值比較
        Timestamp until = Timestamp.from(at.plus(lockDuration).truncatedTo(ChronoUnit.MILLIS));
        // 單一 UPDATE 完成計數與鎖定，併發的失敗不會互相覆蓋；鎖定時計數歸零，解鎖後重新給予相同的次數
        jdbc.sql("""
                        UPDATE app_user SET
                            locked_until = CASE WHEN failed_login_count + 1 >= :max THEN :until ELSE locked_until END,
                            failed_login_count = CASE WHEN failed_login_count + 1 >= :max THEN 0 ELSE failed_login_count + 1 END,
                            updated_at = :at, row_version = row_version + 1
                        WHERE id = :id""")
                .param("max", maxFailures).param("until", until).param("at", Timestamp.from(at)).param("id", userId)
                .update();
        return findById(userId).map(user -> user.lockedUntil() != null && !user.lockedUntil().isBefore(until.toInstant()))
                .orElse(false);
    }

    @Override
    public void updatePasswordHash(String userId, String passwordHash) {
        jdbc.sql("UPDATE app_user SET password_hash = :hash, updated_at = :at, row_version = row_version + 1 "
                        + "WHERE id = :id")
                .param("hash", passwordHash).param("at", Timestamp.from(clock.instant())).param("id", userId).update();
    }

    @Override
    public UserAuthorities loadAuthorities(String userId) {
        Set<String> roles = new TreeSet<>();
        Set<String> permissions = new TreeSet<>();
        jdbc.sql("""
                        SELECT r.code AS role_code, p.code AS permission_code
                        FROM app_user_role ur
                        JOIN app_role r                  ON r.id = ur.role_id
                        LEFT JOIN app_role_permission rp ON rp.role_id = r.id
                        LEFT JOIN app_permission p       ON p.id = rp.permission_id
                        WHERE ur.user_id = :user AND (ur.expires_at IS NULL OR ur.expires_at > :now)""")
                .param("user", userId).param("now", Timestamp.from(clock.instant()))
                .query(rs -> {
                    roles.add(rs.getString("role_code"));
                    String permission = rs.getString("permission_code");
                    if (permission != null) {
                        permissions.add(permission);
                    }
                });
        return new UserAuthorities(Set.copyOf(roles), Set.copyOf(permissions));
    }

    private static void validateUsername(String username) {
        int length = username.codePointCount(0, username.length());
        if (length < 3 || length > 64 || username.contains("@") || !username.equals(username.strip())) {
            throw new IllegalArgumentException("A username must have 3-64 characters, no '@', and no surrounding spaces");
        }
    }


    private static Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
