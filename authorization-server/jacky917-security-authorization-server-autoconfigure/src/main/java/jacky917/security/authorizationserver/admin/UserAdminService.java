package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.RevokeReason;
import jacky917.security.authorizationserver.support.Columns;
import jacky917.security.authorizationserver.user.NewUser;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Manages users for the administration API (phase 3 and 4 design §4.2).
 * <p>
 * 為管理 API 管理使用者（第 3、4 階段設計 §4.2）。
 * <p>
 * Every change runs in one transaction together with its
 * {@code admin_audit_log} record. Making a user unable to log in, or setting
 * their password, revokes their login sessions so their refresh tokens stop
 * working. An administrator cannot disable or delete themselves, nor remove
 * their own last role that lets them manage users.
 * <p>
 * 每一項變更都與其 {@code admin_audit_log} 紀錄在同一個交易中完成。讓使用者
 * 無法登入或設定其密碼時，會撤銷其登入 Session，Refresh Token 因此失效。
 * 管理員不能停用或刪除自己，也不能移除自己最後一個可以管理使用者的角色。
 * <p>
 * It works on the default user tables; an application that replaces
 * {@link UserAccountService} with another user store should turn the
 * administration API off or provide its own.
 * <p>
 * 本類別直接操作預設的使用者資料表；以其他使用者來源取代
 * {@code UserAccountService} 的應用程式，應關閉管理 API 或自行提供。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class UserAdminService {

    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s]+");
    private static final String USER_WRITE = "as:user:write";
    private static final String SUMMARY_COLUMNS = "id, username, email, email_verified, display_name, status, "
            + "locked_until, failed_login_count, password_hash IS NOT NULL AS password_set, password_change_required, "
            + "last_login_at, created_at";

    private final JdbcClient jdbc;
    private final UserAccountService users;
    private final AuthSessionService sessions;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final AdminAuditService audit;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc             the JDBC client of the authorization server
     *                         database
     *                         <br>Authorization Server 資料庫的 JDBC client
     * @param users            creates users
     *                         <br>建立使用者
     * @param sessions         revokes login sessions
     *                         <br>撤銷登入 Session
     * @param passwordEncoder  hashes new passwords
     *                         <br>雜湊新密碼
     * @param passwordPolicy   checks new passwords
     *                         <br>檢查新密碼
     * @param audit            records the changes
     *                         <br>記錄變更
     * @param transactions     runs each change in one transaction
     *                         <br>每一項變更在同一個交易中執行
     * @param clock            the clock
     *                         <br>時鐘
     */
    public UserAdminService(JdbcClient jdbc, UserAccountService users, AuthSessionService sessions,
                            PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy, AdminAuditService audit,
                            TransactionOperations transactions, Clock clock) {
        this.jdbc = jdbc;
        this.users = users;
        this.sessions = sessions;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Searches users by username, email or display name.
     * <p>
     * 依帳號、Email 或顯示名稱搜尋使用者。
     *
     * @param query   part of the username, email or display name, ignoring
     *                case, or {@code null} for all
     *                <br>帳號、Email 或顯示名稱的一部分（不分大小寫）；
     *                {@code null} 表示全部
     * @param status  only this status, or {@code null}
     *                <br>只列出此狀態；{@code null} 表示不限
     * @param page    the zero-based page number
     *                <br>頁碼，從 0 開始
     * @param size    the page size
     *                <br>每頁筆數
     * @return the users, newest first
     *         <br>使用者，新的在前
     */
    public PageResult<UserSummary> search(@Nullable String query, @Nullable UserStatus status, int page, int size) {
        PageResult.check(page, size);
        AuditAdminController.Filter filter = new AuditAdminController.Filter()
                .add("(LOWER(username) LIKE :q ESCAPE '\\' OR LOWER(email) LIKE :q ESCAPE '\\' "
                        + "OR LOWER(display_name) LIKE :q ESCAPE '\\')", "q", like(query))
                .add("status = :status", "status", status == null ? null : status.name());
        long total = filter.bind(jdbc.sql("SELECT COUNT(*) FROM app_user" + filter.where())).query(Long.class).single();
        List<UserSummary> items = filter.bind(jdbc.sql("SELECT " + SUMMARY_COLUMNS + " FROM app_user" + filter.where()
                        + " ORDER BY created_at DESC, id DESC LIMIT :size OFFSET :offset"))
                .param("size", size).param("offset", (long) page * size)
                .query(UserAdminService::summary).list();
        return new PageResult<>(items, page, size, total);
    }

    /**
     * Returns a user with their roles and linked accounts.
     * <p>
     * 回傳使用者及其角色與已連結的外部帳號。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the user
     *         <br>使用者
     * @throws AdminApiException {@code 404} if there is no such user
     *         <br>使用者不存在時為 {@code 404}
     */
    public UserDetail find(String userId) {
        UserSummary user = summary(userId);
        List<RoleGrant> roles = jdbc.sql("""
                        SELECT r.code, ur.granted_at, ur.granted_by, ur.expires_at
                        FROM app_user_role ur JOIN app_role r ON r.id = ur.role_id
                        WHERE ur.user_id = :user ORDER BY r.code""")
                .param("user", userId)
                .query((rs, rowNum) -> new RoleGrant(rs.getString("code"), instant(rs, "granted_at"),
                        rs.getString("granted_by"), instant(rs, "expires_at")))
                .list();
        List<LinkedAccount> identities = jdbc.sql("""
                        SELECT provider, provider_subject, email, linked_at, last_login_at
                        FROM user_federated_identity WHERE user_id = :user ORDER BY linked_at""")
                .param("user", userId)
                .query((rs, rowNum) -> new LinkedAccount(rs.getString("provider"), rs.getString("provider_subject"),
                        rs.getString("email"), instant(rs, "linked_at"), instant(rs, "last_login_at")))
                .list();
        return new UserDetail(user, roles, identities);
    }

    /**
     * Creates a user. A password set by an administrator must be changed at
     * the first login unless {@code passwordChangeRequired} is
     * {@code false}.
     * <p>
     * 建立使用者。除非 {@code passwordChangeRequired} 為 {@code false}，管理員
     * 設定的密碼必須在第一次登入時變更。
     *
     * @param request  the new user
     *                 <br>新的使用者
     * @return the created user
     *         <br>建立的使用者
     * @throws AdminApiException {@code 400} if a field is invalid or a role
     *         does not exist; {@code 409} if the username or email is used
     *         <br>欄位無效或角色不存在時為 {@code 400}；帳號或 Email 已被使用
     *         時為 {@code 409}
     */
    public UserDetail create(CreateUserRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (blank(request.username()) && blank(request.email())) {
            errors.put("username", "username or email is required");
        }
        checkEmail(request.email(), errors);
        checkDisplayName(request.displayName(), errors);
        checkPassword(request.password(), errors);
        Set<String> roles = request.roles() == null ? Set.of() : Set.copyOf(request.roles());
        roles.stream().filter(role -> !roleExists(role)).forEach(role -> errors.put("roles", "role " + role
                + " does not exist"));
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        String userId = transactions.execute(status -> {
            UserAccount created;
            try {
                created = users.createUser(new NewUser(trimToNull(request.username()), trimToNull(request.email()),
                        Boolean.TRUE.equals(request.emailVerified()), request.password(),
                        trimToNull(request.displayName()), roles));
            } catch (IllegalArgumentException ex) {
                throw AdminApiException.invalid("username", ex.getMessage());
            }
            boolean changeRequired = request.password() != null
                    && !Boolean.FALSE.equals(request.passwordChangeRequired());
            if (changeRequired) {
                jdbc.sql("UPDATE app_user SET password_change_required = :required WHERE id = :id")
                        .param("required", true).param("id", created.id()).update();
            }
            audit.record("USER_CREATED", AdminAuditTarget.USER, created.id(), null, summary(created.id()));
            return created.id();
        });
        return find(Objects.requireNonNull(userId));
    }

    /**
     * Changes the given fields of a user; fields that are not present stay
     * as they are. Making the user unable to log in revokes their login
     * sessions.
     * <p>
     * 變更使用者的指定欄位；沒有出現的欄位維持不變。讓使用者無法登入時，會撤銷
     * 其登入 Session。
     *
     * @param userId   the user id
     *                 <br>使用者 ID
     * @param changes  any of {@code username}, {@code email},
     *                 {@code emailVerified}, {@code displayName},
     *                 {@code status} ({@code ACTIVE}, {@code LOCKED},
     *                 {@code DISABLED})
     *                 <br>{@code username}、{@code email}、
     *                 {@code emailVerified}、{@code displayName}、
     *                 {@code status}（{@code ACTIVE}、{@code LOCKED}、
     *                 {@code DISABLED}）中的任意欄位
     * @return the updated user
     *         <br>更新後的使用者
     * @throws AdminApiException {@code 400} for an unknown or invalid field,
     *         or a change of the caller's own status; {@code 404} if there is
     *         no such user; {@code 409} if the new username or email belongs
     *         to another user
     *         <br>欄位不明或無效、或變更自己的狀態時為 {@code 400}；使用者
     *         不存在時為 {@code 404}；新的帳號或 Email 屬於其他使用者時為
     *         {@code 409}
     */
    public UserDetail update(String userId, Map<String, Object> changes) {
        Set<String> known = Set.of("username", "email", "emailVerified", "displayName", "status");
        Map<String, String> errors = new LinkedHashMap<>();
        changes.keySet().stream().filter(field -> !known.contains(field))
                .forEach(field -> errors.put(field, "unknown field"));
        UserStatus newStatus = null;
        if (changes.containsKey("status")) {
            newStatus = parseStatus(changes.get("status"), errors);
            if (userId.equals(AdminOperator.current().userId())) {
                errors.put("status", "you cannot change your own status");
            }
        }
        if (changes.containsKey("email")) {
            checkEmail(text(changes.get("email")), errors);
        }
        if (changes.containsKey("displayName")) {
            checkDisplayName(text(changes.get("displayName")), errors);
        }
        if (changes.containsKey("emailVerified") && !(changes.get("emailVerified") instanceof Boolean)) {
            errors.put("emailVerified", "must be true or false");
        }
        if (changes.containsKey("username") && changes.get("username") != null) {
            String username = text(changes.get("username"));
            int length = username == null ? 0 : username.codePointCount(0, username.length());
            if (length < 3 || length > 64 || username.contains("@") || !username.equals(username.strip())) {
                errors.put("username", "must have 3-64 characters, no '@', and no surrounding spaces");
            }
        }
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        UserStatus status = newStatus;
        transactions.executeWithoutResult(tx -> {
            UserSummary before = summary(userId);
            Timestamp now = Timestamp.from(clock.instant());
            if (changes.containsKey("username")) {
                set(userId, "username", trimToNull(text(changes.get("username"))), now);
            }
            if (changes.containsKey("email")) {
                String email = trimToNull(text(changes.get("email")));
                set(userId, "email", email, now);
                // Email 變更且沒有指定驗證狀態時，新的 Email 視為未驗證
                if (!changes.containsKey("emailVerified") && !Objects.equals(email, before.email())) {
                    set(userId, "email_verified", false, now);
                }
            }
            if (changes.containsKey("emailVerified")) {
                set(userId, "email_verified", changes.get("emailVerified"), now);
            }
            if (changes.containsKey("displayName")) {
                set(userId, "display_name", trimToNull(text(changes.get("displayName"))), now);
            }
            if (status != null) {
                set(userId, "status", status.name(), now);
                if (status != UserStatus.ACTIVE) {
                    sessions.revokeAll(userId, RevokeReason.USER_DISABLED, null);
                }
            }
            audit.record("USER_UPDATED", AdminAuditTarget.USER, userId, before, summary(userId));
        });
        return find(userId);
    }

    /**
     * Deletes a user: the status becomes {@code DELETED} and the login
     * sessions are revoked. The row is kept for the audit.
     * <p>
     * 刪除使用者：狀態改為 {@code DELETED}，並撤銷登入 Session。資料列保留供
     * 稽核。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @throws AdminApiException {@code 404} if there is no such user;
     *         {@code 409} for the caller themselves
     *         <br>使用者不存在時為 {@code 404}；刪除自己時為 {@code 409}
     */
    public void delete(String userId) {
        if (userId.equals(AdminOperator.current().userId())) {
            throw AdminApiException.conflict("You cannot delete yourself");
        }
        transactions.executeWithoutResult(tx -> {
            UserSummary before = summary(userId);
            set(userId, "status", UserStatus.DELETED.name(), Timestamp.from(clock.instant()));
            sessions.revokeAll(userId, RevokeReason.USER_DISABLED, null);
            audit.record("USER_DELETED", AdminAuditTarget.USER, userId, before, summary(userId));
        });
    }

    /**
     * Ends a temporary lock after failed logins and resets the failure
     * count.
     * <p>
     * 解除登入失敗造成的暫時鎖定，並將失敗次數歸零。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the updated user
     *         <br>更新後的使用者
     * @throws AdminApiException {@code 404} if there is no such user
     *         <br>使用者不存在時為 {@code 404}
     */
    public UserDetail unlock(String userId) {
        transactions.executeWithoutResult(tx -> {
            UserSummary before = summary(userId);
            jdbc.sql("UPDATE app_user SET locked_until = NULL, failed_login_count = 0, updated_at = :at, "
                            + "row_version = row_version + 1 WHERE id = :id")
                    .param("at", Timestamp.from(clock.instant())).param("id", userId).update();
            audit.record("USER_UNLOCKED", AdminAuditTarget.USER, userId, before, summary(userId));
        });
        return find(userId);
    }

    /**
     * Sets a user's password and revokes their login sessions.
     * <p>
     * 設定使用者的密碼，並撤銷其登入 Session。
     *
     * @param userId          the user id
     *                        <br>使用者 ID
     * @param password        the new password
     *                        <br>新密碼
     * @param changeRequired  whether the user must change it at the next
     *                        login; {@code null} means {@code true}
     *                        <br>下一次登入時是否必須變更；{@code null} 視為
     *                        {@code true}
     * @throws AdminApiException {@code 400} if the password breaks the
     *         policy; {@code 404} if there is no such user
     *         <br>密碼不符合政策時為 {@code 400}；使用者不存在時為 {@code 404}
     */
    public void setPassword(String userId, @Nullable String password, @Nullable Boolean changeRequired) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (password == null) {
            errors.put("password", "required");
        }
        checkPassword(password, errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            UserSummary before = summary(userId);
            Timestamp now = Timestamp.from(clock.instant());
            jdbc.sql("UPDATE app_user SET password_hash = :hash, password_changed_at = :at, "
                            + "password_change_required = :required, locked_until = NULL, failed_login_count = 0, "
                            + "updated_at = :at, row_version = row_version + 1 WHERE id = :id")
                    .param("hash", passwordEncoder.encode(password)).param("at", now)
                    .param("required", !Boolean.FALSE.equals(changeRequired)).param("id", userId).update();
            sessions.revokeAll(userId, RevokeReason.PASSWORD_CHANGED, null);
            audit.record("USER_PASSWORD_SET", AdminAuditTarget.USER, userId, before, summary(userId));
        });
    }

    /**
     * Gives a user a role, or changes when it expires.
     * <p>
     * 指派角色給使用者，或變更其到期時間。
     *
     * @param userId     the user id
     *                   <br>使用者 ID
     * @param role       the role code
     *                   <br>角色代碼
     * @param expiresAt  when the role ends, or {@code null} for never
     *                   <br>角色的到期時間；{@code null} 表示不到期
     * @return the updated user
     *         <br>更新後的使用者
     * @throws AdminApiException {@code 400} if {@code expiresAt} is in the
     *         past; {@code 404} if the user or role does not exist
     *         <br>{@code expiresAt} 已過時為 {@code 400}；使用者或角色不存在
     *         時為 {@code 404}
     */
    public UserDetail assignRole(String userId, String role, @Nullable Instant expiresAt) {
        Instant now = clock.instant();
        if (expiresAt != null && !expiresAt.isAfter(now)) {
            throw AdminApiException.invalid("expiresAt", "must be in the future");
        }
        String roleId = roleId(role);
        transactions.executeWithoutResult(tx -> {
            summary(userId);
            int updated = jdbc.sql("UPDATE app_user_role SET expires_at = :expires WHERE user_id = :user AND role_id = :role")
                    .param("expires", expiresAt == null ? null : Timestamp.from(expiresAt))
                    .param("user", userId).param("role", roleId).update();
            if (updated == 0) {
                jdbc.sql("INSERT INTO app_user_role (user_id, role_id, granted_by, granted_at, expires_at) "
                                + "VALUES (:user, :role, :by, :at, :expires)")
                        .param("user", userId).param("role", roleId)
                        .param("by", AdminOperator.current().userId())
                        .param("at", Timestamp.from(now))
                        .param("expires", expiresAt == null ? null : Timestamp.from(expiresAt))
                        .update();
            }
            audit.record("ROLE_ASSIGNED", AdminAuditTarget.USER, userId, null,
                    Map.of("role", role, "expiresAt", expiresAt == null ? "never" : expiresAt.toString()));
        });
        return find(userId);
    }

    /**
     * Removes a role from a user. Roles take effect at the user's next token
     * request.
     * <p>
     * 移除使用者的角色。角色變更在使用者下一次取得 token 時生效。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @param role    the role code
     *                <br>角色代碼
     * @return the updated user
     *         <br>更新後的使用者
     * @throws AdminApiException {@code 404} if the user or role does not
     *         exist; {@code 409} if it is the caller's last role that lets
     *         them manage users
     *         <br>使用者或角色不存在時為 {@code 404}；這是呼叫者最後一個可以
     *         管理使用者的角色時為 {@code 409}
     */
    public UserDetail removeRole(String userId, String role) {
        String roleId = roleId(role);
        transactions.executeWithoutResult(tx -> {
            summary(userId);
            int removed = jdbc.sql("DELETE FROM app_user_role WHERE user_id = :user AND role_id = :role")
                    .param("user", userId).param("role", roleId).update();
            if (removed > 0 && userId.equals(AdminOperator.current().userId()) && !hasPermission(userId, USER_WRITE)) {
                tx.setRollbackOnly();
                throw AdminApiException.conflict("You cannot remove your own last role with " + USER_WRITE);
            }
            if (removed > 0) {
                audit.record("ROLE_REMOVED", AdminAuditTarget.USER, userId, Map.of("role", role), null);
            }
        });
        return find(userId);
    }

    private boolean hasPermission(String userId, String permission) {
        return jdbc.sql("""
                        SELECT COUNT(*) FROM app_user_role ur
                        JOIN app_role_permission rp ON rp.role_id = ur.role_id
                        JOIN app_permission p ON p.id = rp.permission_id
                        WHERE ur.user_id = :user AND p.code = :permission
                          AND (ur.expires_at IS NULL OR ur.expires_at > :now)""")
                .param("user", userId).param("permission", permission)
                .param("now", Timestamp.from(clock.instant())).query(Integer.class).single() > 0;
    }

    /**
     * Returns the summary of a user.
     * <p>
     * 回傳使用者的摘要。
     *
     * @param userId  the user id
     *                <br>使用者 ID
     * @return the summary
     *         <br>摘要
     * @throws AdminApiException {@code 404} if there is no such user
     *         <br>使用者不存在時為 {@code 404}
     */
    public UserSummary summary(String userId) {
        return jdbc.sql("SELECT " + SUMMARY_COLUMNS + " FROM app_user WHERE id = :id").param("id", userId)
                .query(UserAdminService::summary).optional()
                .orElseThrow(() -> AdminApiException.notFound("User " + userId));
    }

    private void set(String userId, String column, @Nullable Object value, Timestamp now) {
        jdbc.sql("UPDATE app_user SET " + column + " = :value, updated_at = :at, row_version = row_version + 1 "
                        + "WHERE id = :id")
                .param("value", value).param("at", now).param("id", userId).update();
    }

    private boolean roleExists(String role) {
        return jdbc.sql("SELECT COUNT(*) FROM app_role WHERE code = :code").param("code", role)
                .query(Integer.class).single() > 0;
    }

    private String roleId(String role) {
        return jdbc.sql("SELECT id FROM app_role WHERE code = :code").param("code", role).query(String.class)
                .optional().orElseThrow(() -> AdminApiException.notFound("Role " + role));
    }

    private void checkEmail(@Nullable String email, Map<String, String> errors) {
        if (email != null && !email.isBlank() && (email.length() > 255 || !EMAIL.matcher(email.strip()).matches())) {
            errors.put("email", "must be an email address of at most 255 characters");
        }
    }

    private static void checkDisplayName(@Nullable String displayName, Map<String, String> errors) {
        if (displayName != null && displayName.strip().length() > Columns.DISPLAY_NAME) {
            errors.put("displayName", "must be at most " + Columns.DISPLAY_NAME + " characters");
        }
    }

    private void checkPassword(@Nullable String password, Map<String, String> errors) {
        if (password == null) {
            return;
        }
        try {
            passwordPolicy.check(password);
        } catch (IllegalArgumentException ex) {
            errors.put("password", ex.getMessage());
        }
    }

    private static @Nullable UserStatus parseStatus(@Nullable Object value, Map<String, String> errors) {
        String text = value instanceof String string ? string.toUpperCase(Locale.ROOT) : null;
        if (!"ACTIVE".equals(text) && !"LOCKED".equals(text) && !"DISABLED".equals(text)) {
            errors.put("status", "must be ACTIVE, LOCKED or DISABLED");
            return null;
        }
        return UserStatus.valueOf(text);
    }

    private static @Nullable String like(@Nullable String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        String escaped = query.strip().toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%")
                .replace("_", "\\_");
        return "%" + escaped + "%";
    }

    private static @Nullable String text(@Nullable Object value) {
        return value == null ? null : value.toString();
    }

    private static boolean blank(@Nullable String value) {
        return value == null || value.isBlank();
    }

    private static @Nullable String trimToNull(@Nullable String value) {
        return blank(value) ? null : value.strip();
    }

    private static @Nullable Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private static UserSummary summary(ResultSet rs, int rowNum) throws SQLException {
        return new UserSummary(rs.getString("id"), rs.getString("username"), rs.getString("email"),
                rs.getBoolean("email_verified"), rs.getString("display_name"),
                UserStatus.valueOf(rs.getString("status")), instant(rs, "locked_until"),
                rs.getInt("failed_login_count"), rs.getBoolean("password_set"),
                rs.getBoolean("password_change_required"), instant(rs, "last_login_at"),
                Objects.requireNonNull(instant(rs, "created_at")));
    }

    /**
     * A user as listed by the administration API; it never contains the
     * password hash.
     * <p>
     * 管理 API 列出的使用者；不包含密碼雜湊。
     *
     * @param id                      the user id
     *                                <br>使用者 ID
     * @param username                the username, or {@code null}
     *                                <br>帳號，或 {@code null}
     * @param email                   the email, or {@code null}
     *                                <br>Email，或 {@code null}
     * @param emailVerified           whether the email is verified
     *                                <br>Email 是否已驗證
     * @param displayName             the display name, or {@code null}
     *                                <br>顯示名稱，或 {@code null}
     * @param status                  the status
     *                                <br>狀態
     * @param lockedUntil             the end of a temporary lock, or
     *                                {@code null}
     *                                <br>暫時鎖定的結束時間，或 {@code null}
     * @param failedLoginCount        consecutive failed password logins
     *                                <br>連續密碼登入失敗次數
     * @param passwordSet             whether the user has a password
     *                                <br>使用者是否有密碼
     * @param passwordChangeRequired  whether the password must be changed at
     *                                the next login
     *                                <br>下一次登入時是否必須變更密碼
     * @param lastLoginAt             the last login, or {@code null}
     *                                <br>最後登入時間，或 {@code null}
     * @param createdAt               when the user was created
     *                                <br>建立時間
     */
    public record UserSummary(String id, @Nullable String username, @Nullable String email, boolean emailVerified,
                              @Nullable String displayName, UserStatus status, @Nullable Instant lockedUntil,
                              int failedLoginCount, boolean passwordSet, boolean passwordChangeRequired,
                              @Nullable Instant lastLoginAt, Instant createdAt) {
    }

    /**
     * A user with their roles and linked accounts.
     * <p>
     * 使用者及其角色與已連結的外部帳號。
     *
     * @param user        the user
     *                    <br>使用者
     * @param roles       the roles, by code
     *                    <br>角色，依代碼排序
     * @param identities  the linked external accounts, oldest first
     *                    <br>已連結的外部帳號，最早連結的在前
     */
    public record UserDetail(UserSummary user, List<RoleGrant> roles, List<LinkedAccount> identities) {
    }

    /**
     * A role given to a user.
     * <p>
     * 指派給使用者的角色。
     *
     * @param role       the role code
     *                   <br>角色代碼
     * @param grantedAt  when it was given
     *                   <br>指派時間
     * @param grantedBy  who gave it, or {@code null}
     *                   <br>指派者，或 {@code null}
     * @param expiresAt  when it ends, or {@code null} for never
     *                   <br>到期時間；{@code null} 表示不到期
     */
    public record RoleGrant(String role, @Nullable Instant grantedAt, @Nullable String grantedBy,
                            @Nullable Instant expiresAt) {
    }

    /**
     * An external account linked to a user.
     * <p>
     * 連結到使用者的外部帳號。
     *
     * @param provider     the registration id of the provider
     *                     <br>提供者的 registration id
     * @param subject      the account id at the provider
     *                     <br>提供者端的帳號 ID
     * @param email        the email reported by the provider, or
     *                     {@code null}
     *                     <br>提供者回報的 Email，或 {@code null}
     * @param linkedAt     when it was linked
     *                     <br>連結時間
     * @param lastLoginAt  the last login through it, or {@code null}
     *                     <br>最後一次透過它登入的時間，或 {@code null}
     */
    public record LinkedAccount(String provider, String subject, @Nullable String email, @Nullable Instant linkedAt,
                                @Nullable Instant lastLoginAt) {
    }

    /**
     * A user to create.
     * <p>
     * 要建立的使用者。
     *
     * @param username                the username, or {@code null}
     *                                <br>帳號，或 {@code null}
     * @param email                   the email, or {@code null}; one of the
     *                                two is required
     *                                <br>Email，或 {@code null}；兩者至少需要
     *                                一個
     * @param emailVerified           whether the email is already verified;
     *                                {@code null} means {@code false}
     *                                <br>Email 是否已驗證；{@code null} 視為
     *                                {@code false}
     * @param password                the initial password, or {@code null}
     *                                for a user who logs in only through
     *                                identity providers
     *                                <br>初始密碼；只透過身分提供者登入的使用者
     *                                為 {@code null}
     * @param passwordChangeRequired  whether the password must be changed at
     *                                the first login; {@code null} means
     *                                {@code true}
     *                                <br>第一次登入時是否必須變更密碼；
     *                                {@code null} 視為 {@code true}
     * @param displayName             the display name, or {@code null}
     *                                <br>顯示名稱，或 {@code null}
     * @param roles                   the roles besides {@code USER}, or
     *                                {@code null}
     *                                <br>{@code USER} 以外的角色，或
     *                                {@code null}
     */
    public record CreateUserRequest(@Nullable String username, @Nullable String email, @Nullable Boolean emailVerified,
                                    @Nullable String password, @Nullable Boolean passwordChangeRequired,
                                    @Nullable String displayName, @Nullable List<String> roles) {
    }
}
