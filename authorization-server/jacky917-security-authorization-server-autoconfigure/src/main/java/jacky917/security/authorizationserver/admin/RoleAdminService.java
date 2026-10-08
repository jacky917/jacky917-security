package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.support.UuidV7;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Manages roles and permissions for the administration API (phase 3 and 4
 * design §4.2, data model §5).
 * <p>
 * 為管理 API 管理角色與權限（第 3、4 階段設計 §4.2、資料模型 §5）。
 * <ul>
 *   <li>Codes follow data model §5.1: roles are upper case
 *       ({@code CONTENT_MANAGER}), permissions are lower case
 *       {@code resource:action} ({@code order:read}). Permissions starting
 *       with {@code as:} belong to the authorization server and cannot be
 *       created.
 *       <br>代碼依資料模型 §5.1：角色為大寫（{@code CONTENT_MANAGER}），權限為
 *       小寫的「資源:動作」（{@code order:read}）。以 {@code as:} 開頭的
 *       權限屬於 Authorization Server，不能新增。</li>
 *   <li>Built-in roles and permissions keep their codes and cannot be
 *       deleted. The permissions of {@code AS_ADMIN} cannot change
 *       ({@code 409}); other roles, built-in ones included, can change their
 *       name, description and permissions.
 *       <br>內建的角色與權限不能改代碼、不能刪除。{@code AS_ADMIN} 的權限不能
 *       變更（{@code 409}）；其他角色（包含內建角色）可以變更名稱、說明與
 *       權限。</li>
 *   <li>A role that users still have, or a permission that a role or scope
 *       still uses, cannot be deleted.
 *       <br>仍有使用者的角色、仍被角色或 scope 使用的權限不能刪除。</li>
 * </ul>
 * Changes take effect at each user's next token request (D18).
 * <p>
 * 變更在每位使用者下一次取得 token 時生效（D18）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class RoleAdminService {

    private static final Pattern ROLE_CODE = Pattern.compile("[A-Z][A-Z0-9_]{1,63}");
    private static final Pattern PERMISSION_CODE = Pattern.compile("[a-z0-9][a-z0-9_-]*(:[a-z0-9*][a-z0-9_*-]*)+");
    private static final String ADMIN_ROLE = "AS_ADMIN";

    private final JdbcClient jdbc;
    private final AdminAuditService audit;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc          the JDBC client of the authorization server database
     *                      <br>Authorization Server 資料庫的 JDBC client
     * @param audit         records the changes
     *                      <br>記錄變更
     * @param transactions  runs each change in one transaction
     *                      <br>每一項變更在同一個交易中執行
     * @param clock         the clock
     *                      <br>時鐘
     */
    public RoleAdminService(JdbcClient jdbc, AdminAuditService audit, TransactionOperations transactions,
                            Clock clock) {
        this.jdbc = jdbc;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Lists every role with its permissions.
     * <p>
     * 列出所有角色及其權限。
     *
     * @return the roles, by code
     *         <br>角色，依代碼排序
     */
    public List<RoleView> roles() {
        return jdbc.sql("SELECT code FROM app_role ORDER BY code").query(String.class).list().stream()
                .map(this::role).toList();
    }

    /**
     * Returns a role with its permissions and how many users have it.
     * <p>
     * 回傳角色及其權限，以及擁有它的使用者數量。
     *
     * @param code  the role code
     *              <br>角色代碼
     * @return the role
     *         <br>角色
     * @throws AdminApiException {@code 404} if there is no such role
     *         <br>角色不存在時為 {@code 404}
     */
    public RoleView role(String code) {
        RoleRow row = jdbc.sql("SELECT id, code, name, description, built_in FROM app_role WHERE code = :code")
                .param("code", code)
                .query((rs, rowNum) -> new RoleRow(rs.getString("id"), rs.getString("code"), rs.getString("name"),
                        rs.getString("description"), rs.getBoolean("built_in")))
                .optional().orElseThrow(() -> AdminApiException.notFound("Role " + code));
        List<String> permissions = jdbc.sql("""
                        SELECT p.code FROM app_role_permission rp JOIN app_permission p ON p.id = rp.permission_id
                        WHERE rp.role_id = :role ORDER BY p.code""")
                .param("role", row.id()).query(String.class).list();
        long users = jdbc.sql("SELECT COUNT(*) FROM app_user_role WHERE role_id = :role").param("role", row.id())
                .query(Long.class).single();
        return new RoleView(row.code(), row.name(), row.description(), row.builtIn(), permissions, users);
    }

    /**
     * Creates a role.
     * <p>
     * 建立角色。
     *
     * @param request  the role
     *                 <br>角色
     * @return the created role
     *         <br>建立的角色
     * @throws AdminApiException {@code 400} for an invalid code or name, or
     *         an unknown permission; {@code 409} if the code is used
     *         <br>代碼或名稱無效、或權限不存在時為 {@code 400}；代碼已被使用時
     *         為 {@code 409}
     */
    public RoleView createRole(RoleRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (request.code() == null || !ROLE_CODE.matcher(request.code()).matches()) {
            errors.put("code", "must be 2-64 upper case letters, digits or '_', starting with a letter");
        }
        checkName(request.name(), errors);
        Set<String> permissionIds = permissionIds(request.permissions(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            if (exists("app_role", request.code())) {
                throw AdminApiException.conflict("Role " + request.code() + " already exists");
            }
            String id = UuidV7.next(clock);
            Timestamp now = Timestamp.from(clock.instant());
            jdbc.sql("INSERT INTO app_role (id, code, name, description, built_in, created_at, updated_at) "
                            + "VALUES (:id, :code, :name, :description, :builtIn, :now, :now)")
                    .param("id", id).param("code", request.code()).param("name", request.name().strip())
                    .param("description", request.description()).param("builtIn", false).param("now", now).update();
            grant(id, permissionIds);
            audit.record("ROLE_CREATED", AdminAuditTarget.ROLE, request.code(), null, role(request.code()));
        });
        return role(request.code());
    }

    /**
     * Replaces the name, description and permissions of a role.
     * <p>
     * 取代角色的名稱、說明與權限。
     *
     * @param code     the role code
     *                 <br>角色代碼
     * @param request  the new values; its {@code code} is ignored
     *                 <br>新的值；其中的 {@code code} 不使用
     * @return the updated role
     *         <br>更新後的角色
     * @throws AdminApiException {@code 400} for an invalid name or unknown
     *         permission; {@code 404} if there is no such role; {@code 409}
     *         when changing the permissions of {@code AS_ADMIN}
     *         <br>名稱無效或權限不存在時為 {@code 400}；角色不存在時為
     *         {@code 404}；變更 {@code AS_ADMIN} 的權限時為 {@code 409}
     */
    public RoleView updateRole(String code, RoleRequest request) {
        RoleView before = role(code);
        Map<String, String> errors = new LinkedHashMap<>();
        checkName(request.name(), errors);
        Set<String> permissionIds = permissionIds(request.permissions(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        if (ADMIN_ROLE.equals(code) && request.permissions() != null
                && !Set.copyOf(request.permissions()).equals(Set.copyOf(before.permissions()))) {
            throw AdminApiException.conflict("The permissions of " + ADMIN_ROLE + " cannot change");
        }
        transactions.executeWithoutResult(tx -> {
            String id = id("app_role", code);
            jdbc.sql("UPDATE app_role SET name = :name, description = :description, updated_at = :now WHERE id = :id")
                    .param("name", request.name().strip()).param("description", request.description())
                    .param("now", Timestamp.from(clock.instant())).param("id", id).update();
            if (request.permissions() != null) {
                jdbc.sql("DELETE FROM app_role_permission WHERE role_id = :role").param("role", id).update();
                grant(id, permissionIds);
            }
            audit.record("ROLE_UPDATED", AdminAuditTarget.ROLE, code, before, role(code));
        });
        return role(code);
    }

    /**
     * Deletes a role that no user has.
     * <p>
     * 刪除沒有任何使用者擁有的角色。
     *
     * @param code  the role code
     *              <br>角色代碼
     * @throws AdminApiException {@code 404} if there is no such role;
     *         {@code 409} if it is built in or users have it
     *         <br>角色不存在時為 {@code 404}；內建或仍有使用者時為 {@code 409}
     */
    public void deleteRole(String code) {
        RoleView before = role(code);
        if (before.builtIn()) {
            throw AdminApiException.conflict("Built-in role " + code + " cannot be deleted");
        }
        if (before.users() > 0) {
            throw AdminApiException.conflict("Role " + code + " is still given to " + before.users() + " users");
        }
        transactions.executeWithoutResult(tx -> {
            // app_role_permission 由外鍵 ON DELETE CASCADE 一併刪除
            jdbc.sql("DELETE FROM app_role WHERE code = :code").param("code", code).update();
            audit.record("ROLE_DELETED", AdminAuditTarget.ROLE, code, before, null);
        });
    }

    /**
     * Lists every permission with the roles and scopes that use it.
     * <p>
     * 列出所有權限，以及使用它的角色與 scope。
     *
     * @return the permissions, by code
     *         <br>權限，依代碼排序
     */
    public List<PermissionView> permissions() {
        return jdbc.sql("SELECT code FROM app_permission ORDER BY code").query(String.class).list().stream()
                .map(this::permission).toList();
    }

    /**
     * Returns a permission.
     * <p>
     * 回傳權限。
     *
     * @param code  the permission code
     *              <br>權限代碼
     * @return the permission
     *         <br>權限
     * @throws AdminApiException {@code 404} if there is no such permission
     *         <br>權限不存在時為 {@code 404}
     */
    public PermissionView permission(String code) {
        PermissionRow row = jdbc.sql("SELECT id, code, name, description, built_in FROM app_permission WHERE code = :code")
                .param("code", code)
                .query((rs, rowNum) -> new PermissionRow(rs.getString("id"), rs.getString("code"), rs.getString("name"),
                        rs.getString("description"), rs.getBoolean("built_in")))
                .optional().orElseThrow(() -> AdminApiException.notFound("Permission " + code));
        List<String> roles = jdbc.sql("""
                        SELECT r.code FROM app_role_permission rp JOIN app_role r ON r.id = rp.role_id
                        WHERE rp.permission_id = :permission ORDER BY r.code""")
                .param("permission", row.id()).query(String.class).list();
        List<String> scopes = jdbc.sql("SELECT scope_code FROM app_scope_permission WHERE permission_id = :permission "
                        + "ORDER BY scope_code")
                .param("permission", row.id()).query(String.class).list();
        return new PermissionView(row.code(), row.name(), row.description(), row.builtIn(), roles, scopes);
    }

    /**
     * Creates a permission.
     * <p>
     * 建立權限。
     *
     * @param request  the permission
     *                 <br>權限
     * @return the created permission
     *         <br>建立的權限
     * @throws AdminApiException {@code 400} for an invalid or reserved code,
     *         or an invalid name; {@code 409} if the code is used
     *         <br>代碼無效或為保留值、或名稱無效時為 {@code 400}；代碼已被使用
     *         時為 {@code 409}
     */
    public PermissionView createPermission(PermissionRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (request.code() == null || request.code().length() > 128 || !PERMISSION_CODE.matcher(request.code()).matches()) {
            errors.put("code", "must be lower case resource:action, for example order:read, at most 128 characters");
        } else if (request.code().startsWith(AdminJwtAuthenticationConverter.ADMIN_PERMISSION_PREFIX)) {
            errors.put("code", "permissions starting with as: are reserved for the authorization server");
        }
        checkName(request.name(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            if (exists("app_permission", request.code())) {
                throw AdminApiException.conflict("Permission " + request.code() + " already exists");
            }
            Timestamp now = Timestamp.from(clock.instant());
            jdbc.sql("INSERT INTO app_permission (id, code, name, description, built_in, created_at, updated_at) "
                            + "VALUES (:id, :code, :name, :description, :builtIn, :now, :now)")
                    .param("id", UuidV7.next(clock)).param("code", request.code()).param("name", request.name().strip())
                    .param("description", request.description()).param("builtIn", false).param("now", now).update();
            audit.record("PERMISSION_CREATED", AdminAuditTarget.PERMISSION, request.code(), null,
                    permission(request.code()));
        });
        return permission(request.code());
    }

    /**
     * Changes the name and description of a permission.
     * <p>
     * 變更權限的名稱與說明。
     *
     * @param code     the permission code
     *                 <br>權限代碼
     * @param request  the new values; its {@code code} is ignored
     *                 <br>新的值；其中的 {@code code} 不使用
     * @return the updated permission
     *         <br>更新後的權限
     * @throws AdminApiException {@code 400} for an invalid name; {@code 404}
     *         if there is no such permission
     *         <br>名稱無效時為 {@code 400}；權限不存在時為 {@code 404}
     */
    public PermissionView updatePermission(String code, PermissionRequest request) {
        PermissionView before = permission(code);
        Map<String, String> errors = new LinkedHashMap<>();
        checkName(request.name(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            jdbc.sql("UPDATE app_permission SET name = :name, description = :description, updated_at = :now "
                            + "WHERE code = :code")
                    .param("name", request.name().strip()).param("description", request.description())
                    .param("now", Timestamp.from(clock.instant())).param("code", code).update();
            audit.record("PERMISSION_UPDATED", AdminAuditTarget.PERMISSION, code, before, permission(code));
        });
        return permission(code);
    }

    /**
     * Deletes a permission that no role or scope uses.
     * <p>
     * 刪除沒有任何角色或 scope 使用的權限。
     *
     * @param code  the permission code
     *              <br>權限代碼
     * @throws AdminApiException {@code 404} if there is no such permission;
     *         {@code 409} if it is built in or still used
     *         <br>權限不存在時為 {@code 404}；內建或仍被使用時為 {@code 409}
     */
    public void deletePermission(String code) {
        PermissionView before = permission(code);
        if (before.builtIn()) {
            throw AdminApiException.conflict("Built-in permission " + code + " cannot be deleted");
        }
        if (!before.roles().isEmpty() || !before.scopes().isEmpty()) {
            throw AdminApiException.conflict("Permission " + code + " is still used by roles " + before.roles()
                    + " and scopes " + before.scopes());
        }
        transactions.executeWithoutResult(tx -> {
            jdbc.sql("DELETE FROM app_permission WHERE code = :code").param("code", code).update();
            audit.record("PERMISSION_DELETED", AdminAuditTarget.PERMISSION, code, before, null);
        });
    }

    private Set<String> permissionIds(@Nullable List<String> codes, Map<String, String> errors) {
        Set<String> ids = new LinkedHashSet<>();
        if (codes == null) {
            return ids;
        }
        for (String code : new LinkedHashSet<>(codes)) {
            jdbc.sql("SELECT id FROM app_permission WHERE code = :code").param("code", code).query(String.class)
                    .optional().ifPresentOrElse(ids::add, () -> errors.put("permissions", "permission " + code
                            + " does not exist"));
        }
        return ids;
    }

    private void grant(String roleId, Set<String> permissionIds) {
        for (String permissionId : permissionIds) {
            jdbc.sql("INSERT INTO app_role_permission (role_id, permission_id) VALUES (:role, :permission)")
                    .param("role", roleId).param("permission", permissionId).update();
        }
    }

    private boolean exists(String table, String code) {
        return jdbc.sql("SELECT COUNT(*) FROM " + table + " WHERE code = :code").param("code", code)
                .query(Integer.class).single() > 0;
    }

    private String id(String table, String code) {
        return jdbc.sql("SELECT id FROM " + table + " WHERE code = :code").param("code", code).query(String.class)
                .single();
    }

    private static void checkName(@Nullable String name, Map<String, String> errors) {
        if (name == null || name.isBlank() || name.strip().length() > 128) {
            errors.put("name", "required, at most 128 characters");
        }
    }

    private record RoleRow(String id, String code, String name, @Nullable String description, boolean builtIn) {
    }

    private record PermissionRow(String id, String code, String name, @Nullable String description, boolean builtIn) {
    }

    /**
     * A role.
     * <p>
     * 角色。
     *
     * @param code         the role code
     *                     <br>角色代碼
     * @param name         the name
     *                     <br>名稱
     * @param description  the description, or {@code null}
     *                     <br>說明，或 {@code null}
     * @param builtIn      whether the authorization server needs it
     *                     <br>是否為 Authorization Server 需要的內建角色
     * @param permissions  the permission codes
     *                     <br>權限代碼
     * @param users        how many users have it
     *                     <br>擁有它的使用者數量
     */
    public record RoleView(String code, String name, @Nullable String description, boolean builtIn,
                           List<String> permissions, long users) {
    }

    /**
     * A role to create or update.
     * <p>
     * 要建立或更新的角色。
     *
     * @param code         the role code; used only when creating
     *                     <br>角色代碼；只在建立時使用
     * @param name         the name
     *                     <br>名稱
     * @param description  the description, or {@code null}
     *                     <br>說明，或 {@code null}
     * @param permissions  the permission codes, or {@code null} to keep them
     *                     when updating
     *                     <br>權限代碼；更新時為 {@code null} 表示維持不變
     */
    public record RoleRequest(@Nullable String code, @Nullable String name, @Nullable String description,
                              @Nullable List<String> permissions) {
    }

    /**
     * A permission.
     * <p>
     * 權限。
     *
     * @param code         the permission code
     *                     <br>權限代碼
     * @param name         the name
     *                     <br>名稱
     * @param description  the description, or {@code null}
     *                     <br>說明，或 {@code null}
     * @param builtIn      whether the authorization server needs it
     *                     <br>是否為 Authorization Server 需要的內建權限
     * @param roles        the roles that have it
     *                     <br>擁有它的角色
     * @param scopes       the scopes that grant it to third-party clients
     *                     <br>把它授予第三方 client 的 scope
     */
    public record PermissionView(String code, String name, @Nullable String description, boolean builtIn,
                                 List<String> roles, List<String> scopes) {
    }

    /**
     * A permission to create or update.
     * <p>
     * 要建立或更新的權限。
     *
     * @param code         the permission code; used only when creating
     *                     <br>權限代碼；只在建立時使用
     * @param name         the name
     *                     <br>名稱
     * @param description  the description, or {@code null}
     *                     <br>說明，或 {@code null}
     */
    public record PermissionRequest(@Nullable String code, @Nullable String name, @Nullable String description) {
    }
}
