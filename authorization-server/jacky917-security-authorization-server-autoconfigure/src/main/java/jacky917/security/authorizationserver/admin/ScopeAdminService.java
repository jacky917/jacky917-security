package jacky917.security.authorizationserver.admin;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Manages scopes and API resources for the administration API (phase 3
 * and 4 design §6.4, data model §5).
 * <p>
 * 為管理 API 管理 scope 與 API resource（第 3、4 階段設計 §6.4、資料模型 §5）。
 * <ul>
 *   <li>An API resource is a value of the access token's {@code aud}; a
 *       scope may belong to one, which decides the audience when
 *       {@code token.audience-strategy} is {@code per-scope}.
 *       <br>API resource 是 Access Token 的 {@code aud} 的值；scope 可以屬於
 *       一個 API resource，在 {@code token.audience-strategy} 為
 *       {@code per-scope} 時決定 audience。</li>
 *   <li>A scope grants permissions to third-party clients: their tokens
 *       carry the permissions of the consented scopes that the user also
 *       has (D07). Scopes cannot grant {@code as:} permissions, and codes
 *       starting with {@code as:} are reserved.
 *       <br>Scope 把權限授予第三方 client：它們的 token 帶有「使用者同意的
 *       scope 對應的權限」中使用者也擁有的部分（D07）。Scope 不能對應
 *       {@code as:} 權限，以 {@code as:} 開頭的代碼也保留不用。</li>
 *   <li>Built-in scopes ({@code openid}, {@code profile}, {@code email})
 *       cannot be deleted; a scope that a client may ask for, or an API
 *       resource that a scope or the configuration uses, cannot be deleted
 *       either.
 *       <br>內建 scope（{@code openid}、{@code profile}、{@code email}）不能
 *       刪除；client 可以要求的 scope、被 scope 或設定使用的 API resource
 *       也不能刪除。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
public class ScopeAdminService {

    private static final Pattern SCOPE_CODE = Pattern.compile("[a-z0-9][a-z0-9._:-]{0,127}");
    private static final Pattern RESOURCE_CODE = Pattern.compile("[a-z0-9][a-z0-9._-]{1,63}");
    private static final int NAME_MAX_LENGTH = 128;

    private final JdbcClient jdbc;
    private final AuthorizationServerProperties properties;
    private final AdminAuditService audit;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc          the JDBC client of the authorization server
     *                      database
     *                      <br>Authorization Server 資料庫的 JDBC client
     * @param properties    the authorization server properties, for the
     *                      audiences in use
     *                      <br>Authorization Server 設定屬性，用於使用中的
     *                      audience
     * @param audit         records the changes
     *                      <br>記錄變更
     * @param transactions  runs each change in one transaction
     *                      <br>每一項變更在同一個交易中執行
     * @param clock         the clock
     *                      <br>時鐘
     */
    public ScopeAdminService(JdbcClient jdbc, AuthorizationServerProperties properties, AdminAuditService audit,
                             TransactionOperations transactions, Clock clock) {
        this.jdbc = jdbc;
        this.properties = properties;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Returns every scope, ordered by code.
     * <p>
     * 回傳所有 scope，依代碼排序。
     *
     * @return the scopes
     *         <br>scope
     */
    public List<ScopeView> scopes() {
        return jdbc.sql("SELECT code FROM app_scope ORDER BY code").query(String.class).list().stream()
                .map(this::scope).toList();
    }

    /**
     * Returns a scope.
     * <p>
     * 回傳一個 scope。
     *
     * @param code  the scope code
     *              <br>scope 代碼
     * @return the scope
     *         <br>scope
     * @throws AdminApiException {@code 404} if it does not exist
     *         <br>不存在時為 {@code 404}
     */
    public ScopeView scope(String code) {
        ScopeView scope = jdbc.sql("""
                        SELECT code, display_name, description, consent_required, built_in, api_resource_code
                        FROM app_scope WHERE code = :code""")
                .param("code", code)
                .query((rs, rowNum) -> new ScopeView(rs.getString("code"), rs.getString("display_name"),
                        rs.getString("description"), rs.getBoolean("consent_required"), rs.getBoolean("built_in"),
                        rs.getString("api_resource_code"), List.of()))
                .optional().orElseThrow(() -> AdminApiException.notFound("Scope " + code));
        List<String> permissions = jdbc.sql("""
                        SELECT p.code FROM app_scope_permission sp JOIN app_permission p ON p.id = sp.permission_id
                        WHERE sp.scope_code = :code ORDER BY p.code""")
                .param("code", code).query(String.class).list();
        return new ScopeView(scope.code(), scope.displayName(), scope.description(), scope.consentRequired(),
                scope.builtIn(), scope.apiResource(), permissions);
    }

    /**
     * Creates a scope.
     * <p>
     * 建立 scope。
     *
     * @param request  the scope
     *                 <br>scope
     * @return the scope
     *         <br>scope
     * @throws AdminApiException {@code 400} if the request is not valid;
     *         {@code 409} if the code is used
     *         <br>請求不正確時為 {@code 400}；代碼已被使用時為 {@code 409}
     */
    public ScopeView createScope(ScopeRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (request.code() == null || !SCOPE_CODE.matcher(request.code()).matches()) {
            errors.put("code", "must be 1-128 lower case letters, digits, '.', '_', ':' or '-'");
        } else if (request.code().startsWith(AdminJwtAuthenticationConverter.ADMIN_PERMISSION_PREFIX)) {
            errors.put("code", "scopes starting with as: are reserved for the authorization server");
        }
        checkName("displayName", request.displayName(), errors);
        checkResource(request.apiResource(), errors);
        Set<String> permissionIds = permissionIds(request.permissions(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            if (count("SELECT COUNT(*) FROM app_scope WHERE code = :code", request.code()) > 0) {
                throw AdminApiException.conflict("Scope " + request.code() + " already exists");
            }
            jdbc.sql("""
                            INSERT INTO app_scope (code, api_resource_code, display_name, description, consent_required,
                                built_in, created_at)
                            VALUES (:code, :resource, :name, :description, :consent, :builtIn, :now)""")
                    .param("code", request.code()).param("resource", blankToNull(request.apiResource()))
                    .param("name", request.displayName().strip()).param("description", request.description())
                    .param("consent", request.consentRequired() == null || request.consentRequired())
                    .param("builtIn", false).param("now", Timestamp.from(clock.instant())).update();
            grant(request.code(), permissionIds);
            audit.record("SCOPE_CREATED", AdminAuditTarget.SCOPE, request.code(), null, scope(request.code()));
        });
        return scope(request.code());
    }

    /**
     * Replaces a scope's name, description, consent requirement, API
     * resource and permissions. For a built-in scope only the name and
     * description change.
     * <p>
     * 取代 scope 的名稱、說明、是否需要同意、API resource 與權限。內建 scope
     * 只變更名稱與說明。
     *
     * @param code     the scope code
     *                 <br>scope 代碼
     * @param request  the new values; the code in it is ignored
     *                 <br>新的值；其中的代碼不使用
     * @return the scope
     *         <br>scope
     * @throws AdminApiException {@code 400} if the request is not valid;
     *         {@code 404} if the scope does not exist
     *         <br>請求不正確時為 {@code 400}；scope 不存在時為 {@code 404}
     */
    public ScopeView updateScope(String code, ScopeRequest request) {
        ScopeView before = scope(code);
        Map<String, String> errors = new LinkedHashMap<>();
        checkName("displayName", request.displayName(), errors);
        checkResource(request.apiResource(), errors);
        Set<String> permissionIds = permissionIds(request.permissions(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            if (before.builtIn()) {
                jdbc.sql("UPDATE app_scope SET display_name = :name, description = :description WHERE code = :code")
                        .param("name", request.displayName().strip()).param("description", request.description())
                        .param("code", code).update();
            } else {
                jdbc.sql("""
                                UPDATE app_scope SET display_name = :name, description = :description,
                                    consent_required = :consent, api_resource_code = :resource
                                WHERE code = :code""")
                        .param("name", request.displayName().strip()).param("description", request.description())
                        .param("consent", request.consentRequired() == null || request.consentRequired())
                        .param("resource", blankToNull(request.apiResource())).param("code", code).update();
                jdbc.sql("DELETE FROM app_scope_permission WHERE scope_code = :code").param("code", code).update();
                grant(code, permissionIds);
            }
            audit.record("SCOPE_UPDATED", AdminAuditTarget.SCOPE, code, before, scope(code));
        });
        return scope(code);
    }

    /**
     * Deletes a scope that is not built in and that no client may ask for.
     * <p>
     * 刪除非內建、且沒有任何 client 可以要求的 scope。
     *
     * @param code  the scope code
     *              <br>scope 代碼
     * @throws AdminApiException {@code 404} if the scope does not exist;
     *         {@code 409} if it is built in or a client may ask for it
     *         <br>scope 不存在時為 {@code 404}；為內建或有 client 可以要求時為
     *         {@code 409}
     */
    public void deleteScope(String code) {
        ScopeView before = scope(code);
        if (before.builtIn()) {
            throw AdminApiException.conflict("Built-in scope " + code + " cannot be deleted");
        }
        List<String> users = clientsUsing(code);
        if (!users.isEmpty()) {
            throw AdminApiException.conflict("Scope " + code + " is still used by clients " + users);
        }
        transactions.executeWithoutResult(tx -> {
            // app_scope_permission 由外鍵 ON DELETE CASCADE 一併刪除
            jdbc.sql("DELETE FROM app_scope WHERE code = :code").param("code", code).update();
            audit.record("SCOPE_DELETED", AdminAuditTarget.SCOPE, code, before, null);
        });
    }

    /**
     * Returns every API resource, ordered by code.
     * <p>
     * 回傳所有 API resource，依代碼排序。
     *
     * @return the API resources
     *         <br>API resource
     */
    public List<ApiResourceView> apiResources() {
        return jdbc.sql("SELECT code FROM api_resource ORDER BY code").query(String.class).list().stream()
                .map(this::apiResource).toList();
    }

    /**
     * Returns an API resource.
     * <p>
     * 回傳一個 API resource。
     *
     * @param code  the API resource code
     *              <br>API resource 代碼
     * @return the API resource
     *         <br>API resource
     * @throws AdminApiException {@code 404} if it does not exist
     *         <br>不存在時為 {@code 404}
     */
    public ApiResourceView apiResource(String code) {
        ApiResourceView resource = jdbc.sql("SELECT code, name, description FROM api_resource WHERE code = :code")
                .param("code", code)
                .query((rs, rowNum) -> new ApiResourceView(rs.getString("code"), rs.getString("name"),
                        rs.getString("description"), List.of()))
                .optional().orElseThrow(() -> AdminApiException.notFound("API resource " + code));
        List<String> scopes = jdbc.sql("SELECT code FROM app_scope WHERE api_resource_code = :code ORDER BY code")
                .param("code", code).query(String.class).list();
        return new ApiResourceView(resource.code(), resource.name(), resource.description(), scopes);
    }

    /**
     * Creates an API resource.
     * <p>
     * 建立 API resource。
     *
     * @param request  the API resource
     *                 <br>API resource
     * @return the API resource
     *         <br>API resource
     * @throws AdminApiException {@code 400} if the request is not valid;
     *         {@code 409} if the code is used
     *         <br>請求不正確時為 {@code 400}；代碼已被使用時為 {@code 409}
     */
    public ApiResourceView createApiResource(ApiResourceRequest request) {
        Map<String, String> errors = new LinkedHashMap<>();
        if (request.code() == null || !RESOURCE_CODE.matcher(request.code()).matches()) {
            errors.put("code", "must be 2-64 lower case letters, digits, '.', '_' or '-'");
        }
        checkName("name", request.name(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            if (count("SELECT COUNT(*) FROM api_resource WHERE code = :code", request.code()) > 0) {
                throw AdminApiException.conflict("API resource " + request.code() + " already exists");
            }
            jdbc.sql("INSERT INTO api_resource (code, name, description, created_at) "
                            + "VALUES (:code, :name, :description, :now)")
                    .param("code", request.code()).param("name", request.name().strip())
                    .param("description", request.description()).param("now", Timestamp.from(clock.instant()))
                    .update();
            audit.record("API_RESOURCE_CREATED", AdminAuditTarget.API_RESOURCE, request.code(), null,
                    apiResource(request.code()));
        });
        return apiResource(request.code());
    }

    /**
     * Replaces an API resource's name and description.
     * <p>
     * 取代 API resource 的名稱與說明。
     *
     * @param code     the API resource code
     *                 <br>API resource 代碼
     * @param request  the new values; the code in it is ignored
     *                 <br>新的值；其中的代碼不使用
     * @return the API resource
     *         <br>API resource
     * @throws AdminApiException {@code 400} if the request is not valid;
     *         {@code 404} if the API resource does not exist
     *         <br>請求不正確時為 {@code 400}；API resource 不存在時為
     *         {@code 404}
     */
    public ApiResourceView updateApiResource(String code, ApiResourceRequest request) {
        ApiResourceView before = apiResource(code);
        Map<String, String> errors = new LinkedHashMap<>();
        checkName("name", request.name(), errors);
        if (!errors.isEmpty()) {
            throw AdminApiException.invalid(errors);
        }
        transactions.executeWithoutResult(tx -> {
            jdbc.sql("UPDATE api_resource SET name = :name, description = :description WHERE code = :code")
                    .param("name", request.name().strip()).param("description", request.description())
                    .param("code", code).update();
            audit.record("API_RESOURCE_UPDATED", AdminAuditTarget.API_RESOURCE, code, before, apiResource(code));
        });
        return apiResource(code);
    }

    /**
     * Deletes an API resource that no scope belongs to and that is not
     * configured as an audience.
     * <p>
     * 刪除沒有任何 scope 屬於它、且未被設定為 audience 的 API resource。
     *
     * @param code  the API resource code
     *              <br>API resource 代碼
     * @throws AdminApiException {@code 404} if it does not exist;
     *         {@code 409} if it is still used
     *         <br>不存在時為 {@code 404}；仍在使用時為 {@code 409}
     */
    public void deleteApiResource(String code) {
        ApiResourceView before = apiResource(code);
        if (!before.scopes().isEmpty()) {
            throw AdminApiException.conflict("API resource " + code + " is still used by scopes " + before.scopes());
        }
        if (properties.getToken().getAudience().contains(code)
                || code.equals(properties.getAdminApi().effectiveAudience(properties.getToken()))) {
            throw AdminApiException.conflict("API resource " + code + " is configured as token.audience or "
                    + "admin-api.audience");
        }
        transactions.executeWithoutResult(tx -> {
            jdbc.sql("DELETE FROM api_resource WHERE code = :code").param("code", code).update();
            audit.record("API_RESOURCE_DELETED", AdminAuditTarget.API_RESOURCE, code, before, null);
        });
    }

    private List<String> clientsUsing(String scope) {
        // oauth2_registered_client.scopes 是以逗號分隔的字串（Spring Authorization Server 的格式）
        return jdbc.sql("SELECT client_id, scopes FROM oauth2_registered_client ORDER BY client_id")
                .query((rs, rowNum) -> Map.entry(rs.getString(1), rs.getString(2))).list().stream()
                .filter(row -> Arrays.asList(row.getValue().split(",")).contains(scope))
                .map(Map.Entry::getKey).toList();
    }

    private Set<String> permissionIds(@Nullable List<String> codes, Map<String, String> errors) {
        Set<String> ids = new LinkedHashSet<>();
        if (codes == null) {
            return ids;
        }
        for (String code : new LinkedHashSet<>(codes)) {
            if (code == null || code.startsWith(AdminJwtAuthenticationConverter.ADMIN_PERMISSION_PREFIX)) {
                errors.put("permissions", "a scope cannot grant permissions starting with as:");
                return ids;
            }
            jdbc.sql("SELECT id FROM app_permission WHERE code = :code").param("code", code).query(String.class)
                    .optional().ifPresentOrElse(ids::add, () -> errors.put("permissions", "permission " + code
                            + " does not exist"));
        }
        return ids;
    }

    private void grant(String scope, Set<String> permissionIds) {
        for (String permissionId : permissionIds) {
            jdbc.sql("INSERT INTO app_scope_permission (scope_code, permission_id) VALUES (:scope, :permission)")
                    .param("scope", scope).param("permission", permissionId).update();
        }
    }

    private void checkResource(@Nullable String code, Map<String, String> errors) {
        String resource = blankToNull(code);
        if (resource != null && count("SELECT COUNT(*) FROM api_resource WHERE code = :code", resource) == 0) {
            errors.put("apiResource", "API resource " + resource + " does not exist");
        }
    }

    private int count(String sql, String code) {
        return jdbc.sql(sql).param("code", code).query(Integer.class).single();
    }

    private static void checkName(String field, @Nullable String name, Map<String, String> errors) {
        if (name == null || name.isBlank() || name.strip().length() > NAME_MAX_LENGTH) {
            errors.put(field, "required, at most " + NAME_MAX_LENGTH + " characters");
        }
    }

    private static @Nullable String blankToNull(@Nullable String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    /**
     * A scope.
     * <p>
     * Scope。
     *
     * @param code             the scope code
     *                         <br>scope 代碼
     * @param displayName      the name shown on the consent page
     *                         <br>顯示在同意畫面上的名稱
     * @param description      the description shown on the consent page, or
     *                         {@code null}
     *                         <br>顯示在同意畫面上的說明，或 {@code null}
     * @param consentRequired  whether users are asked to consent to it
     *                         <br>是否要求使用者同意
     * @param builtIn          whether the authorization server defines it
     *                         <br>是否為 Authorization Server 定義的內建 scope
     * @param apiResource      the API resource it belongs to, or {@code null}
     *                         <br>所屬的 API resource，或 {@code null}
     * @param permissions      the permissions it grants to third-party
     *                         clients
     *                         <br>授予第三方 client 的權限
     */
    public record ScopeView(String code, String displayName, @Nullable String description, boolean consentRequired,
                            boolean builtIn, @Nullable String apiResource, List<String> permissions) {
    }

    /**
     * A scope to create or update.
     * <p>
     * 要建立或更新的 scope。
     *
     * @param code             the scope code; used only when creating
     *                         <br>scope 代碼；只在建立時使用
     * @param displayName      the name shown on the consent page
     *                         <br>顯示在同意畫面上的名稱
     * @param description      the description, or {@code null}
     *                         <br>說明，或 {@code null}
     * @param consentRequired  whether users are asked to consent to it;
     *                         {@code true} when {@code null}
     *                         <br>是否要求使用者同意；{@code null} 時為
     *                         {@code true}
     * @param apiResource      the API resource it belongs to, or {@code null}
     *                         <br>所屬的 API resource，或 {@code null}
     * @param permissions      the permission codes it grants, or {@code null}
     *                         for none
     *                         <br>授予的權限代碼；{@code null} 表示沒有
     */
    public record ScopeRequest(@Nullable String code, @Nullable String displayName, @Nullable String description,
                               @Nullable Boolean consentRequired, @Nullable String apiResource,
                               @Nullable List<String> permissions) {
    }

    /**
     * An API resource.
     * <p>
     * API resource。
     *
     * @param code         the code, used as the {@code aud} value
     *                     <br>代碼，作為 {@code aud} 的值
     * @param name         the name
     *                     <br>名稱
     * @param description  the description, or {@code null}
     *                     <br>說明，或 {@code null}
     * @param scopes       the scopes that belong to it
     *                     <br>屬於它的 scope
     */
    public record ApiResourceView(String code, String name, @Nullable String description, List<String> scopes) {
    }

    /**
     * An API resource to create or update.
     * <p>
     * 要建立或更新的 API resource。
     *
     * @param code         the code; used only when creating
     *                     <br>代碼；只在建立時使用
     * @param name         the name
     *                     <br>名稱
     * @param description  the description, or {@code null}
     *                     <br>說明，或 {@code null}
     */
    public record ApiResourceRequest(@Nullable String code, @Nullable String name, @Nullable String description) {
    }
}
