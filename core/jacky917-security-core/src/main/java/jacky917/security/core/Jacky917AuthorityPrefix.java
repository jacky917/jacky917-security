package jacky917.security.core;

/**
 * Default prefixes added to authorities mapped from JWT claims.
 * <p>
 * 由 JWT claim 映射出的 authority 所使用的預設前綴。
 * <p>
 * Values in tokens and in the authorization server's database never carry
 * these prefixes; the resource server adds them when it maps claims.
 * <p>
 * Token 與 Authorization Server 資料庫中的值都不含這些前綴；由 Resource Server
 * 在映射 claim 時加上。
 *
 * @since 2.0.0
 */
public final class Jacky917AuthorityPrefix {

    /**
     * Prefix for roles, for example {@code ROLE_ADMIN}.
     * <p>
     * 角色前綴，例如 {@code ROLE_ADMIN}。
     */
    public static final String ROLE = "ROLE_";

    /**
     * Prefix for permissions, for example {@code PERM_order:read}.
     * <p>
     * 權限前綴，例如 {@code PERM_order:read}。
     */
    public static final String PERMISSION = "PERM_";

    /**
     * Prefix for scopes, for example {@code SCOPE_profile}.
     * <p>
     * Scope 前綴，例如 {@code SCOPE_profile}。
     */
    public static final String SCOPE = "SCOPE_";

    private Jacky917AuthorityPrefix() {
    }
}
