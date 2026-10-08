package jacky917.security.authorizationserver.admin;

/**
 * What an administration action changed, as written to
 * {@code admin_audit_log.target_type}.
 * <p>
 * 管理操作變更的對象種類，寫入 {@code admin_audit_log.target_type}。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum AdminAuditTarget {

    /**
     * A user.
     * <p>
     * 使用者。
     */
    USER,

    /**
     * A role.
     * <p>
     * 角色。
     */
    ROLE,

    /**
     * A permission.
     * <p>
     * 權限。
     */
    PERMISSION,

    /**
     * A client.
     * <p>
     * Client。
     */
    CLIENT,

    /**
     * A scope.
     * <p>
     * Scope。
     */
    SCOPE,

    /**
     * An API resource, the value of an {@code aud} claim.
     * <p>
     * API resource，即 {@code aud} claim 的值。
     */
    API_RESOURCE,

    /**
     * A login session.
     * <p>
     * 登入 Session。
     */
    SESSION,

    /**
     * A signing key.
     * <p>
     * 簽章金鑰。
     */
    SIGNING_KEY
}
