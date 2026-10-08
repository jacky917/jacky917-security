package jacky917.security.authorizationserver.audit;

/**
 * Kinds of security events recorded in {@code login_audit} (detailed design
 * §8.1).
 * <p>
 * 寫入 {@code login_audit} 的安全事件種類（詳細設計 §8.1）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum LoginAuditEventType {

    /**
     * A login attempt, successful or not.
     * <p>
     * 登入嘗試，成功或失敗。
     */
    LOGIN,

    /**
     * A login session ended by the user.
     * <p>
     * 使用者結束登入 Session。
     */
    LOGOUT,

    /**
     * A rotated refresh token was used again after the grace period.
     * <p>
     * 已輪換的 Refresh Token 在寬限期之後再次被使用。
     */
    TOKEN_REFRESH_REUSE,

    /**
     * An account was locked after too many failed logins.
     * <p>
     * 帳號因連續登入失敗而被鎖定。
     */
    ACCOUNT_LOCKED,

    /**
     * An external account was linked to a user.
     * <p>
     * 外部帳號連結到使用者。
     */
    ACCOUNT_LINKED,

    /**
     * An external account was unlinked from a user.
     * <p>
     * 外部帳號與使用者解除連結。
     */
    ACCOUNT_UNLINKED,

    /**
     * A user changed their password.
     * <p>
     * 使用者變更密碼。
     */
    PASSWORD_CHANGED
}
