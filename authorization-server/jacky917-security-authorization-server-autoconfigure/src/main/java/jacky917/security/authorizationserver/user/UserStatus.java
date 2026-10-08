package jacky917.security.authorizationserver.user;

/**
 * Status of a user account (data model §10.1).
 * <p>
 * 使用者帳號的狀態（資料模型 §10.1）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum UserStatus {

    /**
     * Can log in, unless temporarily locked by {@code locked_until}.
     * <p>
     * 可以登入，除非被 {@code locked_until} 暫時鎖定。
     */
    ACTIVE,

    /**
     * Locked by an administrator.
     * <p>
     * 由管理員鎖定。
     */
    LOCKED,

    /**
     * Disabled by an administrator or by the user.
     * <p>
     * 由管理員或使用者自行停用。
     */
    DISABLED,

    /**
     * Deleted; personal data has been cleared.
     * <p>
     * 已刪除，個資已清除。
     */
    DELETED
}
