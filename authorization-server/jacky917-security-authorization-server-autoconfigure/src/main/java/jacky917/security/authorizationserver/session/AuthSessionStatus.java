package jacky917.security.authorizationserver.session;

/**
 * Status of a login session (data model §10.2).
 * <p>
 * 登入 Session 的狀態（資料模型 §10.2）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum AuthSessionStatus {

    /**
     * The session can refresh tokens.
     * <p>
     * 可以刷新 token。
     */
    ACTIVE,

    /**
     * Ended by logout, reuse detection, an administrator, or a password
     * change.
     * <p>
     * 因登出、重用偵測、管理員或變更密碼而結束。
     */
    REVOKED,

    /**
     * Passed its absolute lifetime.
     * <p>
     * 超過絕對有效期。
     */
    EXPIRED
}
