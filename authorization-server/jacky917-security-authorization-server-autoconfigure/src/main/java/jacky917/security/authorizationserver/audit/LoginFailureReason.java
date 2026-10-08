package jacky917.security.authorizationserver.audit;

/**
 * Why a login failed, as written to {@code login_audit.failure_reason}.
 * The login page shows the same message for all of them (detailed design
 * §7.2).
 * <p>
 * 登入失敗的原因，寫入 {@code login_audit.failure_reason}。登入頁對所有原因
 * 顯示相同的訊息（詳細設計 §7.2）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum LoginFailureReason {

    /**
     * Wrong password for an existing account.
     * <p>
     * 既有帳號的密碼錯誤。
     */
    BAD_CREDENTIALS,

    /**
     * No account matches the typed login.
     * <p>
     * 沒有符合輸入帳號的帳號。
     */
    UNKNOWN_USER,

    /**
     * The account is locked, temporarily or by an administrator.
     * <p>
     * 帳號被鎖定（暫時鎖定或管理員鎖定）。
     */
    LOCKED,

    /**
     * The account is disabled.
     * <p>
     * 帳號已停用。
     */
    DISABLED,

    /**
     * Too many failed logins from the same IP address.
     * <p>
     * 同一個 IP 的登入失敗次數過多。
     */
    RATE_LIMITED,

    /**
     * An external login could not be processed.
     * <p>
     * 無法處理第三方登入。
     */
    FEDERATION,

    /**
     * The account of an external login cannot log in.
     * <p>
     * 第三方登入對應的帳號無法登入。
     */
    USER_CANNOT_LOG_IN,

    /**
     * The verified email of an external login belongs to an existing
     * account.
     * <p>
     * 第三方登入的已驗證 Email 屬於既有帳號。
     */
    ACCOUNT_EXISTS
}
