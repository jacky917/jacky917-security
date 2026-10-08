package jacky917.security.authorizationserver.audit;

/**
 * Why a login or a related action failed, as written to
 * {@code login_audit.failure_reason}.
 * <p>
 * 登入或相關動作失敗的原因，寫入 {@code login_audit.failure_reason}。
 * <p>
 * The login page shows one message for all password failures, so it never
 * reveals whether the account exists or is locked (detailed design §7.2);
 * only rate limiting, two-step verification and external logins have their
 * own messages.
 * <p>
 * 登入頁對所有密碼登入失敗顯示同一個訊息，不會透露帳號是否存在或被鎖定（詳細
 * 設計 §7.2）；只有限流、兩步驟驗證與第三方登入有各自的訊息。
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
     * The account is disabled, expired or deleted.
     * <p>
     * 帳號已停用、已過期或已刪除。
     */
    DISABLED,

    /**
     * The account has no password, so it cannot confirm with one.
     * <p>
     * 帳號沒有密碼，因此無法以密碼確認。
     */
    NO_PASSWORD,

    /**
     * Too many failed logins from the same IP address.
     * <p>
     * 同一個 IP 的登入失敗次數過多。
     */
    RATE_LIMITED,

    /**
     * The login could not be checked because of an unexpected error, for
     * example the database being unavailable.
     * <p>
     * 因非預期的錯誤（例如資料庫無法使用）而無法檢查登入。
     */
    ERROR,

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
    ACCOUNT_EXISTS,

    /**
     * The verified email of an external login belongs to an existing
     * account; the user was asked to confirm the link.
     * <p>
     * 第三方登入的已驗證 Email 屬於既有帳號；已要求使用者確認連結。
     */
    LINK_REQUIRED,

    /**
     * A link was not confirmed in time, or was confirmed by another user.
     * <p>
     * 連結未在期限內確認，或由其他使用者確認。
     */
    LINK_EXPIRED,

    /**
     * The external account to link is already linked to another user.
     * <p>
     * 要連結的外部帳號已連結到其他使用者。
     */
    LINKED_TO_ANOTHER_USER,

    /**
     * The user already has another account of the same provider linked.
     * <p>
     * 使用者已連結同一個提供者的另一個帳號。
     */
    PROVIDER_ALREADY_LINKED,

    /**
     * A rotated refresh token was used again after the grace period.
     * <p>
     * 已輪換的 Refresh Token 在寬限期之後再次被使用。
     */
    REUSE_DETECTED,

    /**
     * The two-step verification code or recovery code was wrong.
     * <p>
     * 兩步驟驗證的驗證碼或復原碼錯誤。
     */
    MFA_FAILED;

    /**
     * Returns whether a failure for this reason counts towards locking the
     * account.
     * <p>
     * 回傳此原因的失敗是否計入帳號鎖定。
     * <p>
     * Used by the password form's failure handler, where only a wrong
     * password counts: an attempt on a locked or disabled account must not
     * extend the lock, and an unexpected error must not lock out a user who
     * typed the right password. Wrong two-step verification codes and a
     * wrong current password on the change page are counted by their own
     * pages.
     * <p>
     * 由密碼表單的失敗處理器使用，只有密碼錯誤會計入：對已鎖定或已停用帳號的
     * 嘗試不應延長鎖定，非預期的錯誤也不應鎖住輸入正確密碼的使用者。兩步驟驗證
     * 的錯誤驗證碼與變更密碼頁的錯誤目前密碼，由各自的頁面計入。
     *
     * @return {@code true} only for {@link #BAD_CREDENTIALS}
     *         <br>只有 {@code BAD_CREDENTIALS} 為 {@code true}
     */
    public boolean countsTowardsLock() {
        return this == BAD_CREDENTIALS;
    }
}
