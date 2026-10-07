package jacky917.security.authorizationserver.federation;

/**
 * Thrown when a login through an identity provider cannot be accepted.
 * <p>
 * 透過身分提供者的登入無法接受時拋出。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class FederatedLoginRejectedException extends RuntimeException {

    /**
     * Why the login was rejected.
     * <p>
     * 拒絕登入的原因。
     */
    public enum Reason {
        /**
         * The linked user cannot log in (disabled, locked, deleted).
         * <p>
         * 連結的使用者無法登入（停用、鎖定、已刪除）。
         */
        USER_CANNOT_LOG_IN,
        /**
         * The verified email belongs to an existing account; linking it
         * requires a confirmation that is not available yet.
         * <p>
         * 已驗證的 Email 屬於既有帳號；連結需要確認，此功能尚未提供。
         */
        ACCOUNT_EXISTS
    }

    private final Reason reason;

    /**
     * Creates the exception.
     * <p>
     * 建立例外。
     *
     * @param reason   why the login was rejected
     *                 <br>拒絕登入的原因
     * @param message  details for the log
     *                 <br>寫入日誌的詳細資訊
     */
    public FederatedLoginRejectedException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    /**
     * Returns why the login was rejected.
     * <p>
     * 回傳拒絕登入的原因。
     *
     * @return the reason
     *         <br>原因
     */
    public Reason reason() {
        return reason;
    }
}
