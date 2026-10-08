package jacky917.security.authorizationserver.federation;

import org.jspecify.annotations.Nullable;

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
         * The verified email belongs to an existing account and linking
         * is allowed only from the account page
         * ({@code account-linking.mode=manual-only}).
         * <p>
         * 已驗證的 Email 屬於既有帳號，且只能從帳號頁連結
         * （{@code account-linking.mode=manual-only}）。
         */
        ACCOUNT_EXISTS,
        /**
         * The verified email belongs to an existing account; the user must
         * confirm the link by logging in to that account
         * ({@link FederatedLoginRejectedException#existingUserId()}).
         * <p>
         * 已驗證的 Email 屬於既有帳號；使用者必須登入該帳號以確認連結
         * （{@code existingUserId()}）。
         */
        LINK_REQUIRED,
        /**
         * The external account is already linked to another user.
         * <p>
         * 外部帳號已連結到其他使用者。
         */
        LINKED_TO_ANOTHER_USER,
        /**
         * The user already has another account of this provider linked.
         * <p>
         * 使用者已連結此提供者的另一個帳號。
         */
        PROVIDER_ALREADY_LINKED
    }

    private final Reason reason;
    private final @Nullable String existingUserId;

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
        this(reason, null, message);
    }

    /**
     * Creates the exception for a login that must be linked to an existing
     * user.
     * <p>
     * 為必須連結到既有使用者的登入建立例外。
     *
     * @param reason          why the login was rejected
     *                        <br>拒絕登入的原因
     * @param existingUserId  the existing user, or {@code null}
     *                        <br>既有使用者，或 {@code null}
     * @param message         details for the log
     *                        <br>寫入日誌的詳細資訊
     */
    public FederatedLoginRejectedException(Reason reason, @Nullable String existingUserId, String message) {
        super(message);
        this.reason = reason;
        this.existingUserId = existingUserId;
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

    /**
     * Returns the existing user the login must be linked to.
     * <p>
     * 回傳登入必須連結到的既有使用者。
     *
     * @return the user id for {@link Reason#LINK_REQUIRED}, otherwise
     *         {@code null}
     *         <br>{@code LINK_REQUIRED} 時為使用者 ID，其他情況為 {@code null}
     */
    public @Nullable String existingUserId() {
        return existingUserId;
    }
}
