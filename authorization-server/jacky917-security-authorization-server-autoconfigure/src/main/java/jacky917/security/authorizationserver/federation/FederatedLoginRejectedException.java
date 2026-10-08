package jacky917.security.authorizationserver.federation;

import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * Thrown when a login through an identity provider, or a link of an external
 * account, cannot be accepted.
 * <p>
 * 透過身分提供者的登入或外部帳號的連結無法接受時拋出。
 * <p>
 * Instances are created with the factory method of each reason, so a
 * {@link Reason#LINK_REQUIRED} rejection always names the existing user.
 * <p>
 * 實例以各原因的 factory 方法建立，因此 {@code LINK_REQUIRED} 的拒絕一定帶有
 * 既有使用者。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class FederatedLoginRejectedException extends RuntimeException {

    /**
     * Why the login or link was rejected.
     * <p>
     * 拒絕登入或連結的原因。
     */
    public enum Reason {
        /**
         * The linked user cannot log in (disabled, locked by an
         * administrator, deleted).
         * <p>
         * 連結的使用者無法登入（停用、被管理員鎖定、已刪除）。
         */
        USER_CANNOT_LOG_IN,
        /**
         * The email belongs to an existing account and linking is allowed
         * only from the account page ({@code account-linking.mode=manual-only}),
         * or the email is already used by an account whose email is not
         * verified.
         * <p>
         * Email 屬於既有帳號，且只能從帳號頁連結
         * （{@code account-linking.mode=manual-only}）；或 Email 已被一個尚未
         * 驗證 Email 的帳號使用。
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

    private FederatedLoginRejectedException(Reason reason, @Nullable String existingUserId, String message,
                                            @Nullable Throwable cause) {
        super(message, cause);
        this.reason = reason;
        this.existingUserId = existingUserId;
    }

    /**
     * Creates the exception for a linked user who cannot log in.
     * <p>
     * 為無法登入的已連結使用者建立例外。
     *
     * @param message  details for the log
     *                 <br>寫入日誌的詳細資訊
     * @return the exception with {@link Reason#USER_CANNOT_LOG_IN}
     *         <br>原因為 {@code USER_CANNOT_LOG_IN} 的例外
     */
    public static FederatedLoginRejectedException userCannotLogIn(String message) {
        return new FederatedLoginRejectedException(Reason.USER_CANNOT_LOG_IN, null, message, null);
    }

    /**
     * Creates the exception for an email that already belongs to an
     * account.
     * <p>
     * 為已屬於某個帳號的 Email 建立例外。
     *
     * @param existingUserId  the account, or {@code null} if not known
     *                        <br>該帳號；不明時為 {@code null}
     * @param message         details for the log
     *                        <br>寫入日誌的詳細資訊
     * @param cause           the database error that revealed it, or
     *                        {@code null}
     *                        <br>發現此情況的資料庫錯誤，或 {@code null}
     * @return the exception with {@link Reason#ACCOUNT_EXISTS}
     *         <br>原因為 {@code ACCOUNT_EXISTS} 的例外
     */
    public static FederatedLoginRejectedException accountExists(@Nullable String existingUserId, String message,
                                                                @Nullable Throwable cause) {
        return new FederatedLoginRejectedException(Reason.ACCOUNT_EXISTS, existingUserId, message, cause);
    }

    /**
     * Creates the exception for a login that must be linked to an existing
     * user after the user confirms.
     * <p>
     * 為必須在使用者確認後連結到既有使用者的登入建立例外。
     *
     * @param existingUserId  the existing user
     *                        <br>既有使用者
     * @param message         details for the log
     *                        <br>寫入日誌的詳細資訊
     * @return the exception with {@link Reason#LINK_REQUIRED}
     *         <br>原因為 {@code LINK_REQUIRED} 的例外
     */
    public static FederatedLoginRejectedException linkRequired(String existingUserId, String message) {
        return new FederatedLoginRejectedException(Reason.LINK_REQUIRED,
                Objects.requireNonNull(existingUserId, "existingUserId"), message, null);
    }

    /**
     * Creates the exception for an external account already linked to
     * another user.
     * <p>
     * 為已連結到其他使用者的外部帳號建立例外。
     *
     * @param message  details for the log
     *                 <br>寫入日誌的詳細資訊
     * @return the exception with {@link Reason#LINKED_TO_ANOTHER_USER}
     *         <br>原因為 {@code LINKED_TO_ANOTHER_USER} 的例外
     */
    public static FederatedLoginRejectedException linkedToAnotherUser(String message) {
        return new FederatedLoginRejectedException(Reason.LINKED_TO_ANOTHER_USER, null, message, null);
    }

    /**
     * Creates the exception for a user who already has another account of
     * the provider linked.
     * <p>
     * 為已連結該提供者另一個帳號的使用者建立例外。
     *
     * @param message  details for the log
     *                 <br>寫入日誌的詳細資訊
     * @return the exception with {@link Reason#PROVIDER_ALREADY_LINKED}
     *         <br>原因為 {@code PROVIDER_ALREADY_LINKED} 的例外
     */
    public static FederatedLoginRejectedException providerAlreadyLinked(String message) {
        return new FederatedLoginRejectedException(Reason.PROVIDER_ALREADY_LINKED, null, message, null);
    }

    /**
     * Returns why the login or link was rejected.
     * <p>
     * 回傳拒絕登入或連結的原因。
     *
     * @return the reason
     *         <br>原因
     */
    public Reason reason() {
        return reason;
    }

    /**
     * Returns the existing user that the email belongs to.
     * <p>
     * 回傳 Email 所屬的既有使用者。
     *
     * @return the user id; never {@code null} for {@link Reason#LINK_REQUIRED},
     *         set for {@link Reason#ACCOUNT_EXISTS} when known, otherwise
     *         {@code null}
     *         <br>使用者 ID；{@code LINK_REQUIRED} 時一定有值，
     *         {@code ACCOUNT_EXISTS} 時於已知的情況下有值，其他情況為
     *         {@code null}
     */
    public @Nullable String existingUserId() {
        return existingUserId;
    }
}
