package jacky917.security.authorizationserver.user;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * A user account as stored in {@code app_user}.
 * <p>
 * 儲存於 {@code app_user} 的使用者帳號。
 *
 * @param id                 the user id, also the token {@code sub}
 *                           <br>使用者 ID，也是 token 的 {@code sub}
 * @param username           the login name, or {@code null} for users who
 *                           only log in through an identity provider
 *                           <br>登入帳號；只用第三方登入的使用者為 {@code null}
 * @param email              the verified email, or {@code null}
 *                           <br>已驗證的 Email，或 {@code null}
 * @param emailVerified      whether the email is verified
 *                           <br>Email 是否已驗證
 * @param passwordHash       the encoded password, or {@code null} without a
 *                           password
 *                           <br>編碼後的密碼；沒有密碼時為 {@code null}
 * @param displayName        the display name
 *                           <br>顯示名稱
 * @param avatarUrl          the avatar URL
 *                           <br>頭像網址
 * @param locale             the preferred locale
 *                           <br>偏好語系
 * @param status             the account status
 *                           <br>帳號狀態
 * @param lockedUntil        the end of a temporary lock, or {@code null}
 *                           <br>暫時鎖定的到期時間，或 {@code null}
 * @param passwordChangedAt  when the password last changed
 *                           <br>最後變更密碼的時間
 * @param lastLoginAt        when the user last logged in
 *                           <br>最後登入時間
 * @param createdAt          when the account was created
 *                           <br>建立時間
 * @param passwordChangeRequired  whether the user must change the password
 *                           at the next password login
 *                           <br>下一次以密碼登入時是否必須變更密碼
 * @author Jacky
 * @since 2.1.0
 */
public record UserAccount(
        String id,
        @Nullable String username,
        @Nullable String email,
        boolean emailVerified,
        @Nullable String passwordHash,
        @Nullable String displayName,
        @Nullable String avatarUrl,
        @Nullable String locale,
        UserStatus status,
        @Nullable Instant lockedUntil,
        @Nullable Instant passwordChangedAt,
        @Nullable Instant lastLoginAt,
        Instant createdAt,
        boolean passwordChangeRequired) {

    /**
     * Returns whether the account may log in at the given time.
     * <p>
     * 回傳帳號在指定時間是否可以登入。
     *
     * @param now  the current time
     *             <br>目前時間
     * @return {@code true} if active and not temporarily locked
     *         <br>為 {@code ACTIVE} 且未被暫時鎖定時為 {@code true}
     */
    public boolean canLogIn(Instant now) {
        return status == UserStatus.ACTIVE && !isTemporarilyLocked(now);
    }

    /**
     * Returns whether the account is temporarily locked at the given time.
     * <p>
     * 回傳帳號在指定時間是否被暫時鎖定。
     *
     * @param now  the current time
     *             <br>目前時間
     * @return {@code true} if {@code locked_until} is in the future
     *         <br>{@code locked_until} 尚未到期時為 {@code true}
     */
    public boolean isTemporarilyLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }
}
