package jacky917.security.authorizationserver.session;

import org.jspecify.annotations.Nullable;

import java.time.Instant;

/**
 * A login session: one login on one device, shared by every token issued
 * from it (data model §7.2).
 * <p>
 * 登入 Session：一個裝置上的一次登入，由此簽發的所有 token 共用（資料模型 §7.2）。
 *
 * @param sessionId     the session id, the access token {@code asid}
 *                      <br>Session ID，即 Access Token 的 {@code asid}
 * @param userId        the user id
 *                      <br>使用者 ID
 * @param status        the session status
 *                      <br>Session 狀態
 * @param loginMethod   how the user logged in
 *                      <br>登入方式
 * @param idp           the identity provider, {@code local} for passwords
 *                      <br>身分提供者；密碼登入為 {@code local}
 * @param amr           authentication methods, comma-separated, for the
 *                      ID token {@code amr}
 *                      <br>驗證方式（逗號分隔），用於 ID Token 的 {@code amr}
 * @param createdAt     the login time, the ID token {@code auth_time}
 *                      <br>登入時間，即 ID Token 的 {@code auth_time}
 * @param lastSeenAt    the last refresh
 *                      <br>最後一次刷新的時間
 * @param expiresAt     the absolute end of the session
 *                      <br>Session 的絕對到期時間
 * @param revokedAt     when the session was revoked, or {@code null}
 *                      <br>撤銷時間，或 {@code null}
 * @author Jacky
 * @since 2.1.0
 */
public record AuthSession(
        String sessionId,
        String userId,
        AuthSessionStatus status,
        LoginMethod loginMethod,
        String idp,
        String amr,
        Instant createdAt,
        Instant lastSeenAt,
        Instant expiresAt,
        @Nullable Instant revokedAt) {

    /**
     * Returns whether the session can still be used at the given time.
     * <p>
     * 回傳 Session 在指定時間是否仍可使用。
     *
     * @param now  the current time
     *             <br>目前時間
     * @return {@code true} if active and not expired
     *         <br>為 {@code ACTIVE} 且未到期時為 {@code true}
     */
    public boolean isUsable(Instant now) {
        return status == AuthSessionStatus.ACTIVE && expiresAt.isAfter(now);
    }
}
