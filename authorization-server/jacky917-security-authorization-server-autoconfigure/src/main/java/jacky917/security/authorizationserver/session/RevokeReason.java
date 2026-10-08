package jacky917.security.authorizationserver.session;

/**
 * Why a login session was revoked ({@code auth_session.revoke_reason},
 * detailed design §5.6).
 * <p>
 * 登入 Session 被撤銷的原因（{@code auth_session.revoke_reason}，詳細設計
 * §5.6）。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum RevokeReason {

    /**
     * The user logged out of this session.
     * <p>
     * 使用者登出此 Session。
     */
    LOGOUT,

    /**
     * The user logged out of every device.
     * <p>
     * 使用者登出所有裝置。
     */
    LOGOUT_ALL,

    /**
     * A rotated refresh token of this session was used again.
     * <p>
     * 此 Session 已輪換的 Refresh Token 再次被使用。
     */
    REUSE_DETECTED,

    /**
     * An administrator ended the session.
     * <p>
     * 管理員結束 Session。
     */
    ADMIN,

    /**
     * The user changed their password on another session.
     * <p>
     * 使用者在其他 Session 變更了密碼。
     */
    PASSWORD_CHANGED,

    /**
     * The user can no longer log in.
     * <p>
     * 使用者已無法登入。
     */
    USER_DISABLED
}
