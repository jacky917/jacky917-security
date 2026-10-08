package jacky917.security.authorizationserver.session;

/**
 * Why a login session was revoked ({@code auth_session.revoke_reason},
 * detailed design §5.6).
 * <p>
 * 登入 Session 被撤銷的原因（{@code auth_session.revoke_reason}，詳細設計
 * §5.6）。
 * <p>
 * The database also allows {@code EXPIRED}, which is reserved: expired
 * sessions get the status {@code EXPIRED} and no revoke reason.
 * <p>
 * 資料庫另外允許 {@code EXPIRED}，此值為保留值：過期的 Session 狀態為
 * {@code EXPIRED}，不記錄撤銷原因。
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
     * An administrator ended the session. Reserved for the administration
     * API; nothing in this starter revokes with it yet.
     * <p>
     * 管理員結束 Session。保留給管理 API；本 starter 目前沒有以此原因撤銷。
     */
    ADMIN,

    /**
     * The password changed after this session was created, by the user or
     * by an administrator.
     * <p>
     * 密碼在此 Session 建立之後被變更（由使用者或管理員）。
     */
    PASSWORD_CHANGED,

    /**
     * The user no longer exists, or is not {@code ACTIVE} (disabled, locked
     * by an administrator, deleted). A temporary lock after failed logins
     * does not revoke sessions.
     * <p>
     * 使用者已不存在，或不是 {@code ACTIVE}（停用、被管理員鎖定、已刪除）。
     * 登入失敗造成的暫時鎖定不會撤銷 Session。
     */
    USER_DISABLED
}
