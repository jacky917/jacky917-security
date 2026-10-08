package jacky917.security.authorizationserver.federation;

/**
 * The outcome of unlinking an external account.
 * <p>
 * 解除外部帳號連結的結果。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum UnlinkResult {

    /**
     * The link was removed.
     * <p>
     * 已移除連結。
     */
    UNLINKED,

    /**
     * The user has no link to that provider, for example because another
     * tab already removed it.
     * <p>
     * 使用者沒有連結該提供者，例如已在另一個分頁解除。
     */
    NOT_LINKED,

    /**
     * The link was kept because it is the user's only way to log in.
     * <p>
     * 因為這是使用者唯一的登入方式，連結未移除。
     */
    LAST_LOGIN_METHOD
}
