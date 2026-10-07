package jacky917.security.core;

/**
 * Names of the JWT claims that jacky917-security issues and reads.
 * <p>
 * jacky917-security 簽發與讀取的 JWT claim 名稱。
 * <p>
 * The authorization server writes these claims and the resource server
 * starter reads them, so both sides share one definition. Standard claims
 * such as {@code sub} and {@code aud} are not listed here.
 * <p>
 * 由 Authorization Server 寫入、Resource Server starter 讀取，因此兩端共用同一份
 * 定義。{@code sub}、{@code aud} 等標準 claim 不列於此。
 *
 * @since 2.0.0
 */
public final class Jacky917ClaimNames {

    /**
     * Roles of the user, without the {@code ROLE_} prefix.
     * <p>
     * 使用者的角色，不含 {@code ROLE_} 前綴。
     */
    public static final String ROLES = "roles";

    /**
     * Permissions of the user, without the {@code PERM_} prefix.
     * <p>
     * 使用者的權限，不含 {@code PERM_} 前綴。
     */
    public static final String PERMISSIONS = "permissions";

    /**
     * OAuth 2.0 scopes as a space-separated string or an array.
     * <p>
     * OAuth 2.0 scope，為空白分隔字串或陣列。
     */
    public static final String SCOPE = "scope";

    /**
     * OAuth 2.0 scopes as an array, used by some identity providers.
     * <p>
     * 以陣列表示的 OAuth 2.0 scope，部分身分提供者使用。
     */
    public static final String SCP = "scp";

    /**
     * Identifier of the login session that issued the access token.
     * <p>
     * 簽發此 Access Token 的登入 Session 識別碼。
     * <p>
     * It is deliberately not {@code sid}: the ID token's {@code sid} is
     * managed by Spring Security for OIDC logout and has a different value.
     * <p>
     * 刻意不使用 {@code sid}：ID Token 的 {@code sid} 由 Spring Security 管理，
     * 用於 OIDC 登出，值也不同。
     */
    public static final String ASID = "asid";

    /**
     * Identity provider used for the login, for example {@code local} or
     * {@code google}.
     * <p>
     * 本次登入使用的身分提供者，例如 {@code local}、{@code google}。
     */
    public static final String IDP = "idp";

    /**
     * Client that obtained the token.
     * <p>
     * 取得此 Token 的 client。
     */
    public static final String CLIENT_ID = "client_id";

    private Jacky917ClaimNames() {
    }
}
