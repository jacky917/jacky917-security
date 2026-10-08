package jacky917.security.authorizationserver.session;

/**
 * How the user logged in.
 * <p>
 * 使用者的登入方式。
 *
 * @author Jacky
 * @since 2.1.0
 */
public enum LoginMethod {

    /**
     * Username or email with a password.
     * <p>
     * 帳號或 Email 搭配密碼。
     */
    PASSWORD,

    /**
     * Through an external identity provider such as Google.
     * <p>
     * 透過外部身分提供者，例如 Google。
     */
    FEDERATED;

    /**
     * The identity provider recorded for password logins, in login sessions,
     * audit events and the access token {@code idp} claim.
     * <p>
     * 密碼登入所記錄的身分提供者，用於登入 Session、稽核事件與 Access Token 的
     * {@code idp} claim。
     */
    public static final String LOCAL_IDP = "local";
}
