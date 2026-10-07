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
    FEDERATED
}
