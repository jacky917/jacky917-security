package jacky917.security.authorizationserver.account;

/**
 * Paths of the account self-service pages.
 * <p>
 * 帳號自助功能頁面的路徑。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class AccountPaths {

    /**
     * Changing the password of a logged-in user.
     * <p>
     * 已登入使用者變更密碼。
     */
    public static final String CHANGE_PASSWORD = "/jacky917/account/password";

    /**
     * Asking for a password reset link.
     * <p>
     * 要求重設密碼連結。
     */
    public static final String FORGOT_PASSWORD = "/jacky917/password/forgot";

    /**
     * Setting a new password from a reset link.
     * <p>
     * 從重設連結設定新密碼。
     */
    public static final String RESET_PASSWORD = "/jacky917/password/reset";

    /**
     * Registering an account.
     * <p>
     * 註冊帳號。
     */
    public static final String REGISTER = "/jacky917/register";

    /**
     * Confirming an email address from a verification link.
     * <p>
     * 從驗證連結確認 Email。
     */
    public static final String VERIFY_EMAIL = "/jacky917/verify-email";

    /**
     * Browser session attribute marking a login that must change its
     * password before doing anything else.
     * <p>
     * 標記「登入後必須先變更密碼」的瀏覽器 Session 屬性。
     */
    public static final String PASSWORD_CHANGE_REQUIRED_ATTRIBUTE =
            AccountPaths.class.getName() + ".PASSWORD_CHANGE_REQUIRED";

    private AccountPaths() {
    }
}
