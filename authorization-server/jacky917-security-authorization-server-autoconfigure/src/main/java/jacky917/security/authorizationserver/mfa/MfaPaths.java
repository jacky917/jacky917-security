package jacky917.security.authorizationserver.mfa;

/**
 * The paths of the two-step verification pages.
 * <p>
 * 兩步驟驗證頁面的路徑。
 *
 * @author Jacky
 * @since 2.1.0
 */
public final class MfaPaths {

    /**
     * Entering a code to complete a login.
     * <p>
     * 輸入驗證碼以完成登入。
     */
    public static final String VERIFY = "/jacky917/mfa";

    /**
     * Turning two-step verification on to complete a login, for users who
     * must use it.
     * <p>
     * 為必須使用兩步驟驗證的使用者，在完成登入前啟用它。
     */
    public static final String SETUP = "/jacky917/mfa/setup";

    /**
     * Giving up a login that waits for the second step.
     * <p>
     * 放棄等待第二步的登入。
     */
    public static final String CANCEL = "/jacky917/mfa/cancel";

    /**
     * Two-step verification on the account page.
     * <p>
     * 帳號頁的兩步驟驗證。
     */
    public static final String ACCOUNT = "/jacky917/account/mfa";

    /**
     * Replacing the recovery codes.
     * <p>
     * 取代復原碼。
     */
    public static final String ACCOUNT_RECOVERY_CODES = ACCOUNT + "/recovery-codes";

    /**
     * Turning two-step verification off.
     * <p>
     * 停用兩步驟驗證。
     */
    public static final String ACCOUNT_DISABLE = ACCOUNT + "/disable";

    private MfaPaths() {
    }
}
