package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.mfa.QrCodes;
import jacky917.security.authorizationserver.mfa.Totp;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;

/**
 * Builds the page that turns two-step verification on: the QR code for the
 * authenticator app and the key to type in instead.
 * <p>
 * 產生啟用兩步驟驗證的頁面資料：驗證器 App 掃描的 QR code，以及改為手動輸入
 * 時的金鑰。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class MfaSetupSupport {

    private final UserAccountService users;
    private final String issuer;

    /**
     * Creates the support.
     * <p>
     * 建立此支援類別。
     *
     * @param properties  the authorization server properties: the name the
     *                    app shows ({@code mfa.issuer-name}, or
     *                    {@code branding.product-name})
     *                    <br>Authorization Server 設定屬性：App 顯示的名稱
     *                    （{@code mfa.issuer-name}，或
     *                    {@code branding.product-name}）
     * @param users       reads the account name the app shows
     *                    <br>讀取 App 顯示的帳號名稱
     */
    public MfaSetupSupport(AuthorizationServerProperties properties, UserAccountService users) {
        this.users = users;
        String configured = properties.getMfa().getIssuerName();
        this.issuer = StringUtils.hasText(configured) ? configured : properties.getBranding().getProductName();
    }

    /**
     * Creates a new secret.
     * <p>
     * 產生新的密鑰。
     *
     * @return the Base32 secret
     *         <br>Base32 編碼的密鑰
     */
    public static String newSecret() {
        return Totp.newSecret();
    }

    /**
     * Adds the QR code, the key and the form address to a model.
     * <p>
     * 把 QR code、金鑰與表單網址加入畫面資料。
     *
     * @param model   the view model
     *                <br>畫面資料
     * @param userId  the user
     *                <br>使用者
     * @param secret  the Base32 secret
     *                <br>Base32 編碼的密鑰
     * @param action  where the form posts the code
     *                <br>表單送出驗證碼的網址
     */
    public void populate(Model model, String userId, String secret, String action) {
        String account = users.findById(userId).map(MfaSetupSupport::accountName).orElse(userId);
        model.addAttribute("qrCode", QrCodes.svgDataUri(Totp.uri(issuer, account, secret)));
        // 每 4 個字元加一個空白，方便手動輸入
        model.addAttribute("secret", secret.replaceAll("(.{4})(?!$)", "$1 "));
        model.addAttribute("action", action);
    }

    private static String accountName(UserAccount user) {
        if (StringUtils.hasText(user.email())) {
            return user.email();
        }
        return StringUtils.hasText(user.username()) ? user.username() : user.id();
    }
}
