package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.account.AccountMailer;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The login page and the page shown after logging in directly.
 * <p>
 * 登入頁，以及直接登入後顯示的頁面。
 * <p>
 * Texts come from the starter's own message bundle
 * ({@code jacky917/authorization-server-messages}) in the request's
 * language, so the application's {@code MessageSource} is not affected.
 * Every password login error shows the same text (detailed design §7.2), so
 * the page never reveals whether an account exists or is locked; rate
 * limiting, external logins and account links have their own texts.
 * <p>
 * 文字取自 starter 自己的訊息檔（{@code jacky917/authorization-server-messages}），
 * 依請求的語言顯示，不影響應用程式的 {@code MessageSource}。所有密碼登入錯誤都
 * 顯示相同的文字（詳細設計 §7.2），頁面因此不會透露帳號是否存在或被鎖定；限流、
 * 第三方登入與帳號連結有各自的文字。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Controller
public class LoginController {

    /**
     * Page shown after logging in without an authorization request. It is
     * under {@code /jacky917/} so it never clashes with the application's
     * own pages.
     * <p>
     * 在沒有授權請求的情況下登入後顯示的頁面。放在 {@code /jacky917/} 之下，
     * 不會與應用程式自己的頁面衝突。
     */
    public static final String SIGNED_IN_PATH = "/jacky917/signed-in";

    private static final String[] PAGE_KEYS = {"login.title", "login.username", "login.password", "login.submit",
            "login.or", "signed-in.title", "signed-in.message", "signed-in.account", "login.forgot"};

    private final AuthorizationServerProperties.Branding branding;
    private final PageSupport page;
    private final IdentityProviders providers;
    private final AccountMailer mailer;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties           the authorization server properties
     *                             <br>Authorization Server 設定屬性
     * @param providers            the identity providers shown as buttons
     *                             <br>顯示為按鈕的身分提供者
     * @param mailer               decides whether the forgotten password link
     *                             is shown
     *                             <br>決定是否顯示忘記密碼的連結
     */
    public LoginController(AuthorizationServerProperties properties, IdentityProviders providers,
                           AccountMailer mailer) {
        this.branding = properties.getBranding();
        this.page = new PageSupport(branding);
        this.mailer = mailer;
        this.providers = providers;
    }

    /**
     * Shows the login page.
     * <p>
     * 顯示登入頁。
     *
     * @param error    present after a failed login; its value selects the
     *                 message
     *                 <br>登入失敗後出現，值決定顯示的訊息
     * @param logout   present after logging out
     *                 <br>登出後出現
     * @param request  the current request, for its language
     *                 <br>目前的請求，用於判斷語言
     * @param model    the view model
     *                 <br>畫面資料
     * @return the login view
     *         <br>登入頁面
     */
    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error, @RequestParam(required = false) String logout,
                        HttpServletRequest request, Model model) {
        Locale locale = RequestContextUtils.getLocale(request);
        populate(model, locale);
        // 「?error」沒有值：依容器不同可能是空字串或 null，因此以參數是否存在判斷
        if (request.getParameterMap().containsKey("error")) {
            String key = switch (error == null ? "" : error) {
                case "rate_limited" -> "login.error.rate-limited";
                case "federation" -> "login.error.federation";
                case "account_exists" -> "login.error.account-exists";
                case "link_expired" -> "login.error.link-expired";
                case "link_failed" -> "login.error.link-failed";
                case "linked_elsewhere" -> "login.error.linked-elsewhere";
                case "provider_already_linked" -> "login.error.provider-already-linked";
                default -> "login.error.bad-credentials";
            };
            model.addAttribute("error", page.message(key, null, locale));
        } else if (request.getParameterMap().containsKey("logout")) {
            model.addAttribute("notice", page.message("login.logged-out", null, locale));
        }
        return "jacky917/login";
    }

    /**
     * Shows a confirmation after logging in without an authorization
     * request, for example by opening the login page directly, with the
     * reason when a pending account link could not be completed.
     * <p>
     * 在沒有授權請求的情況下登入後（例如直接開啟登入頁）顯示的確認頁；待確認的
     * 帳號連結無法完成時，一併顯示原因。
     *
     * @param request  the current request, for its language
     *                 <br>目前的請求，用於判斷語言
     * @param model    the view model
     *                 <br>畫面資料
     * @return the signed-in view
     *         <br>已登入頁面
     */
    @GetMapping(SIGNED_IN_PATH)
    public String signedIn(HttpServletRequest request, Model model) {
        Locale locale = RequestContextUtils.getLocale(request);
        populate(model, locale);
        String linkError = AccountController.takeLinkError(request);
        if (linkError != null) {
            model.addAttribute("error", page.message("account.error." + linkError, null, locale));
        }
        return "jacky917/signed-in";
    }

    /**
     * Serves the theme color as a stylesheet, because the content security
     * policy does not allow inline styles.
     * <p>
     * 以樣式表提供主題色，因為內容安全政策不允許內嵌樣式。
     *
     * @return the stylesheet
     *         <br>樣式表
     */
    @GetMapping(value = "/jacky917/theme.css", produces = "text/css")
    public ResponseEntity<String> theme() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofHours(1)))
                .contentType(MediaType.valueOf("text/css"))
                .body(":root { --jacky917-primary: " + branding.getPrimaryColor() + "; }\n");
    }

    private void populate(Model model, Locale locale) {
        page.populate(model, locale, PAGE_KEYS);
        List<Map<String, String>> buttons = new ArrayList<>();
        for (IdentityProviders.Provider provider : providers.list()) {
            buttons.add(Map.of("url", "/oauth2/authorization/" + provider.registrationId(),
                    "label", page.message("login.with", new Object[]{provider.name()}, locale)));
        }
        model.addAttribute("providers", buttons);
        model.addAttribute("forgotPassword", mailer.isAvailable());
    }
}
