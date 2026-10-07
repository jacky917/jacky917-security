package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.context.MessageSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
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
 * Every login error shows the same text (detailed design §7.2), so the
 * page never reveals whether an account exists or is locked.
 * <p>
 * 文字取自 starter 自己的訊息檔（{@code jacky917/authorization-server-messages}），
 * 依請求的語言顯示，不影響應用程式的 {@code MessageSource}。所有登入錯誤都顯示
 * 相同的文字（詳細設計 §7.2），頁面因此不會透露帳號是否存在或被鎖定。
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
            "login.or", "signed-in.title", "signed-in.message"};

    private final AuthorizationServerProperties.Branding branding;
    private final MessageSource messages;
    private final List<Provider> providers;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties           the authorization server properties
     *                             <br>Authorization Server 設定屬性
     * @param clientRegistrations  the identity providers shown as buttons,
     *                             or {@code null} without any
     *                             <br>顯示為按鈕的身分提供者；沒有時為 {@code null}
     */
    public LoginController(AuthorizationServerProperties properties,
                           @Nullable ClientRegistrationRepository clientRegistrations) {
        this.branding = properties.getBranding();
        List<Provider> found = new ArrayList<>();
        if (clientRegistrations instanceof Iterable<?> registrations) {
            for (Object registration : registrations) {
                ClientRegistration client = (ClientRegistration) registration;
                found.add(new Provider(client.getRegistrationId(), client.getClientName()));
            }
        }
        this.providers = List.copyOf(found);
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("jacky917/authorization-server-messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        this.messages = source;
    }

    /**
     * Shows the login page.
     * <p>
     * 顯示登入頁。
     *
     * @param error    present after a failed login; its value selects the
     *                 message
     *                 <br>登入失敗後出現，值決定顯示的訊息
     * @param request  the current request, for its language
     *                 <br>目前的請求，用於判斷語言
     * @param model    the view model
     *                 <br>畫面資料
     * @return the login view
     *         <br>登入頁面
     */
    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error, HttpServletRequest request, Model model) {
        Locale locale = RequestContextUtils.getLocale(request);
        populate(model, locale);
        // 「?error」沒有值：依容器不同可能是空字串或 null，因此以參數是否存在判斷
        if (request.getParameterMap().containsKey("error")) {
            String key = switch (error == null ? "" : error) {
                case "rate_limited" -> "login.error.rate-limited";
                case "federation" -> "login.error.federation";
                case "account_exists" -> "login.error.account-exists";
                default -> "login.error.bad-credentials";
            };
            model.addAttribute("error", messages.getMessage(key, null, locale));
        }
        return "jacky917/login";
    }

    /**
     * Shows a confirmation after logging in without an authorization
     * request, for example by opening the login page directly.
     * <p>
     * 在沒有授權請求的情況下登入後（例如直接開啟登入頁）顯示的確認頁。
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
        populate(model, RequestContextUtils.getLocale(request));
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
        Map<String, String> text = new LinkedHashMap<>();
        for (String key : PAGE_KEYS) {
            text.put(key, messages.getMessage(key, null, locale));
        }
        model.addAttribute("text", text);
        model.addAttribute("lang", locale.toLanguageTag());
        model.addAttribute("productName", branding.getProductName());
        model.addAttribute("logoUrl", branding.getLogoUrl());
        List<Map<String, String>> buttons = new ArrayList<>();
        for (Provider provider : providers) {
            buttons.add(Map.of("url", "/oauth2/authorization/" + provider.registrationId(),
                    "label", messages.getMessage("login.with", new Object[]{provider.name()}, locale)));
        }
        model.addAttribute("providers", buttons);
    }

    private record Provider(String registrationId, String name) {
    }
}
