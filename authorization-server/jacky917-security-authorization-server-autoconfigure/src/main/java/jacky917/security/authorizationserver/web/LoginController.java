package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
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
import java.util.Comparator;
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
@Slf4j
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
            "login.or", "signed-in.title", "signed-in.message", "signed-in.account"};

    private final AuthorizationServerProperties.Branding branding;
    private final PageSupport page;
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
        this.page = new PageSupport(branding);
        this.providers = providers(properties.getLogin().getProviders(), clientRegistrations);
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
        page.populate(model, locale, PAGE_KEYS);
        List<Map<String, String>> buttons = new ArrayList<>();
        for (Provider provider : providers) {
            buttons.add(Map.of("url", "/oauth2/authorization/" + provider.registrationId(),
                    "label", page.message("login.with", new Object[]{provider.name()}, locale)));
        }
        model.addAttribute("providers", buttons);
    }

    private static List<Provider> providers(List<String> configured, @Nullable ClientRegistrationRepository repository) {
        List<Provider> found = new ArrayList<>();
        if (repository == null) {
            return found;
        }
        if (!configured.isEmpty()) {
            for (String registrationId : configured) {
                ClientRegistration client = repository.findByRegistrationId(registrationId);
                if (client == null) {
                    throw new IllegalStateException("login.providers contains " + registrationId
                            + ", but there is no client registration with that id");
                }
                found.add(new Provider(client.getRegistrationId(), client.getClientName()));
            }
        } else if (repository instanceof Iterable<?> registrations) {
            for (Object registration : registrations) {
                ClientRegistration client = (ClientRegistration) registration;
                found.add(new Provider(client.getRegistrationId(), client.getClientName()));
            }
            // Spring Boot 預設的 repository 以雜湊表保存，列出的順序不固定：依顯示名稱排序
            found.sort(Comparator.comparing(Provider::name, String.CASE_INSENSITIVE_ORDER));
        } else {
            // 無法列出的 repository（例如存放在資料庫中）：第三方登入仍可使用，但登入頁沒有按鈕
            log.warn("The ClientRegistrationRepository cannot list its registrations, so the login page shows no "
                    + "identity provider buttons; set " + AuthorizationServerProperties.PREFIX + ".login.providers");
        }
        return List.copyOf(found);
    }

    private record Provider(String registrationId, String name) {
    }
}
