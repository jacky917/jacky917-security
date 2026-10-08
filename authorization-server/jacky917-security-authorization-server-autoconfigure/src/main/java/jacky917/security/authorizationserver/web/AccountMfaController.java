package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.mfa.MfaPaths;
import jacky917.security.authorizationserver.mfa.MfaService;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.time.Clock;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Two-step verification on the account page (phase 3 and 4 design §7.1):
 * turning it on with an authenticator app, replacing the recovery codes
 * and turning it off. Replacing and turning off need a current code.
 * <p>
 * 帳號頁的兩步驟驗證（第 3、4 階段設計 §7.1）：以驗證器 App 啟用、取代復原碼
 * 與停用。取代與停用需要目前的驗證碼。
 * <p>
 * Users with a role in {@code mfa.required-roles} cannot turn it off.
 * <p>
 * 擁有 {@code mfa.required-roles} 中角色的使用者不能停用。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Controller
public class AccountMfaController {

    private static final String SECRET_ATTRIBUTE = AccountMfaController.class.getName() + ".SECRET";
    private static final String[] PAGE_KEYS = {"mfa.account.title", "mfa.account.enabled-at",
            "mfa.account.remaining", "mfa.account.regenerate", "mfa.account.disable", "mfa.account.required",
            "mfa.account.low", "mfa.code", "mfa.setup.title", "mfa.setup.scan", "mfa.setup.key", "mfa.setup.code",
            "mfa.setup.submit", "mfa.codes.title", "mfa.codes.message", "mfa.codes.continue", "password.change.back"};

    private final MfaService mfa;
    private final MfaSetupSupport setup;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final ZoneId zone;
    private final PageSupport page;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 設定屬性
     * @param mfa         turns two-step verification on and off
     *                    <br>啟用與停用兩步驟驗證
     * @param setup       builds the setup page
     *                    <br>產生啟用頁面
     * @param events      publishes the audit events
     *                    <br>發布稽核事件
     * @param clock       the clock
     *                    <br>時鐘
     * @param zone        the time zone in which times are shown
     *                    <br>顯示時間所用的時區
     */
    public AccountMfaController(AuthorizationServerProperties properties, MfaService mfa, MfaSetupSupport setup,
                                ApplicationEventPublisher events, Clock clock, ZoneId zone) {
        this.mfa = mfa;
        this.setup = setup;
        this.events = events;
        this.clock = clock;
        this.zone = zone;
        this.page = new PageSupport(properties.getBranding());
    }

    /**
     * Shows the state of two-step verification, or how to turn it on.
     * <p>
     * 顯示兩步驟驗證的狀態，或啟用方式。
     *
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @param model           the view model
     *                        <br>畫面資料
     * @return the view
     *         <br>畫面
     */
    @GetMapping(MfaPaths.ACCOUNT)
    public String show(Authentication authentication, HttpServletRequest request, Model model) {
        return page(authentication.getName(), request, model, null);
    }

    /**
     * Turns two-step verification on and shows the recovery codes once.
     * <p>
     * 啟用兩步驟驗證，並顯示一次復原碼。
     *
     * @param code            the code from the authenticator app
     *                        <br>驗證器 App 的驗證碼
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @param model           the view model
     *                        <br>畫面資料
     * @return the recovery codes, or the page again with an error
     *         <br>復原碼，或帶著錯誤再次顯示的頁面
     */
    @PostMapping(MfaPaths.ACCOUNT)
    public String enable(@RequestParam String code, Authentication authentication, HttpServletRequest request,
                         Model model) {
        String userId = authentication.getName();
        Optional<List<String>> codes = mfa.enable(userId, secret(request), code);
        if (codes.isEmpty()) {
            return page(userId, request, model, "mfa.error.code");
        }
        request.getSession().removeAttribute(SECRET_ATTRIBUTE);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.MFA_ENABLED, clock.instant(), true)
                .userId(userId).request(request).build());
        return codes(request, model, codes.get());
    }

    /**
     * Replaces the recovery codes and shows the new ones once.
     * <p>
     * 取代復原碼，並顯示一次新的復原碼。
     *
     * @param code            the code from the authenticator app
     *                        <br>驗證器 App 的驗證碼
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @param model           the view model
     *                        <br>畫面資料
     * @return the recovery codes, or the page again with an error
     *         <br>復原碼，或帶著錯誤再次顯示的頁面
     */
    @PostMapping(MfaPaths.ACCOUNT_RECOVERY_CODES)
    public String regenerate(@RequestParam String code, Authentication authentication, HttpServletRequest request,
                             Model model) {
        Optional<List<String>> codes = mfa.regenerateRecoveryCodes(authentication.getName(), code);
        return codes.isPresent() ? codes(request, model, codes.get())
                : page(authentication.getName(), request, model, "mfa.error.code");
    }

    /**
     * Turns two-step verification off.
     * <p>
     * 停用兩步驟驗證。
     *
     * @param code            a code from the authenticator app or a
     *                        recovery code
     *                        <br>驗證器 App 的驗證碼或復原碼
     * @param authentication  the logged-in user
     *                        <br>已登入的使用者
     * @param request         the current request
     *                        <br>目前的請求
     * @param model           the view model
     *                        <br>畫面資料
     * @return a redirect to the account page, or the page again with an
     *         error
     *         <br>重導至帳號頁，或帶著錯誤再次顯示的頁面
     */
    @PostMapping(MfaPaths.ACCOUNT_DISABLE)
    public String disable(@RequestParam String code, Authentication authentication, HttpServletRequest request,
                          Model model) {
        String userId = authentication.getName();
        if (mfa.isRequired(userId)) {
            return page(userId, request, model, "mfa.account.required");
        }
        if (mfa.verify(userId, code) == MfaService.Verification.INVALID) {
            return page(userId, request, model, "mfa.error.code");
        }
        if (mfa.disable(userId)) {
            events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.MFA_DISABLED, clock.instant(), true)
                    .userId(userId).request(request).build());
        }
        return "redirect:" + AccountController.ACCOUNT_PATH + "?notice=mfa_disabled";
    }

    private String page(String userId, HttpServletRequest request, Model model, @Nullable String errorKey) {
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
        if (errorKey != null) {
            model.addAttribute("error", page.message(errorKey, null, locale));
        }
        Optional<MfaService.Status> status = mfa.status(userId);
        if (status.isEmpty()) {
            setup.populate(model, userId, secret(request), MfaPaths.ACCOUNT);
            model.addAttribute("required", false);
            return "jacky917/mfa-setup";
        }
        DateTimeFormatter format = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z", locale).withZone(zone);
        model.addAttribute("enabledAt", format.format(status.get().enabledAt()));
        model.addAttribute("remaining", status.get().remainingRecoveryCodes());
        model.addAttribute("canDisable", !mfa.isRequired(userId));
        return "jacky917/account-mfa";
    }

    private String codes(HttpServletRequest request, Model model, List<String> codes) {
        page.populate(model, RequestContextUtils.getLocale(request), PAGE_KEYS);
        model.addAttribute("codes", codes);
        model.addAttribute("next", request.getContextPath() + AccountController.ACCOUNT_PATH);
        return "jacky917/mfa-codes";
    }

    private String secret(HttpServletRequest request) {
        // 密鑰在確認之前只存在瀏覽器 Session，重新整理頁面時沿用同一個
        if (request.getSession().getAttribute(SECRET_ATTRIBUTE) instanceof String secret) {
            return secret;
        }
        String secret = MfaSetupSupport.newSecret();
        request.getSession().setAttribute(SECRET_ATTRIBUTE, secret);
        return secret;
    }
}
