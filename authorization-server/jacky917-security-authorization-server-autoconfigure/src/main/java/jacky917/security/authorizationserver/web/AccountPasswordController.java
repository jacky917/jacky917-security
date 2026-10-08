package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.account.AccountPaths;
import jacky917.security.authorizationserver.account.PasswordChangeService;
import jacky917.security.authorizationserver.account.PasswordChangeService.Outcome;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.io.IOException;
import java.util.Locale;

/**
 * The page where a logged-in user changes their password, also used when
 * the password must be changed after logging in (phase 3 and 4 design
 * §5.2).
 * <p>
 * 已登入使用者變更密碼的頁面；登入後必須變更密碼時也使用此頁（第 3、4 階段
 * 設計 §5.2）。
 * <p>
 * After a forced change the browser continues to the authorization request
 * that the login interrupted; otherwise it returns to the account page.
 * <p>
 * 強制變更完成後，瀏覽器繼續被登入中斷的授權請求；否則回到帳號頁。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Controller
public class AccountPasswordController {

    private static final String[] PAGE_KEYS = {"password.change.title", "password.change.current",
            "password.change.new", "password.change.confirm", "password.change.submit", "password.change.required",
            "password.change.back"};

    private final PasswordChangeService passwords;
    private final PasswordPolicy policy;
    private final PageSupport page;
    private final SavedRequestAwareAuthenticationSuccessHandler continueAuthorization =
            new SavedRequestAwareAuthenticationSuccessHandler();

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 設定屬性
     * @param passwords   changes the password
     *                    <br>變更密碼
     * @param policy      the password rules, shown on the page
     *                    <br>密碼規則，顯示在頁面上
     */
    public AccountPasswordController(AuthorizationServerProperties properties, PasswordChangeService passwords,
                                     PasswordPolicy policy) {
        this.passwords = passwords;
        this.policy = policy;
        this.page = new PageSupport(properties.getBranding());
        continueAuthorization.setDefaultTargetUrl(AccountController.ACCOUNT_PATH);
    }

    /**
     * Shows the page.
     * <p>
     * 顯示頁面。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view
     *         <br>畫面
     */
    @GetMapping(AccountPaths.CHANGE_PASSWORD)
    public String show(HttpServletRequest request, Model model) {
        populate(request, model, null);
        return "jacky917/account-password";
    }

    /**
     * Changes the password.
     * <p>
     * 變更密碼。
     *
     * @param currentPassword  the current password
     *                         <br>目前的密碼
     * @param newPassword      the new password
     *                         <br>新密碼
     * @param confirmPassword  the new password again
     *                         <br>再次輸入的新密碼
     * @param authentication   the logged-in user
     *                         <br>已登入的使用者
     * @param request          the current request
     *                         <br>目前的請求
     * @param response         the current response
     *                         <br>目前的回應
     * @param model            the view model, when the page is shown again
     *                         <br>再次顯示頁面時的畫面資料
     * @return the page again with an error, or {@code null} after
     *         redirecting
     *         <br>帶著錯誤再次顯示的頁面；已重導時為 {@code null}
     * @throws IOException      if the redirect fails
     *                          <br>若重導失敗
     * @throws ServletException if continuing the authorization request fails
     *                          <br>若繼續授權請求失敗
     */
    @PostMapping(AccountPaths.CHANGE_PASSWORD)
    public @Nullable String change(@RequestParam String currentPassword, @RequestParam String newPassword,
                                   @RequestParam String confirmPassword, Authentication authentication,
                                   HttpServletRequest request, HttpServletResponse response, Model model)
            throws IOException, ServletException {
        if (!newPassword.equals(confirmPassword)) {
            populate(request, model, "password.error.mismatch");
            return "jacky917/account-password";
        }
        HttpSession session = request.getSession(false);
        String sessionId = session == null ? null : (String) session.getAttribute(AuthSessionService.SESSION_ATTRIBUTE);
        Outcome outcome = passwords.change(authentication.getName(), currentPassword, newPassword, sessionId, request);
        if (outcome != Outcome.CHANGED) {
            populate(request, model, "password.error." + outcome.name().toLowerCase(Locale.ROOT).replace('_', '-'));
            return "jacky917/account-password";
        }
        boolean required = session != null && session.getAttribute(AccountPaths.PASSWORD_CHANGE_REQUIRED_ATTRIBUTE) != null;
        if (session != null) {
            session.removeAttribute(AccountPaths.PASSWORD_CHANGE_REQUIRED_ATTRIBUTE);
        }
        if (required) {
            // 回到被登入中斷的授權請求；沒有時回到帳號頁
            continueAuthorization.onAuthenticationSuccess(request, response, authentication);
        } else {
            response.sendRedirect(request.getContextPath() + AccountController.ACCOUNT_PATH + "?notice=password_changed");
        }
        return null;
    }

    private void populate(HttpServletRequest request, Model model, @Nullable String errorKey) {
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
        HttpSession session = request.getSession(false);
        model.addAttribute("required", session != null
                && session.getAttribute(AccountPaths.PASSWORD_CHANGE_REQUIRED_ATTRIBUTE) != null);
        model.addAttribute("rules", page.message("password.rules", new Object[]{policy.minLength(),
                PasswordPolicy.MAX_LENGTH}, locale));
        if (errorKey != null) {
            model.addAttribute("error", page.message(errorKey, null, locale));
        }
    }
}
