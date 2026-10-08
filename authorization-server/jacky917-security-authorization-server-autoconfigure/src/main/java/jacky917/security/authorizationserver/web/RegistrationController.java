package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.account.AccountPaths;
import jacky917.security.authorizationserver.account.RegistrationService;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.support.Columns;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The pages to register an account and to verify its email address (phase
 * 3 and 4 design §5.4). The bean exists only when
 * {@code jacky917.security.authorization-server.account.registration.enabled}
 * is {@code true}.
 * <p>
 * 註冊帳號與驗證 Email 的頁面（第 3、4 階段設計 §5.4）。只有
 * {@code jacky917.security.authorization-server.account.registration.enabled}
 * 為 {@code true} 時才有這個 Bean。
 * <p>
 * After a valid form, the page always says that a link was sent, whether
 * the address was new, an unfinished registration or an existing account.
 * <p>
 * 表單內容正確時，無論地址是新的、未完成的註冊，還是既有帳號，頁面一律表示
 * 已寄出連結。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Controller
public class RegistrationController {

    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s]+");
    private static final int EMAIL_MAX_LENGTH = 255;
    private static final String[] PAGE_KEYS = {"register.title", "register.email", "register.display-name",
            "register.password", "register.confirm", "register.submit", "register.sent", "register.resend",
            "register.sign-in", "verify.title", "verify.message", "verify.password", "verify.submit",
            "verify.invalid", "verify.done", "verify.sign-in"};

    private final RegistrationService registrations;
    private final PasswordPolicy policy;
    private final PageSupport page;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties     the authorization server properties
     *                       <br>Authorization Server 設定屬性
     * @param registrations  registers accounts and verifies emails
     *                       <br>註冊帳號並驗證 Email
     * @param policy         checks the password and shows its rules
     *                       <br>檢查密碼並顯示其規則
     */
    public RegistrationController(AuthorizationServerProperties properties, RegistrationService registrations,
                                  PasswordPolicy policy) {
        this.registrations = registrations;
        this.policy = policy;
        this.page = new PageSupport(properties.getBranding());
    }

    /**
     * Shows the registration form.
     * <p>
     * 顯示註冊表單。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view
     *         <br>畫面
     */
    @GetMapping(AccountPaths.REGISTER)
    public String form(HttpServletRequest request, Model model) {
        populate(request, model);
        return "jacky917/register";
    }

    /**
     * Registers the account, or shows the form again with an error.
     * <p>
     * 註冊帳號；表單內容有誤時帶著錯誤再次顯示表單。
     *
     * @param email            the email address
     *                         <br>Email
     * @param displayName      the user's name; may be empty
     *                         <br>使用者名稱，可以留白
     * @param password         the password
     *                         <br>密碼
     * @param confirmPassword  the password again
     *                         <br>再次輸入的密碼
     * @param request          the current request
     *                         <br>目前的請求
     * @param model            the view model
     *                         <br>畫面資料
     * @return the view saying that a link was sent, or the form with an error
     *         <br>表示已寄出連結的畫面，或帶著錯誤的表單
     */
    @PostMapping(AccountPaths.REGISTER)
    public String register(@RequestParam String email, @RequestParam(required = false) @Nullable String displayName,
                           @RequestParam String password, @RequestParam String confirmPassword,
                           HttpServletRequest request, Model model) {
        populate(request, model);
        Locale locale = RequestContextUtils.getLocale(request);
        String address = email.strip();
        String name = StringUtils.hasText(displayName) ? displayName.strip() : null;
        model.addAttribute("email", address);
        model.addAttribute("displayName", name);
        String error = check(address, name, password, confirmPassword);
        if (error != null) {
            model.addAttribute("error", page.message(error, null, locale));
            return "jacky917/register";
        }
        registrations.register(address, name, password, request, locale);
        model.addAttribute("sent", true);
        return "jacky917/register";
    }

    /**
     * Sends the verification link again, and answers the same way for every
     * address.
     * <p>
     * 重新寄出驗證連結；對每一個地址都以相同方式回應。
     *
     * @param email    the email address
     *                 <br>Email
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view saying that a link was sent
     *         <br>表示已寄出連結的畫面
     */
    @PostMapping(AccountPaths.RESEND_VERIFICATION)
    public String resend(@RequestParam String email, HttpServletRequest request, Model model) {
        populate(request, model);
        String address = email.strip();
        if (address.length() <= EMAIL_MAX_LENGTH && EMAIL.matcher(address).matches()) {
            registrations.resendVerification(address, RequestContextUtils.getLocale(request));
        }
        model.addAttribute("email", address);
        model.addAttribute("sent", true);
        return "jacky917/register";
    }

    /**
     * Shows the form that confirms the email address, if the link still
     * works. Opening the link changes nothing, so a mail scanner that opens
     * links cannot use it.
     * <p>
     * 若連結仍有效，顯示確認 Email 的表單。開啟連結不會變更任何資料，因此預先
     * 開啟連結的郵件掃描器無法用掉它。
     *
     * @param token    the token from the link
     *                 <br>連結中的 token
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view
     *         <br>畫面
     */
    @GetMapping(AccountPaths.VERIFY_EMAIL)
    public String verifyForm(@RequestParam(required = false) @Nullable String token, HttpServletRequest request,
                             Model model) {
        populate(request, model);
        boolean valid = token != null && registrations.isValid(token);
        model.addAttribute("valid", valid);
        model.addAttribute("token", valid ? token : null);
        return "jacky917/verify-email";
    }

    /**
     * Verifies the email address with the password chosen when registering.
     * <p>
     * 以註冊時設定的密碼驗證 Email。
     *
     * @param token     the token from the link
     *                  <br>連結中的 token
     * @param password  the password chosen when registering
     *                  <br>註冊時設定的密碼
     * @param request   the current request
     *                  <br>目前的請求
     * @param model     the view model
     *                  <br>畫面資料
     * @return the view: done, the form again with an error, or the link is
     *         no longer valid
     *         <br>畫面：完成、帶著錯誤的表單，或連結已失效
     */
    @PostMapping(AccountPaths.VERIFY_EMAIL)
    public String verify(@RequestParam String token, @RequestParam String password, HttpServletRequest request,
                         Model model) {
        populate(request, model);
        switch (registrations.verify(token, password, request)) {
            case VERIFIED -> {
                model.addAttribute("valid", true);
                model.addAttribute("done", true);
            }
            case WRONG_PASSWORD -> {
                model.addAttribute("valid", true);
                model.addAttribute("token", token);
                model.addAttribute("error", page.message("verify.error.wrong-password", null,
                        RequestContextUtils.getLocale(request)));
            }
            case INVALID_LINK -> model.addAttribute("valid", false);
        }
        return "jacky917/verify-email";
    }

    private @Nullable String check(String email, @Nullable String displayName, String password,
                                   String confirmPassword) {
        if (email.length() > EMAIL_MAX_LENGTH || !EMAIL.matcher(email).matches()) {
            return "register.error.email";
        }
        if (displayName != null && displayName.length() > Columns.DISPLAY_NAME) {
            return "register.error.display-name";
        }
        if (!password.equals(confirmPassword)) {
            return "register.error.mismatch";
        }
        try {
            policy.check(password);
        } catch (IllegalArgumentException ex) {
            return "register.error.weak-password";
        }
        return null;
    }

    private void populate(HttpServletRequest request, Model model) {
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
        model.addAttribute("rules", page.message("password.rules", new Object[]{policy.minLength(),
                PasswordPolicy.MAX_BYTES}, locale));
    }
}
