package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.account.AccountLinks;
import jacky917.security.authorizationserver.account.AccountMail;
import jacky917.security.authorizationserver.account.AccountMailer;
import jacky917.security.authorizationserver.account.AccountPaths;
import jacky917.security.authorizationserver.account.ActionTokenService;
import jacky917.security.authorizationserver.account.PasswordChangeService;
import jacky917.security.authorizationserver.account.PasswordChangeService.Outcome;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

/**
 * Forgotten passwords: asking for a reset link and setting a new password
 * from it (phase 3 and 4 design §5.3).
 * <p>
 * 忘記密碼：要求重設連結，並以連結設定新密碼（第 3、4 階段設計 §5.3）。
 * <ul>
 *   <li>A link is sent only to a verified email of an account that can log
 *       in; the page always says the same thing, so it never reveals
 *       whether an account exists.
 *       <br>只對可登入帳號的已驗證 Email 寄出連結；頁面一律顯示相同的訊息，
 *       不會透露帳號是否存在。</li>
 *   <li>Opening the link only shows the form; the token is used when the
 *       new password is submitted, so a mail scanner that opens links cannot
 *       use it.
 *       <br>開啟連結只會顯示表單；送出新密碼時才使用 token，因此預先開啟連結
 *       的郵件掃描器無法用掉它。</li>
 *   <li>Setting the password clears a temporary lock and the forced change,
 *       and revokes every login session.
 *       <br>設定密碼後清除暫時鎖定與強制變更，並撤銷所有登入 Session。</li>
 * </ul>
 * The pages exist only when mails can be sent.
 * <p>
 * 只有在可以寄信時才提供這些頁面。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
@Controller
public class PasswordResetController {

    private static final String[] PAGE_KEYS = {"password.forgot.title", "password.forgot.message",
            "password.forgot.email", "password.forgot.submit", "password.forgot.sent", "password.reset.title",
            "password.reset.new", "password.reset.confirm", "password.reset.submit", "password.reset.invalid",
            "password.reset.done", "password.reset.sign-in"};

    private final UserAccountService users;
    private final ActionTokenService tokens;
    private final PasswordChangeService passwords;
    private final PasswordPolicy policy;
    private final AccountMailer mailer;
    private final AccountLinks links;
    private final Duration resetTtl;
    private final PageSupport page;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties  the authorization server properties
     *                    <br>Authorization Server 設定屬性
     * @param users       finds the user of an email
     *                    <br>依 Email 找到使用者
     * @param tokens      issues and uses the reset tokens
     *                    <br>發出與使用重設 token
     * @param passwords   sets the new password
     *                    <br>設定新密碼
     * @param policy      the password rules, shown on the page
     *                    <br>密碼規則，顯示在頁面上
     * @param mailer      sends the link
     *                    <br>寄出連結
     * @param links       builds the link
     *                    <br>產生連結
     */
    public PasswordResetController(AuthorizationServerProperties properties, UserAccountService users,
                                   ActionTokenService tokens, PasswordChangeService passwords, PasswordPolicy policy,
                                   AccountMailer mailer, AccountLinks links) {
        this.users = users;
        this.tokens = tokens;
        this.passwords = passwords;
        this.policy = policy;
        this.mailer = mailer;
        this.links = links;
        this.resetTtl = properties.getAccount().getPasswordResetTtl();
        this.page = new PageSupport(properties.getBranding());
    }

    /**
     * Shows the form to ask for a reset link.
     * <p>
     * 顯示要求重設連結的表單。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view
     *         <br>畫面
     */
    @GetMapping(AccountPaths.FORGOT_PASSWORD)
    public String forgot(HttpServletRequest request, Model model) {
        requireMail();
        populate(request, model);
        return "jacky917/password-forgot";
    }

    /**
     * Sends a reset link if the email belongs to an account that can log
     * in, and answers the same way in every case.
     * <p>
     * 若 Email 屬於可登入的帳號則寄出重設連結；無論如何都以相同方式回應。
     *
     * @param email    the email address
     *                 <br>Email
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view saying that a mail was sent if the account exists
     *         <br>表示「若帳號存在已寄出信件」的畫面
     */
    @PostMapping(AccountPaths.FORGOT_PASSWORD)
    public String sendLink(@RequestParam String email, HttpServletRequest request, Model model) {
        requireMail();
        Locale locale = RequestContextUtils.getLocale(request);
        users.findByVerifiedEmail(email.strip())
                .filter(user -> user.status() == UserStatus.ACTIVE)
                .ifPresent(user -> send(user, locale));
        populate(request, model);
        model.addAttribute("sent", true);
        return "jacky917/password-forgot";
    }

    /**
     * Shows the form to set a new password, if the link still works.
     * <p>
     * 若連結仍有效，顯示設定新密碼的表單。
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
    @GetMapping(AccountPaths.RESET_PASSWORD)
    public String resetForm(@RequestParam(required = false) @Nullable String token, HttpServletRequest request,
                            Model model) {
        requireMail();
        populate(request, model);
        boolean valid = token != null && tokens.find(token, ActionTokenService.Purpose.PASSWORD_RESET).isPresent();
        model.addAttribute("valid", valid);
        model.addAttribute("token", valid ? token : null);
        return "jacky917/password-reset";
    }

    /**
     * Sets the new password and uses the link.
     * <p>
     * 設定新密碼並使用連結。
     *
     * @param token            the token from the link
     *                         <br>連結中的 token
     * @param newPassword      the new password
     *                         <br>新密碼
     * @param confirmPassword  the new password again
     *                         <br>再次輸入的新密碼
     * @param request          the current request
     *                         <br>目前的請求
     * @param model            the view model
     *                         <br>畫面資料
     * @return the view: done, the form again with an error, or the link is
     *         no longer valid
     *         <br>畫面：完成、帶著錯誤的表單，或連結已失效
     */
    @PostMapping(AccountPaths.RESET_PASSWORD)
    public String reset(@RequestParam String token, @RequestParam String newPassword,
                        @RequestParam String confirmPassword, HttpServletRequest request, Model model) {
        requireMail();
        populate(request, model);
        Locale locale = RequestContextUtils.getLocale(request);
        Optional<UserAccount> user = tokens.find(token, ActionTokenService.Purpose.PASSWORD_RESET)
                .flatMap(users::findById).filter(found -> found.status() == UserStatus.ACTIVE);
        if (user.isEmpty()) {
            model.addAttribute("valid", false);
            return "jacky917/password-reset";
        }
        model.addAttribute("valid", true);
        model.addAttribute("token", token);
        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("error", page.message("password.error.mismatch", null, locale));
            return "jacky917/password-reset";
        }
        Outcome invalid = passwords.validate(user.get(), newPassword);
        if (invalid != null) {
            model.addAttribute("error", page.message("password.error."
                    + invalid.name().toLowerCase(Locale.ROOT).replace('_', '-'), null, locale));
            return "jacky917/password-reset";
        }
        // 先用掉 token（只能使用一次），再設定密碼
        if (tokens.consume(token, ActionTokenService.Purpose.PASSWORD_RESET).isEmpty()) {
            model.addAttribute("valid", false);
            return "jacky917/password-reset";
        }
        passwords.reset(user.get(), newPassword, request);
        model.addAttribute("done", true);
        return "jacky917/password-reset";
    }

    private void send(UserAccount user, Locale locale) {
        Optional<String> token = tokens.issue(user.id(), ActionTokenService.Purpose.PASSWORD_RESET, resetTtl);
        if (token.isEmpty()) {
            log.info("Not sending another password reset link to user {} so soon", user.id());
            return;
        }
        try {
            mailer.send(new AccountMail(AccountMail.Type.PASSWORD_RESET, user.email(), locale, user.displayName(),
                    links.withToken(AccountPaths.RESET_PASSWORD, token.get()), resetTtl));
            log.info("Sent a password reset link to user {}", user.id());
        } catch (RuntimeException ex) {
            log.error("Cannot send the password reset link to user {}", user.id(), ex);
        }
    }

    private void requireMail() {
        if (!mailer.isAvailable()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }

    private void populate(HttpServletRequest request, Model model) {
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
        model.addAttribute("rules", page.message("password.rules", new Object[]{policy.minLength(),
                PasswordPolicy.MAX_LENGTH}, locale));
    }
}
