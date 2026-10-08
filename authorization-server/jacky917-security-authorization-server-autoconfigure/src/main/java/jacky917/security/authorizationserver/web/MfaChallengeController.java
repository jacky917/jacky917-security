package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.authentication.AccountLockout;
import jacky917.security.authorizationserver.federation.FederatedLoginSuccessHandler;
import jacky917.security.authorizationserver.mfa.MfaLoginFlow;
import jacky917.security.authorizationserver.mfa.MfaPaths;
import jacky917.security.authorizationserver.mfa.MfaService;
import jacky917.security.authorizationserver.mfa.PendingLogin;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The second step of a login (phase 3 and 4 design §7.2): entering a code
 * from the authenticator app or a recovery code, or turning two-step
 * verification on when a role requires it.
 * <p>
 * 登入的第二步（第 3、4 階段設計 §7.2）：輸入驗證器 App 的驗證碼或復原碼，或
 * 在角色要求時啟用兩步驟驗證。
 * <ul>
 *   <li>Each wrong code is audited as a failed {@code LOGIN}
 *       ({@code MFA_FAILED}) and counts towards the account lock; after
 *       five the pending login ends and the browser goes back to the login
 *       page.
 *       <br>每次輸入錯誤都稽核為失敗的 {@code LOGIN}（{@code MFA_FAILED}），
 *       並計入帳號鎖定；錯誤五次後結束待驗證的登入，瀏覽器回到登入頁。</li>
 *   <li>Without a pending login, or after it expired, the pages send the
 *       browser to the login page.
 *       <br>沒有待驗證的登入或已逾時時，頁面把瀏覽器導向登入頁。</li>
 * </ul>
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
@Controller
public class MfaChallengeController {

    private static final String SETUP_SECRET_ATTRIBUTE = MfaChallengeController.class.getName() + ".SECRET";
    private static final String[] PAGE_KEYS = {"mfa.title", "mfa.message", "mfa.code", "mfa.submit",
            "mfa.recovery-hint", "mfa.cancel", "mfa.setup.title", "mfa.setup.required", "mfa.setup.scan",
            "mfa.setup.key", "mfa.setup.code", "mfa.setup.submit", "mfa.codes.title", "mfa.codes.message",
            "mfa.codes.continue"};

    private final MfaLoginFlow flow;
    private final MfaService mfa;
    private final MfaSetupSupport setup;
    private final UserAccountService users;
    private final AccountLockout lockout;
    private final ObjectProvider<FederatedLoginSuccessHandler> federatedLogins;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final PageSupport page;

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties       the authorization server properties
     *                         <br>Authorization Server 設定屬性
     * @param flow             holds and completes the pending login
     *                         <br>保存並完成待驗證的登入
     * @param mfa              checks the codes and turns two-step
     *                         verification on
     *                         <br>檢查驗證碼並啟用兩步驟驗證
     * @param setup            builds the setup page
     *                         <br>產生啟用頁面
     * @param users            reads the user of the pending login
     *                         <br>讀取待驗證登入的使用者
     * @param lockout          counts the wrong codes
     *                         <br>計入錯誤的驗證碼
     * @param federatedLogins  completes a link that waited for a login
     *                         through an identity provider, if third-party
     *                         login is configured
     *                         <br>完成等待第三方登入的帳號連結（有設定第三方
     *                         登入時）
     * @param events           publishes the audit events
     *                         <br>發布稽核事件
     * @param clock            the clock
     *                         <br>時鐘
     */
    public MfaChallengeController(AuthorizationServerProperties properties, MfaLoginFlow flow, MfaService mfa, MfaSetupSupport setup,
                                  UserAccountService users, AccountLockout lockout,
                                  ObjectProvider<FederatedLoginSuccessHandler> federatedLogins,
                                  ApplicationEventPublisher events, Clock clock) {
        this.page = new PageSupport(properties.getBranding());
        this.flow = flow;
        this.mfa = mfa;
        this.setup = setup;
        this.users = users;
        this.lockout = lockout;
        this.federatedLogins = federatedLogins;
        this.events = events;
        this.clock = clock;
    }

    /**
     * Shows the form for the code.
     * <p>
     * 顯示輸入驗證碼的表單。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view, or a redirect to the login page
     *         <br>畫面，或重導至登入頁
     */
    @GetMapping(MfaPaths.VERIFY)
    public String form(HttpServletRequest request, Model model) {
        PendingLogin pending = flow.pending(request);
        if (pending == null || pending.enrollment()) {
            return "redirect:/login";
        }
        populate(request, model);
        return "jacky917/mfa";
    }

    /**
     * Checks the code and completes the login.
     * <p>
     * 檢查驗證碼並完成登入。
     *
     * @param code      a code from the authenticator app or a recovery code
     *                  <br>驗證器 App 的驗證碼或復原碼
     * @param request   the current request
     *                  <br>目前的請求
     * @param response  the current response
     *                  <br>目前的回應
     * @param model     the view model, when the form is shown again
     *                  <br>再次顯示表單時的畫面資料
     * @return the form again with an error, or {@code null} after
     *         redirecting
     *         <br>帶著錯誤再次顯示的表單；已重導時為 {@code null}
     * @throws IOException if the redirect fails
     *         <br>若重導失敗
     */
    @PostMapping(MfaPaths.VERIFY)
    public @Nullable String verify(@RequestParam String code, HttpServletRequest request,
                                   HttpServletResponse response, Model model) throws IOException {
        PendingLogin pending = flow.pending(request);
        if (pending == null || pending.enrollment()) {
            response.sendRedirect(request.getContextPath() + "/login");
            return null;
        }
        if (!canLogIn(pending, request, response)) {
            return null;
        }
        MfaService.Verification verification = mfa.verify(pending.userId(), code);
        if (verification == MfaService.Verification.INVALID) {
            return refuse(pending, request, response, model);
        }
        log.info("User {} passed two-step verification with a {}", pending.userId(),
                verification == MfaService.Verification.TOTP ? "code" : "recovery code");
        complete(pending, request, response);
        response.sendRedirect(flow.target(request, response));
        return null;
    }

    /**
     * Shows how to turn two-step verification on, for a user whose role
     * requires it.
     * <p>
     * 為角色要求兩步驟驗證的使用者，顯示啟用方式。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view, or a redirect to the login page
     *         <br>畫面，或重導至登入頁
     */
    @GetMapping(MfaPaths.SETUP)
    public String setupForm(HttpServletRequest request, Model model) {
        PendingLogin pending = flow.pending(request);
        if (pending == null || !pending.enrollment()) {
            return "redirect:/login";
        }
        populate(request, model);
        setup.populate(model, pending.userId(), secret(request), MfaPaths.SETUP);
        model.addAttribute("required", true);
        return "jacky917/mfa-setup";
    }

    /**
     * Turns two-step verification on, completes the login and shows the
     * recovery codes once.
     * <p>
     * 啟用兩步驟驗證、完成登入，並顯示一次復原碼。
     *
     * @param code      the code from the authenticator app
     *                  <br>驗證器 App 的驗證碼
     * @param request   the current request
     *                  <br>目前的請求
     * @param response  the current response
     *                  <br>目前的回應
     * @param model     the view model
     *                  <br>畫面資料
     * @return the recovery codes, the form again with an error, or
     *         {@code null} after redirecting
     *         <br>復原碼、帶著錯誤的表單；已重導時為 {@code null}
     * @throws IOException if the redirect fails
     *         <br>若重導失敗
     */
    @PostMapping(MfaPaths.SETUP)
    public @Nullable String enable(@RequestParam String code, HttpServletRequest request,
                                   HttpServletResponse response, Model model) throws IOException {
        PendingLogin pending = flow.pending(request);
        if (pending == null || !pending.enrollment()) {
            response.sendRedirect(request.getContextPath() + "/login");
            return null;
        }
        if (!canLogIn(pending, request, response)) {
            return null;
        }
        String secret = secret(request);
        Optional<List<String>> codes = mfa.enable(pending.userId(), secret, code);
        if (codes.isEmpty()) {
            if (!flow.recordFailure(pending, request)) {
                response.sendRedirect(request.getContextPath() + "/login?error=mfa");
                return null;
            }
            populate(request, model);
            setup.populate(model, pending.userId(), secret, MfaPaths.SETUP);
            model.addAttribute("required", true);
            model.addAttribute("error", page.message("mfa.error.code", null, RequestContextUtils.getLocale(request)));
            return "jacky917/mfa-setup";
        }
        request.getSession().removeAttribute(SETUP_SECRET_ATTRIBUTE);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.MFA_ENABLED, clock.instant(), true)
                .userId(pending.userId()).request(request).build());
        complete(pending, request, response);
        populate(request, model);
        model.addAttribute("codes", codes.get());
        model.addAttribute("next", flow.target(request, response));
        return "jacky917/mfa-codes";
    }

    /**
     * Gives up the pending login.
     * <p>
     * 放棄待驗證的登入。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @return a redirect to the login page
     *         <br>重導至登入頁
     */
    @PostMapping(MfaPaths.CANCEL)
    public String cancel(HttpServletRequest request) {
        flow.abandon(request);
        return "redirect:/login";
    }

    private void complete(PendingLogin pending, HttpServletRequest request, HttpServletResponse response) {
        flow.complete(pending, request, response);
        if (pending.continuation() == PendingLogin.Continuation.FEDERATED) {
            federatedLogins.ifAvailable(handler -> handler.completePendingLink(pending.userId(), request));
        }
    }

    private boolean canLogIn(PendingLogin pending, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Instant now = clock.instant();
        UserAccount user = users.findById(pending.userId()).orElse(null);
        if (user != null && user.status() == UserStatus.ACTIVE && !user.isTemporarilyLocked(now)) {
            return true;
        }
        // 第一步之後帳號被停用或鎖定（例如輸入錯誤太多次）：放棄登入
        log.info("Pending login of user {} ended: the account cannot log in", pending.userId());
        flow.abandon(request);
        response.sendRedirect(request.getContextPath() + "/login?error");
        return false;
    }

    private @Nullable String refuse(PendingLogin pending, HttpServletRequest request, HttpServletResponse response,
                                    Model model) throws IOException {
        Instant now = clock.instant();
        log.info("User {} entered a wrong two-step verification code", pending.userId());
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGIN, now, false)
                .userId(pending.userId()).login(pending.method(), pending.idp())
                .failureReason(LoginFailureReason.MFA_FAILED).request(request).build());
        lockout.recordFailure(pending.userId(), now, request);
        if (!flow.recordFailure(pending, request)) {
            response.sendRedirect(request.getContextPath() + "/login?error=mfa");
            return null;
        }
        populate(request, model);
        model.addAttribute("error", page.message("mfa.error.code", null, RequestContextUtils.getLocale(request)));
        return "jacky917/mfa";
    }

    private String secret(HttpServletRequest request) {
        // 密鑰在確認之前只存在瀏覽器 Session，重新整理頁面時沿用同一個
        if (request.getSession().getAttribute(SETUP_SECRET_ATTRIBUTE) instanceof String secret) {
            return secret;
        }
        String secret = MfaSetupSupport.newSecret();
        request.getSession().setAttribute(SETUP_SECRET_ATTRIBUTE, secret);
        return secret;
    }

    private void populate(HttpServletRequest request, Model model) {
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
    }
}
