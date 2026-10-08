package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.authentication.AccountLockout;
import jacky917.security.authorizationserver.authentication.LoginCompletion;
import jacky917.security.authorizationserver.federation.FederatedIdentityService;
import jacky917.security.authorizationserver.federation.FederatedLoginRejectedException;
import jacky917.security.authorizationserver.federation.FederatedLoginSuccessHandler;
import jacky917.security.authorizationserver.federation.PendingLinkService;
import jacky917.security.authorizationserver.mfa.MfaLoginFlow;
import jacky917.security.authorizationserver.mfa.PendingLogin;
import jacky917.security.authorizationserver.federation.PendingLinkService.PendingLink;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * The page where a user confirms linking an external login to an existing
 * account (detailed design §5.3, D06-C).
 * <p>
 * 使用者確認把第三方登入連結到既有帳號的頁面（詳細設計 §5.3、D06-C）。
 * <p>
 * The user proves that they own the existing account with its password, or
 * by logging in with a provider already linked to it (handled by
 * {@link FederatedLoginSuccessHandler}). A wrong password counts towards the
 * account lock like a failed login. After the confirmation the external
 * account is linked, the browser is logged in and the authorization request
 * continues. Cancelling links nothing. When the pending link has expired, or
 * the external account cannot be linked, the browser returns to the login
 * page with a message that says why.
 * <p>
 * 使用者以既有帳號的密碼，或以已連結到該帳號的提供者登入（由
 * {@code FederatedLoginSuccessHandler} 處理），證明擁有既有帳號。密碼錯誤與
 * 登入失敗一樣計入帳號鎖定。確認後連結外部帳號、登入瀏覽器，並繼續授權請求。
 * 取消則不建立任何連結。待確認的連結已到期，或外部帳號無法連結時，瀏覽器回到
 * 登入頁，並顯示原因。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
@Controller
public class AccountLinkController {

    private static final String PATH = FederatedLoginSuccessHandler.LINK_ACCOUNT_PATH;
    private static final String[] PAGE_KEYS = {"link.title", "link.message", "link.password", "link.submit",
            "link.or-provider", "link.cancel", "link.error"};

    private final PendingLinkService pendingLinks;
    private final UserAccountService users;
    private final FederatedIdentityService identities;
    private final PasswordEncoder passwordEncoder;
    private final LoginCompletion completion;
    private final MfaLoginFlow mfa;
    private final IdentityProviders providers;
    private final ApplicationEventPublisher events;
    private final AccountLockout lockout;
    private final PageSupport page;
    private final Clock clock;
    private final SavedRequestAwareAuthenticationSuccessHandler continueAuthorization =
            new SavedRequestAwareAuthenticationSuccessHandler();
    // 自動加上 context path
    private final RedirectStrategy redirects = new DefaultRedirectStrategy();

    /**
     * Creates the controller.
     * <p>
     * 建立 controller。
     *
     * @param properties       the authorization server properties
     *                         <br>Authorization Server 設定屬性
     * @param pendingLinks     the links waiting for confirmation
     *                         <br>待確認的連結
     * @param users            the user accounts
     *                         <br>使用者帳號
     * @param identities       links the external account
     *                         <br>連結外部帳號
     * @param passwordEncoder  checks the password
     *                         <br>檢查密碼
     * @param completion       logs the browser in
     *                         <br>登入瀏覽器
     * @param mfa              starts two-step verification when the owner
     *                         needs it
     *                         <br>帳號擁有者需要時開始兩步驟驗證
     * @param providers        the identity providers, for their names
     *                         <br>身分提供者，用於取得名稱
     * @param events           publishes the audit events
     *                         <br>發布稽核事件
     * @param lockout          counts wrong passwords towards locking the
     *                         account
     *                         <br>把密碼錯誤計入帳號鎖定
     * @param clock            the clock
     *                         <br>時鐘
     */
    public AccountLinkController(AuthorizationServerProperties properties, PendingLinkService pendingLinks,
                                 UserAccountService users, FederatedIdentityService identities,
                                 PasswordEncoder passwordEncoder, LoginCompletion completion, MfaLoginFlow mfa,
                                 IdentityProviders providers, ApplicationEventPublisher events,
                                 AccountLockout lockout, Clock clock) {
        this.pendingLinks = pendingLinks;
        this.users = users;
        this.identities = identities;
        this.passwordEncoder = passwordEncoder;
        this.completion = completion;
        this.mfa = mfa;
        this.providers = providers;
        this.events = events;
        this.lockout = lockout;
        this.page = new PageSupport(properties.getBranding());
        this.clock = clock;
        continueAuthorization.setDefaultTargetUrl(LoginController.SIGNED_IN_PATH);
    }

    /**
     * Shows the confirmation page.
     * <p>
     * 顯示確認頁。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @param model    the view model
     *                 <br>畫面資料
     * @return the view, or a redirect to the login page when nothing is
     *         waiting or the pending link expired
     *         <br>畫面；沒有待確認的連結或已到期時重導至登入頁
     */
    @GetMapping(PATH)
    public String show(HttpServletRequest request, Model model) {
        Optional<PendingLink> pending = pendingLinks.find(request);
        Optional<UserAccount> owner = pending.flatMap(link -> users.findById(link.userId()));
        if (pending.isEmpty() || owner.isEmpty()) {
            log.info("No pending account link to show: it expired, was used, or its user no longer exists");
            PendingLinkService.forget(request);
            return "redirect:/login?error=link_expired";
        }
        Locale locale = RequestContextUtils.getLocale(request);
        page.populate(model, locale, PAGE_KEYS);
        String providerName = providerName(pending.get().info().provider());
        model.addAttribute("heading", page.message("link.heading", new Object[]{providerName}, locale));
        model.addAttribute("email", pending.get().info().email());
        model.addAttribute("hasPassword", owner.get().passwordHash() != null);
        List<Map<String, String>> confirmWith = new ArrayList<>();
        identities.findLinked(owner.get().id()).forEach(linked -> providers.find(linked.provider()).ifPresent(
                provider -> confirmWith.add(Map.of("url", "/oauth2/authorization/" + provider.registrationId(),
                        "label", page.message("login.with", new Object[]{provider.name()}, locale)))));
        model.addAttribute("providers", confirmWith);
        model.addAttribute("error", request.getParameterMap().containsKey("error"));
        return "jacky917/link-account";
    }

    /**
     * Confirms the link with the existing account's password.
     * <p>
     * 以既有帳號的密碼確認連結。
     *
     * @param password  the existing account's password
     *                  <br>既有帳號的密碼
     * @param request   the current request
     *                  <br>目前的請求
     * @param response  the current response
     *                  <br>目前的回應
     * @throws IOException      if the redirect fails
     *                          <br>若重導失敗
     * @throws ServletException if continuing the authorization request fails
     *                          <br>若繼續授權請求失敗
     */
    @PostMapping(PATH)
    public void confirm(@RequestParam String password, HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        Optional<PendingLink> found = pendingLinks.find(request);
        if (found.isEmpty()) {
            log.info("No pending account link to confirm: it expired or was used");
            PendingLinkService.forget(request);
            redirects.sendRedirect(request, response, "/login?error=link_expired");
            return;
        }
        PendingLink pending = found.get();
        Instant now = clock.instant();
        UserAccount owner = users.findById(pending.userId()).orElse(null);
        LoginFailureReason refusal = refusal(owner, now);
        if (refusal != null) {
            refuse(pending, refusal, request, response);
            return;
        }
        if (!passwordEncoder.matches(password, owner.passwordHash())) {
            refuse(pending, LoginFailureReason.BAD_CREDENTIALS, request, response);
            lockout.recordFailure(owner.id(), now, request);
            return;
        }
        String provider = pending.info().provider();
        try {
            // 用掉待確認的連結與建立連結在同一個交易中：連結失敗時待確認的連結維持未使用
            if (!pendingLinks.confirm(pending, () -> identities.link(owner.id(), pending.info()))) {
                log.info("The pending link of {} to user {} expired or was used before the confirmation", provider,
                        owner.id());
                failLink(owner.id(), provider, LoginFailureReason.LINK_EXPIRED, "link_expired", request, response);
                return;
            }
        } catch (FederatedLoginRejectedException ex) {
            log.info("Cannot link {} to user {}: {}", provider, owner.id(), ex.getMessage());
            failLink(owner.id(), provider, FederatedLoginSuccessHandler.auditReason(ex.reason()),
                    FederatedLoginSuccessHandler.linkError(ex.reason()), request, response);
            return;
        }
        PendingLinkService.forget(request);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.ACCOUNT_LINKED, now, true)
                .userId(owner.id()).login(LoginMethod.FEDERATED, provider).request(request).build());
        // 登入前更換 Session ID（session fixation）
        request.changeSessionId();
        UsernamePasswordAuthenticationToken proof = UsernamePasswordAuthenticationToken.authenticated(owner.id(), null,
                List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(now)
                        .build()));
        if (mfa.challenge(owner.id(), LoginMethod.FEDERATED, provider, "fed,pwd", proof,
                PendingLogin.Continuation.LINK, request, response)) {
            return;
        }
        completion.logIn(owner.id(), LoginMethod.FEDERATED, provider, "fed,pwd", proof, request, response);
        continueAuthorization.onAuthenticationSuccess(request, response,
                SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * Cancels the pending link; nothing is linked.
     * <p>
     * 取消待確認的連結，不建立任何連結。
     *
     * @param request  the current request
     *                 <br>目前的請求
     * @return a redirect to the login page
     *         <br>重導至登入頁
     */
    @PostMapping(PATH + "/cancel")
    public String cancel(HttpServletRequest request) {
        PendingLinkService.forget(request);
        return "redirect:/login";
    }

    /**
     * Returns why the existing account cannot confirm with its password, or
     * {@code null} if it can.
     * <p>
     * 回傳既有帳號無法以密碼確認的原因；可以確認時為 {@code null}。
     */
    private static @Nullable LoginFailureReason refusal(@Nullable UserAccount owner, Instant now) {
        if (owner == null || owner.status() == UserStatus.DISABLED || owner.status() == UserStatus.DELETED) {
            return LoginFailureReason.DISABLED;
        }
        if (owner.status() == UserStatus.LOCKED || owner.isTemporarilyLocked(now)) {
            return LoginFailureReason.LOCKED;
        }
        return owner.passwordHash() == null ? LoginFailureReason.NO_PASSWORD : null;
    }

    private void refuse(PendingLink pending, LoginFailureReason reason, HttpServletRequest request,
                        HttpServletResponse response) throws IOException {
        log.info("Account link confirmation failed for user {}: {}", pending.userId(), reason);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGIN, clock.instant(), false)
                .userId(pending.userId()).login(LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP).failureReason(reason)
                .request(request).build());
        redirects.sendRedirect(request, response, PATH + "?error");
    }

    /**
     * Audits a link that cannot be completed, forgets the pending link and
     * returns to the login page with the reason.
     * <p>
     * 稽核無法完成的連結、移除待確認的連結，並帶著原因回到登入頁。
     */
    private void failLink(String userId, String provider, LoginFailureReason reason, String error,
                          HttpServletRequest request, HttpServletResponse response) throws IOException {
        PendingLinkService.forget(request);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.ACCOUNT_LINKED, clock.instant(), false)
                .userId(userId).login(LoginMethod.FEDERATED, provider).failureReason(reason).request(request).build());
        redirects.sendRedirect(request, response, "/login?error=" + error);
    }

    private String providerName(@Nullable String registrationId) {
        return providers.find(registrationId == null ? "" : registrationId)
                .map(IdentityProviders.Provider::name).orElse(registrationId);
    }
}
