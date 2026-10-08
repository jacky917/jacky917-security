package jacky917.security.authorizationserver.web;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.authentication.LoginCompletion;
import jacky917.security.authorizationserver.federation.FederatedIdentityService;
import jacky917.security.authorizationserver.federation.FederatedLoginRejectedException;
import jacky917.security.authorizationserver.federation.FederatedLoginSuccessHandler;
import jacky917.security.authorizationserver.federation.LinkIntent;
import jacky917.security.authorizationserver.federation.PendingLinkService;
import jacky917.security.authorizationserver.federation.PendingLinkService.PendingLink;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
 * continues. Cancelling links nothing.
 * <p>
 * 使用者以既有帳號的密碼，或以已連結到該帳號的提供者登入（由
 * {@code FederatedLoginSuccessHandler} 處理），證明擁有既有帳號。密碼錯誤與
 * 登入失敗一樣計入帳號鎖定。確認後連結外部帳號、登入瀏覽器，並繼續授權請求。
 * 取消則不建立任何連結。
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
    private final IdentityProviders providers;
    private final ApplicationEventPublisher events;
    private final AuthorizationServerProperties.LoginProtection protection;
    private final PageSupport page;
    private final Clock clock;
    private final SavedRequestAwareAuthenticationSuccessHandler continueAuthorization =
            new SavedRequestAwareAuthenticationSuccessHandler();

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
     * @param providers        the identity providers, for their names
     *                         <br>身分提供者，用於取得名稱
     * @param events           publishes the audit events
     *                         <br>發布稽核事件
     * @param clock            the clock
     *                         <br>時鐘
     */
    public AccountLinkController(AuthorizationServerProperties properties, PendingLinkService pendingLinks,
                                 UserAccountService users, FederatedIdentityService identities,
                                 PasswordEncoder passwordEncoder, LoginCompletion completion,
                                 IdentityProviders providers, ApplicationEventPublisher events, Clock clock) {
        this.pendingLinks = pendingLinks;
        this.users = users;
        this.identities = identities;
        this.passwordEncoder = passwordEncoder;
        this.completion = completion;
        this.providers = providers;
        this.events = events;
        this.protection = properties.getLoginProtection();
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
     *         waiting
     *         <br>畫面；沒有待確認的連結時重導至登入頁
     */
    @GetMapping(PATH)
    public String show(HttpServletRequest request, Model model) {
        Optional<PendingLink> pending = pending(request);
        Optional<UserAccount> owner = pending.flatMap(link -> users.findById(link.userId()));
        if (pending.isEmpty() || owner.isEmpty()) {
            return "redirect:/login?error=federation";
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
        Optional<PendingLink> found = pending(request);
        if (found.isEmpty()) {
            response.sendRedirect("/login?error=federation");
            return;
        }
        PendingLink pending = found.get();
        Instant now = clock.instant();
        UserAccount owner = users.findById(pending.userId())
                .filter(user -> user.status() == UserStatus.ACTIVE && user.passwordHash() != null).orElse(null);
        if (owner == null || owner.isTemporarilyLocked(now)) {
            refuse(pending, owner == null ? LoginFailureReason.DISABLED : LoginFailureReason.LOCKED, request, response);
            return;
        }
        if (!passwordEncoder.matches(password, owner.passwordHash())) {
            refuse(pending, LoginFailureReason.BAD_CREDENTIALS, request, response);
            if (users.recordLoginFailure(owner.id(), now, protection.getMaxFailures(), protection.getLockDuration())) {
                events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.ACCOUNT_LOCKED, now, false)
                        .userId(owner.id()).login(LoginMethod.PASSWORD.name(), "local").request(request).build());
            }
            return;
        }
        String provider = pending.info().provider();
        String token = (String) request.getSession().getAttribute(LinkIntent.PENDING_LINK_ATTRIBUTE);
        request.getSession().removeAttribute(LinkIntent.PENDING_LINK_ATTRIBUTE);
        try {
            if (!pendingLinks.consume(token)) {
                response.sendRedirect("/login?error=federation");
                return;
            }
            identities.link(owner.id(), pending.info());
        } catch (FederatedLoginRejectedException ex) {
            log.info("Cannot link {} to user {}: {}", provider, owner.id(), ex.getMessage());
            response.sendRedirect("/login?error=federation");
            return;
        }
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.ACCOUNT_LINKED, now, true)
                .userId(owner.id()).login(LoginMethod.FEDERATED.name(), provider).request(request).build());
        // 登入前更換 Session ID（session fixation）
        request.changeSessionId();
        UsernamePasswordAuthenticationToken proof = UsernamePasswordAuthenticationToken.authenticated(owner.id(), null,
                List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(now)
                        .build()));
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
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(LinkIntent.PENDING_LINK_ATTRIBUTE);
        }
        return "redirect:/login";
    }

    private void refuse(PendingLink pending, LoginFailureReason reason, HttpServletRequest request,
                        HttpServletResponse response) throws IOException {
        log.info("Account link confirmation failed for user {}: {}", pending.userId(), reason);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGIN, clock.instant(), false)
                .userId(pending.userId()).login(LoginMethod.PASSWORD.name(), "local").failureReason(reason.name())
                .request(request).build());
        response.sendRedirect(PATH + "?error");
    }

    private Optional<PendingLink> pending(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        Object token = session == null ? null : session.getAttribute(LinkIntent.PENDING_LINK_ATTRIBUTE);
        return token instanceof String value ? pendingLinks.find(value) : Optional.empty();
    }

    private String providerName(@Nullable String registrationId) {
        return providers.find(registrationId == null ? "" : registrationId)
                .map(IdentityProviders.Provider::name).orElse(registrationId);
    }
}
