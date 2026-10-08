package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.authentication.LoginCompletion;
import jacky917.security.authorizationserver.federation.PendingLinkService.PendingLink;
import jacky917.security.authorizationserver.mfa.MfaLoginFlow;
import jacky917.security.authorizationserver.mfa.PendingLogin;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.web.AccountController;
import jacky917.security.authorizationserver.web.LoginController;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Handles a successful login through an identity provider (detailed design
 * §5.3).
 * <p>
 * 處理透過身分提供者的登入成功（詳細設計 §5.3）。
 * <ul>
 *   <li>Normally it finds or creates the user, logs the browser in with the
 *       standard principal (D16) and returns to the authorization request.
 *       If a link to this user was waiting for confirmation, it is completed
 *       now: logging in with a provider already linked confirms the link.
 *       <br>一般情況下找到或建立使用者、以標準的 principal 登入瀏覽器
 *       （D16），再回到授權請求。若有連結到此使用者的待確認連結，此時完成：以
 *       已連結的提供者登入即代表確認。</li>
 *   <li>When the verified email belongs to an existing user, the login is
 *       kept as a pending link and the browser goes to
 *       {@code /jacky917/link-account} to confirm it.
 *       <br>已驗證的 Email 屬於既有使用者時，此登入保存為待確認的連結，瀏覽器
 *       前往 {@code /jacky917/link-account} 確認。</li>
 *   <li>When the user started from the account page ({@link LinkIntent}),
 *       the provider account is linked to that user, whose login is kept,
 *       and the browser returns to the account page, with an error if the
 *       link failed.
 *       <br>使用者從帳號頁發起時（{@code LinkIntent}），把提供者帳號連結到該
 *       使用者並保留其登入，再回到帳號頁；連結失敗時帶著錯誤。</li>
 * </ul>
 * The provider's tokens are used only to read the user and are removed
 * right away. Any other rejected login is logged out and sent back to the
 * login page with an error. A pending link that cannot be completed never
 * fails the login itself: the reason is logged and audited, and shown on
 * the account page or the signed-in page ({@link #LINK_ERROR_ATTRIBUTE}).
 * <p>
 * 提供者的 token 只用於讀取使用者資料，用完立即移除。其他被拒絕的登入會登出，
 * 並帶著錯誤回到登入頁。無法完成的待確認連結不會讓登入本身失敗：原因會記錄
 * 日誌與稽核，並顯示在帳號頁或已登入頁（{@code LINK_ERROR_ATTRIBUTE}）。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class FederatedLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    /**
     * Page where the user confirms a pending link.
     * <p>
     * 使用者確認待確認連結的頁面。
     */
    public static final String LINK_ACCOUNT_PATH = "/jacky917/link-account";

    /**
     * Name of the browser session attribute holding the error code of a
     * pending link that could not be completed while the login succeeded,
     * for example {@code link_expired}. The page that shows it removes it.
     * <p>
     * 存放「登入成功但待確認連結無法完成」之錯誤代碼（例如
     * {@code link_expired}）的瀏覽器 Session 屬性名稱。顯示它的頁面會將其移除。
     */
    public static final String LINK_ERROR_ATTRIBUTE = FederatedLoginSuccessHandler.class.getName() + ".LINK_ERROR";

    private final List<FederatedUserInfoMapper> mappers;
    private final FederatedIdentityService identities;
    private final PendingLinkService pendingLinks;
    private final LoginCompletion completion;
    private final MfaLoginFlow mfa;
    private final @Nullable OAuth2AuthorizedClientRepository authorizedClients;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    /**
     * Creates the handler.
     * <p>
     * 建立處理器。
     *
     * @param mappers            converts provider users; the first that
     *                           supports the provider is used
     *                           <br>轉換提供者的使用者；使用第一個支援該提供者的 mapper
     * @param identities         finds, creates and links users
     *                           <br>找到、建立與連結使用者
     * @param pendingLinks       the links waiting for confirmation
     *                           <br>待確認的連結
     * @param completion         logs the browser in
     *                           <br>登入瀏覽器
     * @param mfa                starts two-step verification when the user
     *                           needs it
     *                           <br>使用者需要時開始兩步驟驗證
     * @param authorizedClients  where Spring stores the provider tokens, or
     *                           {@code null}
     *                           <br>Spring 存放提供者 token 的位置，或 {@code null}
     * @param events             publishes the audit events
     *                           <br>發布稽核事件
     * @param clock              the clock
     *                           <br>時鐘
     */
    public FederatedLoginSuccessHandler(List<FederatedUserInfoMapper> mappers, FederatedIdentityService identities,
                                        PendingLinkService pendingLinks, LoginCompletion completion, MfaLoginFlow mfa,
                                        @Nullable OAuth2AuthorizedClientRepository authorizedClients,
                                        ApplicationEventPublisher events, Clock clock) {
        this.mappers = List.copyOf(mappers);
        this.identities = identities;
        this.pendingLinks = pendingLinks;
        this.completion = completion;
        this.mfa = mfa;
        this.authorizedClients = authorizedClients;
        this.events = events;
        this.clock = clock;
        setDefaultTargetUrl(LoginController.SIGNED_IN_PATH);
    }

    /**
     * Returns the error code shown to the user for a rejected link.
     * <p>
     * 回傳連結被拒絕時顯示給使用者的錯誤代碼。
     *
     * @param reason  why the link was rejected
     *                <br>連結被拒絕的原因
     * @return {@code linked_elsewhere}, {@code provider_already_linked} or
     *         {@code link_failed}
     *         <br>{@code linked_elsewhere}、{@code provider_already_linked} 或
     *         {@code link_failed}
     */
    public static String linkError(FederatedLoginRejectedException.Reason reason) {
        return switch (reason) {
            case LINKED_TO_ANOTHER_USER -> "linked_elsewhere";
            case PROVIDER_ALREADY_LINKED -> "provider_already_linked";
            default -> "link_failed";
        };
    }

    /**
     * Returns the audit reason of a rejected login or link.
     * <p>
     * 回傳登入或連結被拒絕時的稽核原因。
     *
     * @param reason  why the login or link was rejected
     *                <br>登入或連結被拒絕的原因
     * @return the audit reason
     *         <br>稽核原因
     */
    public static LoginFailureReason auditReason(FederatedLoginRejectedException.Reason reason) {
        return switch (reason) {
            case USER_CANNOT_LOG_IN -> LoginFailureReason.USER_CANNOT_LOG_IN;
            case ACCOUNT_EXISTS -> LoginFailureReason.ACCOUNT_EXISTS;
            case LINK_REQUIRED -> LoginFailureReason.LINK_REQUIRED;
            case LINKED_TO_ANOTHER_USER -> LoginFailureReason.LINKED_TO_ANOTHER_USER;
            case PROVIDER_ALREADY_LINKED -> LoginFailureReason.PROVIDER_ALREADY_LINKED;
        };
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        String provider = token.getAuthorizedClientRegistrationId();
        LinkIntent intent = take(request, LinkIntent.SESSION_ATTRIBUTE) instanceof LinkIntent value ? value : null;
        FederatedUserInfo info;
        try {
            OAuth2AuthorizedClient client = authorizedClients == null ? null
                    : authorizedClients.loadAuthorizedClient(provider, authentication, request);
            FederatedUserInfoMapper mapper = mappers.stream().filter(candidate -> candidate.supports(provider))
                    .findFirst().orElseThrow(() -> new IllegalStateException("No mapper for provider " + provider));
            info = mapper.map(provider, token.getPrincipal(), client == null ? null : client.getAccessToken());
        } catch (RuntimeException ex) {
            // 例如沒有支援此提供者的 mapper、或提供者回傳的資料不完整：回到登入頁（或帳號頁），而不是錯誤頁
            log.error("A login through {} could not be processed", provider, ex);
            if (intent != null) {
                failLink(intent, provider, LoginFailureReason.FEDERATION, "link_failed", request, response);
            } else {
                audit(LoginAuditEventType.LOGIN, provider, false, null, LoginFailureReason.FEDERATION, request);
                reject(request, response, "federation");
            }
            return;
        } finally {
            // 提供者的 token 只用於取得使用者資料，不保留
            if (authorizedClients != null) {
                authorizedClients.removeAuthorizedClient(provider, authentication, request, response);
            }
        }

        if (intent != null) {
            linkFromAccountPage(intent, info, request, response);
            return;
        }
        UserAccount user;
        try {
            user = identities.login(info);
        } catch (FederatedLoginRejectedException ex) {
            log.info("Rejected a login through {}: {}", provider, ex.getMessage());
            handleRejectedLogin(ex, info, request, response);
            return;
        } catch (RuntimeException ex) {
            log.error("A login through {} could not be processed", provider, ex);
            audit(LoginAuditEventType.LOGIN, provider, false, null, LoginFailureReason.FEDERATION, request);
            reject(request, response, "federation");
            return;
        }

        try {
            if (mfa.challenge(user.id(), LoginMethod.FEDERATED, provider, "fed", authentication,
                    PendingLogin.Continuation.FEDERATED, request, response)) {
                return;
            }
            completion.logIn(user.id(), LoginMethod.FEDERATED, provider, "fed", authentication, request, response);
        } catch (RuntimeException ex) {
            log.error("Cannot log user {} in after a login through {}", user.id(), provider, ex);
            audit(LoginAuditEventType.LOGIN, provider, false, user.id(), LoginFailureReason.FEDERATION, request);
            reject(request, response, "federation");
            return;
        }
        completePendingLink(user.id(), request);
        super.onAuthenticationSuccess(request, response, SecurityContextHolder.getContext().getAuthentication());
    }

    private void handleRejectedLogin(FederatedLoginRejectedException rejection, FederatedUserInfo info,
                                     HttpServletRequest request, HttpServletResponse response) throws IOException {
        String provider = info.provider();
        switch (rejection.reason()) {
            case LINK_REQUIRED -> {
                String owner = Objects.requireNonNull(rejection.existingUserId(), "existingUserId");
                String pending;
                try {
                    pending = pendingLinks.create(owner, info);
                } catch (RuntimeException ex) {
                    log.error("Cannot keep the {} login waiting for a link to user {}", provider, owner, ex);
                    audit(LoginAuditEventType.LOGIN, provider, false, null, LoginFailureReason.FEDERATION, request);
                    reject(request, response, "federation");
                    return;
                }
                completion.restore(null, request, response);
                PendingLinkService.remember(request, pending);
                audit(LoginAuditEventType.LOGIN, provider, false, null, LoginFailureReason.LINK_REQUIRED, request);
                getRedirectStrategy().sendRedirect(request, response, LINK_ACCOUNT_PATH);
            }
            case ACCOUNT_EXISTS -> {
                audit(LoginAuditEventType.LOGIN, provider, false, null, LoginFailureReason.ACCOUNT_EXISTS, request);
                reject(request, response, "account_exists");
            }
            default -> {
                audit(LoginAuditEventType.LOGIN, provider, false, null, auditReason(rejection.reason()), request);
                reject(request, response, "federation");
            }
        }
    }

    /**
     * Links the provider account to the user who asked from the account
     * page, and restores that user's login.
     * <p>
     * 把提供者帳號連結到從帳號頁提出請求的使用者，並還原該使用者的登入。
     */
    private void linkFromAccountPage(LinkIntent intent, FederatedUserInfo info, HttpServletRequest request,
                                     HttpServletResponse response) throws IOException {
        if (!intent.isFresh(clock.instant())) {
            log.info("User {} took too long to link {}", intent.userId(), intent.provider());
            failLink(intent, info.provider(), LoginFailureReason.LINK_EXPIRED, "link_expired", request, response);
            return;
        }
        if (!intent.provider().equals(info.provider())) {
            log.warn("User {} asked to link {} but came back from {}; nothing is linked", intent.userId(),
                    intent.provider(), info.provider());
            failLink(intent, info.provider(), LoginFailureReason.FEDERATION, "link_failed", request, response);
            return;
        }
        try {
            identities.link(intent.userId(), info);
        } catch (FederatedLoginRejectedException ex) {
            log.info("Cannot link {} to user {}: {}", info.provider(), intent.userId(), ex.getMessage());
            failLink(intent, info.provider(), auditReason(ex.reason()), linkError(ex.reason()), request, response);
            return;
        } catch (RuntimeException ex) {
            log.error("Cannot link {} to user {}", info.provider(), intent.userId(), ex);
            failLink(intent, info.provider(), LoginFailureReason.FEDERATION, "link_failed", request, response);
            return;
        }
        completion.restore(intent.previous(), request, response);
        audit(LoginAuditEventType.ACCOUNT_LINKED, info.provider(), true, intent.userId(), null, request);
        getRedirectStrategy().sendRedirect(request, response, AccountController.ACCOUNT_PATH);
    }

    /**
     * Restores the login of the user who asked to link from the account
     * page, audits why the link failed and returns to the account page.
     * <p>
     * 還原從帳號頁提出連結請求之使用者的登入、稽核連結失敗的原因，並回到帳號頁。
     */
    private void failLink(LinkIntent intent, String provider, LoginFailureReason reason, String error,
                          HttpServletRequest request, HttpServletResponse response) throws IOException {
        completion.restore(intent.previous(), request, response);
        audit(LoginAuditEventType.ACCOUNT_LINKED, provider, false, intent.userId(), reason, request);
        getRedirectStrategy().sendRedirect(request, response, AccountController.ACCOUNT_PATH + "?error=" + error);
    }

    /**
     * Completes a link waiting for this user: logging in with a provider
     * already linked to the user confirms it. A link that cannot be
     * completed is logged, audited and reported through
     * {@link #LINK_ERROR_ATTRIBUTE}; the login itself goes on.
     * <p>
     * 完成等待此使用者確認的連結：以已連結到該使用者的提供者登入即代表確認。無法
     * 完成的連結會記錄日誌、稽核，並透過 {@code LINK_ERROR_ATTRIBUTE} 回報；登入
     * 本身照常繼續。
     */
    /**
     * Completes the link of an external account that waited for this
     * login, if the browser has one; also called after two-step
     * verification completes a login through an identity provider.
     * <p>
     * 若瀏覽器有等待此次登入的外部帳號連結，完成它；兩步驟驗證完成第三方登入
     * 後也會呼叫。
     *
     * @param userId   the user who logged in
     *                 <br>登入的使用者
     * @param request  the current request
     *                 <br>目前的請求
     */
    public void completePendingLink(String userId, HttpServletRequest request) {
        String token = PendingLinkService.forget(request);
        if (token == null) {
            return;
        }
        Optional<PendingLink> found;
        try {
            found = pendingLinks.find(token);
        } catch (RuntimeException ex) {
            log.error("Cannot read the pending link confirmed by user {}", userId, ex);
            reportLinkError(request, "link_failed");
            return;
        }
        if (found.isEmpty()) {
            log.info("The pending link confirmed by user {} expired or was already used", userId);
            audit(LoginAuditEventType.ACCOUNT_LINKED, null, false, userId, LoginFailureReason.LINK_EXPIRED, request);
            reportLinkError(request, "link_expired");
            return;
        }
        PendingLink link = found.get();
        String provider = link.info().provider();
        if (!link.userId().equals(userId)) {
            // 待確認的連結屬於另一位使用者：絕不能連結到目前登入的使用者
            log.warn("User {} logged in while a link of {} to user {} was pending; the pending link is discarded",
                    userId, provider, link.userId());
            audit(LoginAuditEventType.ACCOUNT_LINKED, provider, false, link.userId(), LoginFailureReason.LINK_EXPIRED,
                    request);
            reportLinkError(request, "link_failed");
            return;
        }
        try {
            if (!pendingLinks.confirm(link, () -> identities.link(userId, link.info()))) {
                log.info("The pending link of {} to user {} was used by another request", provider, userId);
                audit(LoginAuditEventType.ACCOUNT_LINKED, provider, false, userId, LoginFailureReason.LINK_EXPIRED,
                        request);
                reportLinkError(request, "link_expired");
                return;
            }
        } catch (FederatedLoginRejectedException ex) {
            log.info("Cannot link {} to user {}: {}", provider, userId, ex.getMessage());
            audit(LoginAuditEventType.ACCOUNT_LINKED, provider, false, userId, auditReason(ex.reason()), request);
            reportLinkError(request, linkError(ex.reason()));
            return;
        } catch (RuntimeException ex) {
            log.error("Cannot link {} to user {}", provider, userId, ex);
            audit(LoginAuditEventType.ACCOUNT_LINKED, provider, false, userId, LoginFailureReason.FEDERATION, request);
            reportLinkError(request, "link_failed");
            return;
        }
        audit(LoginAuditEventType.ACCOUNT_LINKED, provider, true, userId, null, request);
    }

    private static void reportLinkError(HttpServletRequest request, String error) {
        request.getSession().setAttribute(LINK_ERROR_ATTRIBUTE, error);
    }

    private static @Nullable Object take(HttpServletRequest request, String attribute) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(attribute);
        session.removeAttribute(attribute);
        return value;
    }

    private void audit(LoginAuditEventType type, @Nullable String provider, boolean success, @Nullable String userId,
                       @Nullable LoginFailureReason reason, HttpServletRequest request) {
        events.publishEvent(LoginAuditEvent.builder(type, clock.instant(), success)
                .userId(userId).login(LoginMethod.FEDERATED, provider).failureReason(reason).request(request).build());
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, String error) throws IOException {
        completion.restore(null, request, response);
        getRedirectStrategy().sendRedirect(request, response, "/login?error=" + error);
    }
}
