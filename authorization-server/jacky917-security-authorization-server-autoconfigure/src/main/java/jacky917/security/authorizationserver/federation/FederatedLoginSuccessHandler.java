package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.authentication.LoginCompletion;
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
 *       and the browser returns to the account page.
 *       <br>使用者從帳號頁發起時（{@code LinkIntent}），把提供者帳號連結到該
 *       使用者並保留其登入，再回到帳號頁。</li>
 * </ul>
 * The provider's tokens are used only to read the user and are removed
 * right away. A rejected login is logged out and sent back to the login
 * page with an error.
 * <p>
 * 提供者的 token 只用於讀取使用者資料，用完立即移除。被拒絕的登入會登出，並
 * 帶著錯誤回到登入頁。
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

    private final List<FederatedUserInfoMapper> mappers;
    private final FederatedIdentityService identities;
    private final PendingLinkService pendingLinks;
    private final LoginCompletion completion;
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
     * @param authorizedClients  where Spring stores the provider tokens, or
     *                           {@code null}
     *                           <br>Spring 存放提供者 token 的位置，或 {@code null}
     * @param events             publishes the audit events
     *                           <br>發布稽核事件
     * @param clock              the clock
     *                           <br>時鐘
     */
    public FederatedLoginSuccessHandler(List<FederatedUserInfoMapper> mappers, FederatedIdentityService identities,
                                        PendingLinkService pendingLinks, LoginCompletion completion,
                                        @Nullable OAuth2AuthorizedClientRepository authorizedClients,
                                        ApplicationEventPublisher events, Clock clock) {
        this.mappers = List.copyOf(mappers);
        this.identities = identities;
        this.pendingLinks = pendingLinks;
        this.completion = completion;
        this.authorizedClients = authorizedClients;
        this.events = events;
        this.clock = clock;
        setDefaultTargetUrl(LoginController.SIGNED_IN_PATH);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        String provider = token.getAuthorizedClientRegistrationId();
        FederatedUserInfo info;
        try {
            OAuth2AuthorizedClient client = authorizedClients == null ? null
                    : authorizedClients.loadAuthorizedClient(provider, authentication, request);
            FederatedUserInfoMapper mapper = mappers.stream().filter(candidate -> candidate.supports(provider))
                    .findFirst().orElseThrow(() -> new IllegalStateException("No mapper for provider " + provider));
            info = mapper.map(provider, token.getPrincipal(), client == null ? null : client.getAccessToken());
        } catch (RuntimeException ex) {
            // 例如沒有支援此提供者的 mapper、或提供者回傳的資料不完整：登出並回到登入頁，而不是錯誤頁
            log.error("A login through {} could not be processed", provider, ex);
            take(request, LinkIntent.SESSION_ATTRIBUTE);
            audit(LoginAuditEventType.LOGIN, provider, false, null, null, LoginFailureReason.FEDERATION, request);
            reject(request, response, "federation");
            return;
        } finally {
            // 提供者的 token 只用於取得使用者資料，不保留
            if (authorizedClients != null) {
                authorizedClients.removeAuthorizedClient(provider, authentication, request, response);
            }
        }

        if (take(request, LinkIntent.SESSION_ATTRIBUTE) instanceof LinkIntent intent) {
            linkFromAccountPage(intent, info, request, response);
            return;
        }
        UserAccount user;
        try {
            user = identities.login(info);
        } catch (FederatedLoginRejectedException ex) {
            log.info("Rejected a login through {}: {}", provider, ex.getMessage());
            switch (ex.reason()) {
                case LINK_REQUIRED -> {
                    String pending = pendingLinks.create(ex.existingUserId(), info);
                    completion.restore(null, request, response);
                    request.getSession().setAttribute(LinkIntent.PENDING_LINK_ATTRIBUTE, pending);
                    audit(LoginAuditEventType.LOGIN, provider, false, null, null, LoginFailureReason.LINK_REQUIRED,
                            request);
                    getRedirectStrategy().sendRedirect(request, response, LINK_ACCOUNT_PATH);
                }
                case ACCOUNT_EXISTS -> {
                    audit(LoginAuditEventType.LOGIN, provider, false, null, null, LoginFailureReason.ACCOUNT_EXISTS,
                            request);
                    reject(request, response, "account_exists");
                }
                default -> {
                    audit(LoginAuditEventType.LOGIN, provider, false, null, null,
                            LoginFailureReason.USER_CANNOT_LOG_IN, request);
                    reject(request, response, "federation");
                }
            }
            return;
        } catch (RuntimeException ex) {
            log.error("A login through {} could not be processed", provider, ex);
            audit(LoginAuditEventType.LOGIN, provider, false, null, null, LoginFailureReason.FEDERATION, request);
            reject(request, response, "federation");
            return;
        }

        completion.logIn(user.id(), LoginMethod.FEDERATED, provider, "fed", authentication, request, response);
        completePendingLink(user.id(), request);
        super.onAuthenticationSuccess(request, response, SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * Links the provider account to the user who asked from the account
     * page, and restores that user's login.
     * <p>
     * 把提供者帳號連結到從帳號頁提出請求的使用者，並還原該使用者的登入。
     */
    private void linkFromAccountPage(LinkIntent intent, FederatedUserInfo info, HttpServletRequest request,
                                     HttpServletResponse response) throws IOException {
        completion.restore(intent.previous(), request, response);
        String target = AccountController.ACCOUNT_PATH;
        if (!intent.isFresh(clock.instant()) || !intent.provider().equals(info.provider())) {
            getRedirectStrategy().sendRedirect(request, response, target + "?error=link_failed");
            return;
        }
        try {
            identities.link(intent.userId(), info);
            audit(LoginAuditEventType.ACCOUNT_LINKED, info.provider(), true, intent.userId(), null, null, request);
            getRedirectStrategy().sendRedirect(request, response, target);
        } catch (FederatedLoginRejectedException ex) {
            log.info("Cannot link {} to user {}: {}", info.provider(), intent.userId(), ex.getMessage());
            getRedirectStrategy().sendRedirect(request, response, target + "?error="
                    + (ex.reason() == FederatedLoginRejectedException.Reason.LINKED_TO_ANOTHER_USER
                    ? "linked_elsewhere" : "link_failed"));
        }
    }

    /**
     * Completes a link waiting for this user: logging in with a provider
     * already linked to the user confirms it.
     * <p>
     * 完成等待此使用者確認的連結：以已連結到該使用者的提供者登入即代表確認。
     */
    private void completePendingLink(String userId, HttpServletRequest request) {
        if (!(take(request, LinkIntent.PENDING_LINK_ATTRIBUTE) instanceof String pending)) {
            return;
        }
        pendingLinks.find(pending).filter(link -> link.userId().equals(userId)).ifPresent(link -> {
            if (!pendingLinks.consume(pending)) {
                return;
            }
            try {
                identities.link(userId, link.info());
                audit(LoginAuditEventType.ACCOUNT_LINKED, link.info().provider(), true, userId, null, null, request);
            } catch (FederatedLoginRejectedException ex) {
                log.info("Cannot link {} to user {}: {}", link.info().provider(), userId, ex.getMessage());
            }
        });
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

    private void audit(LoginAuditEventType type, String provider, boolean success, @Nullable String userId,
                       @Nullable String sessionId, @Nullable LoginFailureReason reason, HttpServletRequest request) {
        events.publishEvent(LoginAuditEvent.builder(type, clock.instant(), success)
                .userId(userId).login(LoginMethod.FEDERATED.name(), provider).sessionId(sessionId)
                .failureReason(reason == null ? null : reason.name()).request(request).build());
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, String error) throws IOException {
        completion.restore(null, request, response);
        getRedirectStrategy().sendRedirect(request, response, "/login?error=" + error);
    }
}
