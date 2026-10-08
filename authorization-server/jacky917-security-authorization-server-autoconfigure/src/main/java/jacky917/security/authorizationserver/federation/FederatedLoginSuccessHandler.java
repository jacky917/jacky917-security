package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.authentication.PrincipalNormalizer;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.LoginController;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;
import java.time.Clock;
import java.util.List;

/**
 * Handles a successful login through an identity provider (detailed design
 * §5.3): finds or creates the user, creates the login session, replaces
 * the provider's authentication with the standard one (D16), and returns
 * to the authorization request.
 * <p>
 * 處理透過身分提供者的登入成功（詳細設計 §5.3）：找到或建立使用者、建立登入
 * Session、以標準的 Authentication 取代提供者的 Authentication（D16），再回到
 * 授權請求。
 * <p>
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

    private final List<FederatedUserInfoMapper> mappers;
    private final FederatedIdentityService identities;
    private final UserAccountService users;
    private final AuthSessionService sessions;
    private final PrincipalNormalizer normalizer;
    private final @Nullable OAuth2AuthorizedClientRepository authorizedClients;
    private final Clock clock;
    private final SecurityContextRepository contextRepository = new DelegatingSecurityContextRepository(
            new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());

    /**
     * Creates the handler.
     * <p>
     * 建立處理器。
     *
     * @param mappers            converts provider users; the first that
     *                           supports the provider is used
     *                           <br>轉換提供者的使用者；使用第一個支援該提供者的 mapper
     * @param identities         finds or creates the user
     *                           <br>找到或建立使用者
     * @param users              the user account service
     *                           <br>使用者帳號服務
     * @param sessions           the login session service
     *                           <br>登入 Session 服務
     * @param normalizer         builds the standard authentication
     *                           <br>建立標準的 Authentication
     * @param authorizedClients  where Spring stores the provider tokens, or
     *                           {@code null}
     *                           <br>Spring 存放提供者 token 的位置，或 {@code null}
     * @param clock              the clock for timestamps
     *                           <br>用於時間戳記的時鐘
     */
    public FederatedLoginSuccessHandler(List<FederatedUserInfoMapper> mappers, FederatedIdentityService identities,
                                        UserAccountService users, AuthSessionService sessions,
                                        PrincipalNormalizer normalizer,
                                        @Nullable OAuth2AuthorizedClientRepository authorizedClients, Clock clock) {
        this.mappers = List.copyOf(mappers);
        this.identities = identities;
        this.users = users;
        this.sessions = sessions;
        this.normalizer = normalizer;
        this.authorizedClients = authorizedClients;
        this.clock = clock;
        setDefaultTargetUrl(LoginController.SIGNED_IN_PATH);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        String provider = token.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient client = authorizedClients == null ? null
                : authorizedClients.loadAuthorizedClient(provider, authentication, request);
        UserAccount user;
        try {
            FederatedUserInfoMapper mapper = mappers.stream().filter(candidate -> candidate.supports(provider))
                    .findFirst().orElseThrow(() -> new IllegalStateException("No mapper for provider " + provider));
            FederatedUserInfo info = mapper.map(provider, token.getPrincipal(),
                    client == null ? null : client.getAccessToken());
            user = identities.login(info);
        } catch (FederatedLoginRejectedException ex) {
            log.info("Rejected a login through {}: {}", provider, ex.getMessage());
            reject(request, response,
                    ex.reason() == FederatedLoginRejectedException.Reason.ACCOUNT_EXISTS ? "account_exists" : "federation");
            return;
        } catch (RuntimeException ex) {
            // 例如沒有支援此提供者的 mapper、或提供者回傳的資料不完整：登出並回到登入頁，而不是錯誤頁
            log.error("A login through {} could not be processed", provider, ex);
            reject(request, response, "federation");
            return;
        } finally {
            // 提供者的 token 只用於取得使用者資料，不保留
            if (authorizedClients != null) {
                authorizedClients.removeAuthorizedClient(provider, authentication, request, response);
            }
        }

        users.recordLoginSuccess(user.id(), clock.instant());
        AuthSession session = sessions.create(user.id(), LoginMethod.FEDERATED, provider, "fed",
                request.getRemoteAddr(), request.getHeader(HttpHeaders.USER_AGENT));
        Authentication normalized = normalizer.normalize(user.id(), authentication);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(normalized);
        SecurityContextHolder.setContext(context);
        contextRepository.saveContext(context, request, response);
        request.getSession().setAttribute(AuthSessionService.SESSION_ATTRIBUTE, session.sessionId());
        super.onAuthenticationSuccess(request, response, normalized);
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, String error) throws IOException {
        SecurityContext empty = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(empty);
        contextRepository.saveContext(empty, request, response);
        getRedirectStrategy().sendRedirect(request, response, "/login?error=" + error);
    }
}
