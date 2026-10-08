package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccountService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.time.Clock;

/**
 * Completes a login that did not go through Spring's form login: an
 * external login, or the confirmation of an account link.
 * <p>
 * 完成不經過 Spring 表單登入的登入：第三方登入，或帳號連結的確認。
 * <p>
 * It records the login, creates the login session, logs the browser in
 * with the standard principal (D16) and publishes a successful
 * {@code LOGIN} audit event.
 * <p>
 * 記錄登入、建立登入 Session、以標準的 principal 登入瀏覽器（D16），並發布
 * 成功的 {@code LOGIN} 稽核事件。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class LoginCompletion {

    private final UserAccountService users;
    private final AuthSessionService sessions;
    private final PrincipalNormalizer normalizer;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final SecurityContextRepository contextRepository = new DelegatingSecurityContextRepository(
            new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());

    /**
     * Creates the completion.
     * <p>
     * 建立物件。
     *
     * @param users       the user account service
     *                    <br>使用者帳號服務
     * @param sessions    the login sessions
     *                    <br>登入 Session
     * @param normalizer  builds the standard principal
     *                    <br>建立標準的 principal
     * @param events      publishes the audit event
     *                    <br>發布稽核事件
     * @param clock       the clock
     *                    <br>時鐘
     */
    public LoginCompletion(UserAccountService users, AuthSessionService sessions, PrincipalNormalizer normalizer,
                           ApplicationEventPublisher events, Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.normalizer = normalizer;
        this.events = events;
        this.clock = clock;
    }

    /**
     * Logs the browser in as the given user.
     * <p>
     * 以指定的使用者登入瀏覽器。
     *
     * @param userId    the user id
     *                  <br>使用者 ID
     * @param method    how the user logged in
     *                  <br>登入方式
     * @param idp       the identity provider
     *                  <br>身分提供者
     * @param amr       the authentication methods, comma-separated
     *                  <br>驗證方式（逗號分隔）
     * @param original  the authentication that proved the user, for its
     *                  factors and details
     *                  <br>證明使用者身分的 Authentication，用於取得 factor 與
     *                  details
     * @param request   the current request
     *                  <br>目前的請求
     * @param response  the current response
     *                  <br>目前的回應
     * @return the new login session
     *         <br>新的登入 Session
     */
    public AuthSession logIn(String userId, LoginMethod method, String idp, String amr, Authentication original,
                             HttpServletRequest request, HttpServletResponse response) {
        users.recordLoginSuccess(userId, clock.instant());
        AuthSession session = sessions.create(userId, method, idp, amr, request.getRemoteAddr(),
                request.getHeader(HttpHeaders.USER_AGENT));
        restore(normalizer.normalize(userId, original), request, response);
        request.getSession().setAttribute(AuthSessionService.SESSION_ATTRIBUTE, session.sessionId());
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGIN, session.createdAt(), true)
                .userId(userId).login(method.name(), idp).sessionId(session.sessionId()).request(request).build());
        return session;
    }

    /**
     * Makes the given authentication the browser's login, or logs the
     * browser out with an empty one.
     * <p>
     * 以指定的 Authentication 作為瀏覽器的登入；以空的 context 則登出瀏覽器。
     *
     * @param authentication  the authentication, or {@code null} to log out
     *                        <br>Authentication；{@code null} 表示登出
     * @param request         the current request
     *                        <br>目前的請求
     * @param response        the current response
     *                        <br>目前的回應
     */
    public void restore(@Nullable Authentication authentication, HttpServletRequest request,
                        HttpServletResponse response) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contextRepository.saveContext(context, request, response);
    }
}
