package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.account.AccountPaths;
import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.LoginController;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.time.Clock;

/**
 * Handles a successful password login (detailed design §5.1): records the
 * login, creates the login session, stores its id ({@code asid}) in the
 * authorization server's browser session and publishes a successful
 * {@code LOGIN} audit event before returning to the authorization request.
 * <p>
 * 處理帳號密碼登入成功（詳細設計 §5.1）：記錄登入、建立登入 Session、把它的
 * ID（{@code asid}）存入 Authorization Server 的瀏覽器 Session，並發布成功的
 * {@code LOGIN} 稽核事件，再回到授權請求。
 * <p>
 * The authorization code flow links every authorization issued afterwards
 * to that {@code asid}. A user whose password must be changed goes to the
 * change page first, and continues to the authorization request after
 * changing it.
 * <p>
 * 之後簽發的每一個授權都會透過這個 {@code asid} 連結到此登入 Session。必須變更
 * 密碼的使用者先前往變更頁，變更後再繼續授權請求。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final AuthSessionService sessions;
    private final UserAccountService users;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    /**
     * Creates the handler.
     * <p>
     * 建立處理器。
     *
     * @param sessions  the login session service
     *                  <br>登入 Session 服務
     * @param users     the user account service
     *                  <br>使用者帳號服務
     * @param events    publishes the {@code LOGIN} audit event
     *                  <br>發布 {@code LOGIN} 稽核事件
     * @param clock     the clock for timestamps
     *                  <br>用於時間戳記的時鐘
     */
    public LoginSuccessHandler(AuthSessionService sessions, UserAccountService users, ApplicationEventPublisher events,
                               Clock clock) {
        this.sessions = sessions;
        this.users = users;
        this.events = events;
        this.clock = clock;
        // 沒有被中斷的授權請求時（直接開啟登入頁），導向 starter 的已登入頁，而不是應用程式的 "/"
        setDefaultTargetUrl(LoginController.SIGNED_IN_PATH);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        // D16：UserDetails 的 username 就是使用者 ID
        String userId = authentication.getName();
        users.recordLoginSuccess(userId, clock.instant());
        AuthSession session = sessions.create(userId, LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP, "pwd",
                request.getRemoteAddr(), request.getHeader(HttpHeaders.USER_AGENT));
        request.getSession().setAttribute(AuthSessionService.SESSION_ATTRIBUTE, session.sessionId());
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGIN, session.createdAt(), true)
                .userId(userId).login(LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP).sessionId(session.sessionId())
                .request(request).build());
        if (users.findById(userId).map(UserAccount::passwordChangeRequired).orElse(false)) {
            // D29：先變更密碼；被中斷的授權請求留在 RequestCache 中，變更後繼續
            request.getSession().setAttribute(AccountPaths.PASSWORD_CHANGE_REQUIRED_ATTRIBUTE, Boolean.TRUE);
            getRedirectStrategy().sendRedirect(request, response, AccountPaths.CHANGE_PASSWORD);
            return;
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
