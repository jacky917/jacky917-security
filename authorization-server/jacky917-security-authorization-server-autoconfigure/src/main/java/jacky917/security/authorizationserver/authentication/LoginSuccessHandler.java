package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.LoginController;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.time.Clock;

/**
 * Handles a successful password login (detailed design §5.1): records the
 * login, creates the login session, and stores its id ({@code asid}) in the
 * authorization server's browser session before returning to the
 * authorization request.
 * <p>
 * 處理帳號密碼登入成功（詳細設計 §5.1）：記錄登入、建立登入 Session，並在回到
 * 授權請求之前，把它的 ID（{@code asid}）存入 Authorization Server 的瀏覽器
 * Session。
 * <p>
 * The authorization code flow links every authorization issued afterwards
 * to that {@code asid}.
 * <p>
 * 之後簽發的每一個授權都會透過這個 {@code asid} 連結到此登入 Session。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final AuthSessionService sessions;
    private final UserAccountService users;
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
     * @param clock     the clock for timestamps
     *                  <br>用於時間戳記的時鐘
     */
    public LoginSuccessHandler(AuthSessionService sessions, UserAccountService users, Clock clock) {
        this.sessions = sessions;
        this.users = users;
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
        AuthSession session = sessions.create(userId, LoginMethod.PASSWORD, "local", "pwd",
                request.getRemoteAddr(), request.getHeader(HttpHeaders.USER_AGENT));
        request.getSession().setAttribute(AuthSessionService.SESSION_ATTRIBUTE, session.sessionId());
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
