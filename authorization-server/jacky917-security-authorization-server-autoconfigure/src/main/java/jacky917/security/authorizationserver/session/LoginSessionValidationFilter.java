package jacky917.security.authorizationserver.session;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;

/**
 * Ends the browser login when its login session ({@code auth_session}) can
 * no longer be used, so the user is asked to log in again.
 * <p>
 * 瀏覽器的登入所對應的登入 Session（{@code auth_session}）已無法使用時，結束
 * 該瀏覽器登入，讓使用者重新登入。
 * <p>
 * The browser session (30 minutes idle) can outlive its login session:
 * revoked by an administrator or by logout elsewhere, or past its absolute
 * lifetime. Without this check the next authorization request would issue
 * an authorization that cannot be linked to an active session and fail with
 * an error page. The check runs on the authorization server's endpoints,
 * before access is decided, so the request falls back to the login page and
 * resumes after login.
 * <p>
 * 瀏覽器 Session（閒置 30 分鐘）可能比登入 Session 活得更久：例如被管理員或
 * 其他裝置的登出撤銷，或超過絕對有效期。若不檢查，下一次授權請求會產生無法
 * 連結到有效 Session 的授權，並以錯誤頁結束。此檢查在 Authorization Server
 * 端點決定存取權限之前執行，請求因此會回到登入頁，登入後再繼續。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class LoginSessionValidationFilter extends OncePerRequestFilter {

    private final AuthSessionService sessions;
    private final Clock clock;

    /**
     * Creates the filter.
     * <p>
     * 建立 filter。
     *
     * @param sessions  the login session service
     *                  <br>登入 Session 服務
     * @param clock     the clock for expiry
     *                  <br>判斷到期所用的時鐘
     */
    public LoginSessionValidationFilter(AuthSessionService sessions, Clock clock) {
        this.sessions = sessions;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        HttpSession httpSession = request.getSession(false);
        if (httpSession != null && isUserLogin(authentication) && !isUsable(httpSession, authentication)) {
            log.info("Ending the browser login of user {}: its login session is no longer active", authentication.getName());
            httpSession.invalidate();
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }

    private boolean isUsable(HttpSession httpSession, Authentication authentication) {
        Object sessionId = httpSession.getAttribute(AuthSessionService.SESSION_ATTRIBUTE);
        if (!(sessionId instanceof String asid)) {
            return false;
        }
        Instant now = clock.instant();
        return sessions.find(asid)
                .filter(session -> session.userId().equals(authentication.getName()))
                .filter(session -> session.isUsable(now))
                .isPresent();
    }

    private static boolean isUserLogin(Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }
}
