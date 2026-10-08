package jacky917.security.authorizationserver.account;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Sends a login that must change its password to the change page before
 * anything else, including the authorization endpoint (phase 3 and 4 design
 * D29).
 * <p>
 * 必須變更密碼的登入，在做任何事之前（包含授權端點）都先導向變更頁（第 3、4
 * 階段設計 D29）。
 * <p>
 * The mark is a browser session attribute set at the password login, so the
 * filter needs no database query. The change page, logout, the login page
 * and the stylesheets stay reachable.
 * <p>
 * 標記是以密碼登入時設定的瀏覽器 Session 屬性，因此不需要查詢資料庫。變更頁、
 * 登出、登入頁與樣式表仍可存取。
 *
 * @author Jacky
 * @since 2.1.0
 */
public class PasswordChangeRequiredFilter extends OncePerRequestFilter {

    private static final RequestMatcher ALLOWED = new OrRequestMatcher(
            PathPatternRequestMatcher.withDefaults().matcher(AccountPaths.CHANGE_PASSWORD),
            PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/logout"),
            PathPatternRequestMatcher.withDefaults().matcher("/login"),
            PathPatternRequestMatcher.withDefaults().matcher("/error"),
            PathPatternRequestMatcher.withDefaults().matcher("/jacky917/*.css"));

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(AccountPaths.PASSWORD_CHANGE_REQUIRED_ATTRIBUTE) != null
                && !ALLOWED.matches(request)) {
            response.sendRedirect(request.getContextPath() + AccountPaths.CHANGE_PASSWORD);
            return;
        }
        chain.doFilter(request, response);
    }
}
