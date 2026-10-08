package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginAuditRepository;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.session.LoginMethod;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * Refuses password logins from an IP address with too many recent failures
 * (detailed design §5.1).
 * <p>
 * 拒絕近期登入失敗次數過多之 IP 的密碼登入（詳細設計 §5.1）。
 * <p>
 * Only the password forms are checked: {@code POST /login} and
 * {@code POST /jacky917/link-account}. When the failed logins of the last
 * minute from the request's IP reach the limit, the request is refused
 * before the password is checked: the browser is sent to
 * {@code /login?error=rate_limited}, and a failed {@code LOGIN} event with
 * reason {@code RATE_LIMITED} is published, which itself counts as a
 * failure. The IP is {@code HttpServletRequest#getRemoteAddr()}; behind a
 * reverse proxy, configure {@code server.forward-headers-strategy}.
 * <p>
 * 只檢查輸入密碼的表單：{@code POST /login} 與
 * {@code POST /jacky917/link-account}。請求 IP 最近一分鐘的登入失敗次數達到上限時，在
 * 檢查密碼之前就拒絕：瀏覽器被導向 {@code /login?error=rate_limited}，並發布
 * 原因為 {@code RATE_LIMITED} 的失敗 {@code LOGIN} 事件（它本身也計入失敗）。
 * IP 取自 {@code HttpServletRequest#getRemoteAddr()}；在反向代理之後請設定
 * {@code server.forward-headers-strategy}。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class LoginAttemptGuard extends OncePerRequestFilter {

    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final Set<String> PASSWORD_FORMS = Set.of("/login", "/jacky917/link-account");

    private final LoginAuditRepository audits;
    private final ApplicationEventPublisher events;
    private final int maxFailuresPerMinute;
    private final Clock clock;

    /**
     * Creates the guard.
     * <p>
     * 建立 guard。
     *
     * @param audits                the login audit, which holds the failures
     *                              <br>登入稽核，存放失敗紀錄
     * @param events                publishes the audit events
     *                              <br>發布稽核事件
     * @param maxFailuresPerMinute  failures allowed per IP per minute
     *                              <br>每個 IP 每分鐘允許的失敗次數
     * @param clock                 the clock
     *                              <br>時鐘
     */
    public LoginAttemptGuard(LoginAuditRepository audits, ApplicationEventPublisher events, int maxFailuresPerMinute,
                             Clock clock) {
        this.audits = audits;
        this.events = events;
        this.maxFailuresPerMinute = maxFailuresPerMinute;
        this.clock = clock;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 以 URI 判斷：servlet path 依部署方式不同可能為空
        return !("POST".equals(request.getMethod())
                && PASSWORD_FORMS.contains(request.getRequestURI().substring(request.getContextPath().length())));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Instant now = clock.instant();
        String ip = request.getRemoteAddr();
        if (ip != null && audits.countFailedLogins(ip, now.minus(WINDOW)) >= maxFailuresPerMinute) {
            log.info("Refusing a login from {}: too many failed logins in the last minute", ip);
            events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGIN, now, false)
                    .usernameAttempted(request.getParameter("username"))
                    .login(LoginMethod.PASSWORD.name(), "local")
                    .failureReason(LoginFailureReason.RATE_LIMITED.name())
                    .request(request)
                    .build());
            response.sendRedirect(request.getContextPath() + "/login?error=rate_limited");
            return;
        }
        chain.doFilter(request, response);
    }
}
