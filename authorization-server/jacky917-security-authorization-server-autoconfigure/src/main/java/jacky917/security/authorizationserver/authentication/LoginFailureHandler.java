package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Counts failed password logins, locks the account after too many, and
 * audits every failure (detailed design §5.1).
 * <p>
 * 計算密碼登入失敗次數、失敗過多時鎖定帳號，並稽核每一次失敗（詳細設計 §5.1）。
 * <p>
 * Only a wrong password for an existing, usable account is counted; an
 * attempt on a locked account does not extend the lock. Every failure
 * redirects to {@code /login?error}, so the page never reveals whether the
 * account exists or is locked; the real reason is written to the audit.
 * <p>
 * 只有既有且可用的帳號輸入錯誤密碼時才計數；對已鎖定帳號的嘗試不會延長鎖定。
 * 所有失敗一律導向 {@code /login?error}，頁面不會透露帳號是否存在或被鎖定；
 * 真正的原因寫入稽核紀錄。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserAccountService users;
    private final ApplicationEventPublisher events;
    private final int maxFailures;
    private final Duration lockDuration;
    private final Clock clock;

    /**
     * Creates the handler.
     * <p>
     * 建立處理器。
     *
     * @param users         the user accounts
     *                      <br>使用者帳號
     * @param events        publishes the audit events
     *                      <br>發布稽核事件
     * @param maxFailures   consecutive failures that lock an account
     *                      <br>鎖定帳號的連續失敗次數
     * @param lockDuration  how long an account stays locked
     *                      <br>鎖定的時間
     * @param clock         the clock
     *                      <br>時鐘
     */
    public LoginFailureHandler(UserAccountService users, ApplicationEventPublisher events, int maxFailures,
                               Duration lockDuration, Clock clock) {
        super("/login?error");
        this.users = users;
        this.events = events;
        this.maxFailures = maxFailures;
        this.lockDuration = lockDuration;
        this.clock = clock;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        Instant now = clock.instant();
        String login = request.getParameter("username");
        Optional<UserAccount> user = login == null || login.isBlank() ? Optional.empty() : users.findByLogin(login);
        LoginFailureReason reason;
        if (exception instanceof LockedException) {
            reason = LoginFailureReason.LOCKED;
        } else if (exception instanceof DisabledException) {
            reason = LoginFailureReason.DISABLED;
        } else if (user.isEmpty()) {
            reason = LoginFailureReason.UNKNOWN_USER;
        } else {
            reason = LoginFailureReason.BAD_CREDENTIALS;
        }
        String userId = user.map(UserAccount::id).orElse(null);
        // 登入失敗為 INFO；不記錄輸入的帳號（可能是誤填的密碼）
        log.info("Password login failed for user {} from {}: {}", userId, request.getRemoteAddr(), reason);
        events.publishEvent(event(LoginAuditEventType.LOGIN, now, userId, request)
                .usernameAttempted(login).failureReason(reason.name()).build());

        if (reason == LoginFailureReason.BAD_CREDENTIALS
                && users.recordLoginFailure(userId, now, maxFailures, lockDuration)) {
            log.info("Locked user {} for {} after {} failed logins", userId, lockDuration, maxFailures);
            events.publishEvent(event(LoginAuditEventType.ACCOUNT_LOCKED, now, userId, request).build());
        }
        super.onAuthenticationFailure(request, response, exception);
    }

    private static LoginAuditEvent.Builder event(LoginAuditEventType type, Instant now, String userId,
                                                 HttpServletRequest request) {
        return LoginAuditEvent.builder(type, now, false).userId(userId)
                .login(LoginMethod.PASSWORD.name(), "local").request(request);
    }
}
