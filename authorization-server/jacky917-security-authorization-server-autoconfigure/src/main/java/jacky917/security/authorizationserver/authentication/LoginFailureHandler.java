package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Counts failed password logins, locks the account after too many, and
 * audits every failure (detailed design §5.1).
 * <p>
 * 計算密碼登入失敗次數、失敗過多時鎖定帳號，並稽核每一次失敗（詳細設計 §5.1）。
 * <p>
 * Only a wrong password for an existing account that has a password is
 * counted. An attempt on a locked account does not extend the lock, and an
 * unexpected error, for example the database being unavailable, is logged
 * as an error and never counted, so it cannot lock out a user who typed the
 * right password. Every failure redirects to {@code /login?error}, so the
 * page never reveals whether the account exists or is locked; the real
 * reason is written to the audit.
 * <p>
 * 只有既有且設有密碼的帳號輸入錯誤密碼時才計數。對已鎖定帳號的嘗試不會延長
 * 鎖定；非預期的錯誤（例如資料庫無法使用）記錄為錯誤且一律不計數，因此不會
 * 鎖住輸入正確密碼的使用者。所有失敗一律導向 {@code /login?error}，頁面不會
 * 透露帳號是否存在或被鎖定；真正的原因寫入稽核紀錄。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserAccountService users;
    private final AccountLockout lockout;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    /**
     * Creates the handler.
     * <p>
     * 建立處理器。
     *
     * @param users    the user accounts
     *                 <br>使用者帳號
     * @param lockout  counts wrong passwords towards locking the account
     *                 <br>把密碼錯誤計入帳號鎖定
     * @param events   publishes the audit events
     *                 <br>發布稽核事件
     * @param clock    the clock
     *                 <br>時鐘
     */
    public LoginFailureHandler(UserAccountService users, AccountLockout lockout, ApplicationEventPublisher events,
                               Clock clock) {
        super("/login?error");
        this.users = users;
        this.lockout = lockout;
        this.events = events;
        this.clock = clock;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        Instant now = clock.instant();
        String login = request.getParameter("username");
        Optional<UserAccount> user;
        LoginFailureReason reason;
        try {
            user = login == null || login.isBlank() ? Optional.empty() : users.findByLogin(login);
            reason = reason(exception, user);
        } catch (DataAccessException ex) {
            log.error("Cannot look up the user of a failed password login from {}", request.getRemoteAddr(), ex);
            user = Optional.empty();
            reason = LoginFailureReason.ERROR;
        }
        String userId = user.map(UserAccount::id).orElse(null);
        if (reason == LoginFailureReason.ERROR) {
            log.error("Password login for user {} from {} failed with an unexpected {}", userId,
                    request.getRemoteAddr(), exception.getClass().getSimpleName(), exception);
        } else {
            // 登入失敗為 INFO；不記錄輸入的帳號（可能是誤填的密碼）
            log.info("Password login failed for user {} from {}: {}", userId, request.getRemoteAddr(), reason);
        }
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGIN, now, false).userId(userId)
                .login(LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP).usernameAttempted(login).failureReason(reason)
                .request(request).build());
        if (reason.countsTowardsLock() && userId != null) {
            lockout.recordFailure(userId, now, request);
        }
        super.onAuthenticationFailure(request, response, exception);
    }

    /**
     * Returns why a password login failed. Only the exceptions that
     * describe the account or the password are mapped to a reason; any other
     * exception is an unexpected {@link LoginFailureReason#ERROR}.
     * <p>
     * 回傳密碼登入失敗的原因。只有描述帳號或密碼的例外會對應到原因；其他例外
     * 一律為非預期的 {@code ERROR}。
     *
     * @param exception  the failure
     *                   <br>失敗
     * @param user       the account matching the typed login, or empty
     *                   <br>符合輸入帳號的帳號；沒有時為空
     * @return the reason
     *         <br>原因
     */
    static LoginFailureReason reason(AuthenticationException exception, Optional<UserAccount> user) {
        if (exception instanceof LockedException) {
            return LoginFailureReason.LOCKED;
        }
        if (exception instanceof AccountStatusException) {
            return LoginFailureReason.DISABLED;
        }
        if (!(exception instanceof BadCredentialsException)) {
            return LoginFailureReason.ERROR;
        }
        // 帳號不存在、已刪除或沒有密碼時，Spring 也回報 BadCredentialsException
        return user.map(LoginFailureHandler::badCredentialsReason).orElse(LoginFailureReason.UNKNOWN_USER);
    }

    private static LoginFailureReason badCredentialsReason(UserAccount user) {
        if (user.status() == UserStatus.DELETED) {
            return LoginFailureReason.DISABLED;
        }
        return user.passwordHash() == null ? LoginFailureReason.NO_PASSWORD : LoginFailureReason.BAD_CREDENTIALS;
    }
}
