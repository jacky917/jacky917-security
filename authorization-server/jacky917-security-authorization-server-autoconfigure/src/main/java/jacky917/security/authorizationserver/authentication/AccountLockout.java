package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.LockoutPolicy;
import jacky917.security.authorizationserver.user.UserAccountService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Instant;

/**
 * Counts a wrong password towards locking the account, and audits the lock
 * (detailed design §5.1).
 * <p>
 * 把一次密碼錯誤計入帳號鎖定，並稽核鎖定（詳細設計 §5.1）。
 * <p>
 * Every form that checks a password uses it, so they all lock the account
 * the same way: the login page and the account link confirmation.
 * <p>
 * 所有檢查密碼的表單都使用它，以相同的方式鎖定帳號：登入頁與帳號連結確認頁。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class AccountLockout {

    private final UserAccountService users;
    private final ApplicationEventPublisher events;
    private final LockoutPolicy policy;

    /**
     * Creates the lockout.
     * <p>
     * 建立帳號鎖定處理。
     *
     * @param users   the user accounts
     *                <br>使用者帳號
     * @param events  publishes the {@code ACCOUNT_LOCKED} audit event
     *                <br>發布 {@code ACCOUNT_LOCKED} 稽核事件
     * @param policy  when an account is locked
     *                <br>何時鎖定帳號
     */
    public AccountLockout(UserAccountService users, ApplicationEventPublisher events, LockoutPolicy policy) {
        this.users = users;
        this.events = events;
        this.policy = policy;
    }

    /**
     * Records a wrong password, and publishes {@code ACCOUNT_LOCKED} if it
     * locked the account.
     * <p>
     * 記錄一次密碼錯誤；若因此鎖定帳號，發布 {@code ACCOUNT_LOCKED}。
     *
     * @param userId   the user whose password was wrong
     *                 <br>密碼錯誤的使用者
     * @param at       the time of the failure
     *                 <br>失敗的時間
     * @param request  the current request, for the audit
     *                 <br>目前的請求，用於稽核
     * @return {@code true} if this failure locked the account
     *         <br>此次失敗造成帳號鎖定時為 {@code true}
     */
    public boolean recordFailure(String userId, Instant at, HttpServletRequest request) {
        if (!users.recordLoginFailure(userId, at, policy)) {
            return false;
        }
        log.info("Locked user {} for {} after {} failed logins", userId, policy.lockDuration(), policy.maxFailures());
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.ACCOUNT_LOCKED, at, false)
                .userId(userId).login(LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP).request(request).build());
        return true;
    }
}
