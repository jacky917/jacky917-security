package jacky917.security.authorizationserver.account;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.authentication.AccountLockout;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.session.RevokeReason;
import jacky917.security.authorizationserver.user.PasswordPolicy;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;

/**
 * Sets a user's password and ends their other logins (phase 3 and 4 design
 * §5.2, §5.3).
 * <p>
 * 設定使用者的密碼，並結束其他登入（第 3、4 階段設計 §5.2、§5.3）。
 * <p>
 * A new password must follow the password policy and differ from the
 * current one. Setting it clears the forced change and any temporary lock,
 * revokes the login sessions other than the one to keep
 * ({@code PASSWORD_CHANGED}), writes the audit, and tells the user by mail
 * when mails can be sent and the email is verified.
 * <p>
 * 新密碼必須符合密碼政策，且不能與目前的密碼相同。設定後清除強制變更與暫時
 * 鎖定、撤銷要保留的那一個以外的登入 Session（{@code PASSWORD_CHANGED}）、寫入
 * 稽核，並在可以寄信且 Email 已驗證時寄信通知使用者。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class PasswordChangeService {

    private final UserAccountService users;
    private final JdbcClient jdbc;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final AccountLockout lockout;
    private final AuthSessionService sessions;
    private final AccountMailer mailer;
    private final AccountLinks links;
    private final ApplicationEventPublisher events;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param users            reads the user
     *                         <br>讀取使用者
     * @param jdbc             the JDBC client of the authorization server
     *                         database
     *                         <br>Authorization Server 資料庫的 JDBC client
     * @param passwordEncoder  checks and hashes passwords
     *                         <br>檢查與雜湊密碼
     * @param passwordPolicy   checks new passwords
     *                         <br>檢查新密碼
     * @param lockout          counts a wrong current password
     *                         <br>計入目前密碼的錯誤
     * @param sessions         revokes the other login sessions
     *                         <br>撤銷其他登入 Session
     * @param mailer           sends the notice
     *                         <br>寄出通知
     * @param links            builds the link in the notice
     *                         <br>產生通知中的連結
     * @param events           publishes the audit events
     *                         <br>發布稽核事件
     * @param transactions     changes the password and revokes the sessions
     *                         together
     *                         <br>在同一個交易中變更密碼並撤銷 Session
     * @param clock            the clock
     *                         <br>時鐘
     */
    public PasswordChangeService(UserAccountService users, JdbcClient jdbc, PasswordEncoder passwordEncoder,
                                 PasswordPolicy passwordPolicy, AccountLockout lockout, AuthSessionService sessions,
                                 AccountMailer mailer, AccountLinks links, ApplicationEventPublisher events,
                                 TransactionOperations transactions, Clock clock) {
        this.users = users;
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.lockout = lockout;
        this.sessions = sessions;
        this.mailer = mailer;
        this.links = links;
        this.events = events;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Changes the password of a logged-in user who knows the current one.
     * <p>
     * 變更已登入且知道目前密碼之使用者的密碼。
     *
     * @param userId           the user
     *                         <br>使用者
     * @param currentPassword  the current password
     *                         <br>目前的密碼
     * @param newPassword      the new password
     *                         <br>新密碼
     * @param keepSessionId    the login session to keep, the one making the
     *                         change, or {@code null}
     *                         <br>要保留的登入 Session，即進行變更的那一個，或
     *                         {@code null}
     * @param request          the current request, for the audit and the mail
     *                         language
     *                         <br>目前的請求，用於稽核與信件語言
     * @return the outcome
     *         <br>結果
     */
    public Outcome change(String userId, String currentPassword, String newPassword, @Nullable String keepSessionId,
                          HttpServletRequest request) {
        UserAccount user = users.findById(userId).orElse(null);
        if (user == null || user.passwordHash() == null) {
            return Outcome.NO_PASSWORD;
        }
        Instant now = clock.instant();
        if (user.isTemporarilyLocked(now)) {
            return Outcome.LOCKED;
        }
        if (!passwordEncoder.matches(currentPassword, user.passwordHash())) {
            log.info("Password change of user {} refused: wrong current password", userId);
            events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.PASSWORD_CHANGED, now, false)
                    .userId(userId).login(LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP)
                    .failureReason(LoginFailureReason.BAD_CREDENTIALS).request(request).build());
            lockout.recordFailure(userId, now, request);
            return Outcome.WRONG_PASSWORD;
        }
        Outcome invalid = validate(user, newPassword);
        if (invalid != null) {
            return invalid;
        }
        set(user, newPassword, keepSessionId, LoginAuditEventType.PASSWORD_CHANGED, request);
        return Outcome.CHANGED;
    }

    /**
     * Sets the password of a user who proved their identity another way,
     * for example with a password reset link. Every login session is
     * revoked.
     * <p>
     * 為以其他方式證明身分（例如重設密碼連結）的使用者設定密碼。所有登入
     * Session 都會撤銷。
     *
     * @param user         the user
     *                     <br>使用者
     * @param newPassword  the new password
     *                     <br>新密碼
     * @param request      the current request, for the audit and the mail
     *                     language
     *                     <br>目前的請求，用於稽核與信件語言
     * @return {@link Outcome#CHANGED}, or why the password was refused
     *         <br>{@code CHANGED}，或密碼被拒絕的原因
     */
    public Outcome reset(UserAccount user, String newPassword, HttpServletRequest request) {
        Outcome invalid = validate(user, newPassword);
        if (invalid != null) {
            return invalid;
        }
        set(user, newPassword, null, LoginAuditEventType.PASSWORD_RESET, request);
        return Outcome.CHANGED;
    }

    /**
     * Checks a new password without setting it: it must follow the policy
     * and differ from the current one.
     * <p>
     * 檢查新密碼但不設定：必須符合政策，且與目前的密碼不同。
     *
     * @param user         the user
     *                     <br>使用者
     * @param newPassword  the new password
     *                     <br>新密碼
     * @return {@link Outcome#WEAK_PASSWORD}, {@link Outcome#SAME_PASSWORD},
     *         or {@code null} if the password is acceptable
     *         <br>{@code WEAK_PASSWORD}、{@code SAME_PASSWORD}；可接受時為
     *         {@code null}
     */
    public @Nullable Outcome validate(UserAccount user, String newPassword) {
        try {
            passwordPolicy.check(newPassword);
        } catch (IllegalArgumentException ex) {
            return Outcome.WEAK_PASSWORD;
        }
        if (user.passwordHash() != null && passwordEncoder.matches(newPassword, user.passwordHash())) {
            return Outcome.SAME_PASSWORD;
        }
        return null;
    }

    private void set(UserAccount user, String newPassword, @Nullable String keepSessionId, LoginAuditEventType type,
                     HttpServletRequest request) {
        Instant now = clock.instant();
        String hash = passwordEncoder.encode(newPassword);
        transactions.executeWithoutResult(status -> {
            jdbc.sql("UPDATE app_user SET password_hash = :hash, password_changed_at = :at, "
                            + "password_change_required = :required, failed_login_count = 0, locked_until = NULL, "
                            + "updated_at = :at, row_version = row_version + 1 WHERE id = :id")
                    .param("hash", hash).param("at", Timestamp.from(now)).param("required", false)
                    .param("id", user.id()).update();
            sessions.revokeAll(user.id(), RevokeReason.PASSWORD_CHANGED, keepSessionId);
        });
        log.info("User {} set a new password ({})", user.id(), type);
        events.publishEvent(LoginAuditEvent.builder(type, now, true).userId(user.id())
                .login(LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP).sessionId(keepSessionId).request(request).build());
        notify(user, RequestContextUtils.getLocale(request));
    }

    private void notify(UserAccount user, Locale locale) {
        if (!mailer.isAvailable() || !user.emailVerified() || user.email() == null) {
            return;
        }
        try {
            mailer.send(new AccountMail(AccountMail.Type.PASSWORD_CHANGED, user.email(), locale, user.displayName(),
                    links.to(AccountPaths.FORGOT_PASSWORD), null));
        } catch (RuntimeException ex) {
            log.error("Cannot send the password change notice to user {}", user.id(), ex);
        }
    }

    /**
     * The result of setting a password.
     * <p>
     * 設定密碼的結果。
     */
    public enum Outcome {

        /**
         * The password was set.
         * <p>
         * 已設定密碼。
         */
        CHANGED,

        /**
         * The current password was wrong; it counts towards the lock.
         * <p>
         * 目前的密碼錯誤；計入帳號鎖定。
         */
        WRONG_PASSWORD,

        /**
         * The account is temporarily locked after failed logins.
         * <p>
         * 帳號因登入失敗而被暫時鎖定。
         */
        LOCKED,

        /**
         * The new password breaks the password policy.
         * <p>
         * 新密碼不符合密碼政策。
         */
        WEAK_PASSWORD,

        /**
         * The new password is the current one.
         * <p>
         * 新密碼與目前的密碼相同。
         */
        SAME_PASSWORD,

        /**
         * The user has no password to change; they can set one with a reset
         * link.
         * <p>
         * 使用者沒有可變更的密碼；可以透過重設連結設定。
         */
        NO_PASSWORD
    }
}
