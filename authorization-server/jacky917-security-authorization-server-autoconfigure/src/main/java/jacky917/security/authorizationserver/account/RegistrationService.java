package jacky917.security.authorizationserver.account;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.user.NewUser;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionOperations;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Registers accounts with an email address and verifies the address
 * (phase 3 and 4 design §5.4, D27).
 * <p>
 * 以 Email 註冊帳號並驗證 Email（第 3、4 階段設計 §5.4、D27）。
 * <ul>
 *   <li>A new address creates an account with the {@code USER} role whose
 *       email is not verified yet; it cannot log in until the address is
 *       verified, because logins accept only verified emails.
 *       <br>新的地址建立一個擁有 {@code USER} 角色、Email 尚未驗證的帳號；
 *       驗證之前無法登入，因為登入只接受已驗證的 Email。</li>
 *   <li>An address of an unfinished registration (active, has a password,
 *       not verified, never logged in, no username, no linked account)
 *       replaces that registration's password and name, so nobody can block
 *       an address by registering it first.
 *       <br>屬於未完成之註冊（啟用中、有密碼、未驗證、從未登入、沒有帳號名稱、
 *       沒有連結的外部帳號）的地址，會取代該註冊的密碼與名稱，因此沒有人能先以
 *       他人的地址註冊來占用。</li>
 *   <li>The verified address of an active account changes nothing; its
 *       owner gets a notice with a password reset link instead, as from the
 *       forgotten password page.
 *       <br>啟用中帳號的已驗證地址不會變更任何資料；改寄通知給地址的擁有者，並
 *       附上重設密碼的連結，與忘記密碼頁相同。</li>
 *   <li>An address of any other account gets no mail: a reset link must
 *       never reach an address that was not verified.
 *       <br>屬於其他帳號的地址不會收到信：重設連結絕不能寄到未驗證的地址。</li>
 *   <li>Verifying needs the link and the password chosen when registering.
 *       <br>驗證需要連結以及註冊時設定的密碼。</li>
 * </ul>
 * The caller shows the same page in every case and mails are sent in the
 * background, so the page does not reveal whether an address has an
 * account; only a new or unfinished registration takes the time of
 * hashing a password. Mails
 * are limited by {@link ActionTokenService#COOLDOWN}.
 * <p>
 * 呼叫端在每一種情況都顯示相同的頁面，信件也在背景寄出，因此頁面不會透露地址
 * 是否已有帳號；只有新的或未完成的註冊需要多花雜湊密碼的時間。信件數量受
 * {@code ActionTokenService#COOLDOWN} 限制。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class RegistrationService {

    private final UserAccountService users;
    private final JdbcClient jdbc;
    private final PasswordEncoder passwordEncoder;
    private final ActionTokenService tokens;
    private final AccountMailDispatcher mailer;
    private final AccountLinks links;
    private final ApplicationEventPublisher events;
    private final TransactionOperations transactions;
    private final Duration verificationTtl;
    private final Duration resetTtl;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param users            creates the accounts
     *                         <br>建立帳號
     * @param jdbc             the JDBC client of the authorization server
     *                         database
     *                         <br>Authorization Server 資料庫的 JDBC client
     * @param passwordEncoder  hashes the password of a replaced registration
     *                         and checks the password when verifying
     *                         <br>雜湊被取代之註冊的密碼，並在驗證時檢查密碼
     * @param tokens           issues and uses the email tokens
     *                         <br>發出與使用 Email token
     * @param mailer           sends the mails in the background
     *                         <br>在背景寄出信件
     * @param links            builds the links
     *                         <br>產生連結
     * @param events           publishes the audit events
     *                         <br>發布稽核事件
     * @param transactions     uses the link and verifies the email together
     *                         <br>在同一個交易中使用連結並驗證 Email
     * @param verificationTtl  how long a verification link works
     *                         <br>驗證連結的有效期
     * @param resetTtl         how long a password reset link works
     *                         <br>重設密碼連結的有效期
     * @param clock            the clock
     *                         <br>時鐘
     * @throws IllegalStateException if {@code mailer} cannot send mails;
     *         registering needs the verification mail
     *         <br>若 {@code mailer} 無法寄信；註冊需要寄出驗證信
     */
    public RegistrationService(UserAccountService users, JdbcClient jdbc, PasswordEncoder passwordEncoder,
                               ActionTokenService tokens, AccountMailDispatcher mailer, AccountLinks links,
                               ApplicationEventPublisher events, TransactionOperations transactions,
                               Duration verificationTtl, Duration resetTtl, Clock clock) {
        // 無法寄信時讓啟動失敗，而不是開放一個無法完成的註冊頁
        if (!mailer.isAvailable()) {
            throw new IllegalStateException("jacky917.security.authorization-server.account.registration.enabled "
                    + "needs a way to send mails: add spring-boot-starter-mail and set spring.mail.host, or set "
                    + "jacky917.security.authorization-server.account.mail.log-links=true for development");
        }
        this.users = users;
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
        this.tokens = tokens;
        this.mailer = mailer;
        this.links = links;
        this.events = events;
        this.transactions = transactions;
        this.verificationTtl = verificationTtl;
        this.resetTtl = resetTtl;
        this.clock = clock;
    }

    /**
     * Registers an address, or tells its owner that it already has an
     * account. The password must already follow the policy.
     * <p>
     * 註冊一個地址，或通知其擁有者已經有帳號。密碼必須已符合政策。
     *
     * @param email        the email address
     *                     <br>Email
     * @param displayName  the user's name, or {@code null}
     *                     <br>使用者名稱，或 {@code null}
     * @param password     the password
     *                     <br>密碼
     * @param request      the current request, for the audit
     *                     <br>目前的請求，用於稽核
     * @param locale       the language of the mails
     *                     <br>信件語言
     */
    public void register(String email, @Nullable String displayName, String password, HttpServletRequest request,
                         Locale locale) {
        String address = email.strip();
        Optional<Existing> existing = findByEmail(address);
        if (existing.isEmpty()) {
            UserAccount created;
            try {
                created = users.createUser(new NewUser(null, address, false, password, displayName, Set.of()));
            } catch (DuplicateKeyException ex) {
                // 另一個請求同時建立了此 Email：不寄信，畫面仍相同（另一個請求會寄出驗證信）
                log.info("Registration of an email raced with another registration of the same email");
                return;
            }
            log.info("Registered user {}", created.id());
            events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.USER_REGISTERED, clock.instant(), true)
                    .userId(created.id()).login(LoginMethod.PASSWORD, LoginMethod.LOCAL_IDP).request(request).build());
            sendVerification(created.id(), address, displayName, locale);
            return;
        }
        Existing user = existing.get();
        if (user.unfinishedRegistration()) {
            Instant now = clock.instant();
            jdbc.sql("UPDATE app_user SET password_hash = :hash, display_name = :name, password_changed_at = :at, "
                            + "updated_at = :at, row_version = row_version + 1 WHERE id = :id")
                    .param("hash", passwordEncoder.encode(password)).param("name", displayName)
                    .param("at", Timestamp.from(now)).param("id", user.id()).update();
            log.info("Replaced the unfinished registration of user {}", user.id());
            sendVerification(user.id(), address, displayName, locale);
            return;
        }
        if (!user.verifiedAndActive()) {
            // 重設連結只能寄到已驗證的地址（與忘記密碼頁相同）；其他帳號的地址不寄任何信
            log.info("Registration of the email of user {} ignored: the email is not verified or the account "
                    + "cannot log in", user.id());
            return;
        }
        Optional<String> token = tokens.issue(user.id(), ActionTokenService.Purpose.PASSWORD_RESET, resetTtl);
        if (token.isEmpty()) {
            log.info("Not sending another account notice to user {} so soon", user.id());
            return;
        }
        send(new AccountMail(AccountMail.Type.ACCOUNT_EXISTS, address, locale, user.displayName(),
                links.withToken(AccountPaths.RESET_PASSWORD, token.get()), resetTtl), user.id());
    }

    /**
     * Sends the verification link again to an unfinished registration;
     * does nothing for any other address.
     * <p>
     * 對未完成的註冊重新寄出驗證連結；其他地址不做任何事。
     *
     * @param email   the email address
     *                <br>Email
     * @param locale  the language of the mail
     *                <br>信件語言
     */
    public void resendVerification(String email, Locale locale) {
        String address = email.strip();
        findByEmail(address).filter(Existing::unfinishedRegistration)
                .ifPresent(user -> sendVerification(user.id(), address, user.displayName(), locale));
    }

    /**
     * Returns whether a verification link still works, without using it.
     * <p>
     * 回傳驗證連結是否仍有效，但不使用它。
     *
     * @param token  the token from the link
     *               <br>連結中的 token
     * @return {@code true} if it can verify an address
     *         <br>可以驗證地址時為 {@code true}
     */
    public boolean isValid(String token) {
        return tokens.find(token, ActionTokenService.Purpose.EMAIL_VERIFY).isPresent();
    }

    /**
     * Verifies the address of a link and uses the link, if the password is
     * the one chosen when registering.
     * <p>
     * 若密碼是註冊時設定的密碼，驗證連結所屬的地址並使用連結。
     * <p>
     * Asking for the password proves that the person who registered also
     * reads the mailbox: someone who registers another person's address
     * cannot get an account when that person opens the link, and a
     * registration that replaced an earlier one cannot be verified with the
     * earlier link and password.
     * <p>
     * 要求輸入密碼可以證明註冊的人也能讀取該信箱：以他人地址註冊的人，無法
     * 在對方開啟連結時取得帳號；取代了先前註冊的新註冊，也無法以先前的連結
     * 與密碼完成驗證。
     *
     * @param token     the token from the link
     *                  <br>連結中的 token
     * @param password  the password chosen when registering
     *                  <br>註冊時設定的密碼
     * @param request   the current request, for the audit
     *                  <br>目前的請求，用於稽核
     * @return the outcome
     *         <br>結果
     */
    public Verification verify(String token, String password, HttpServletRequest request) {
        Optional<UserAccount> user = tokens.find(token, ActionTokenService.Purpose.EMAIL_VERIFY)
                .flatMap(users::findById);
        if (user.isEmpty()) {
            return Verification.INVALID_LINK;
        }
        String userId = user.get().id();
        if (user.get().passwordHash() == null || !passwordEncoder.matches(password, user.get().passwordHash())) {
            log.info("Email verification of user {} refused: wrong password", userId);
            events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.EMAIL_VERIFIED, clock.instant(), false)
                    .userId(userId).failureReason(LoginFailureReason.BAD_CREDENTIALS).request(request).build());
            return Verification.WRONG_PASSWORD;
        }
        Boolean verified = transactions.execute(status -> {
            if (tokens.consume(token, ActionTokenService.Purpose.EMAIL_VERIFY).isEmpty()) {
                return false;
            }
            jdbc.sql("UPDATE app_user SET email_verified = :verified, updated_at = :at, "
                            + "row_version = row_version + 1 WHERE id = :id")
                    .param("verified", true).param("at", Timestamp.from(clock.instant())).param("id", userId).update();
            return true;
        });
        if (!Boolean.TRUE.equals(verified)) {
            return Verification.INVALID_LINK;
        }
        log.info("User {} verified their email", userId);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.EMAIL_VERIFIED, clock.instant(), true)
                .userId(userId).request(request).build());
        return Verification.VERIFIED;
    }

    private void sendVerification(String userId, String address, @Nullable String displayName, Locale locale) {
        tokens.issue(userId, ActionTokenService.Purpose.EMAIL_VERIFY, verificationTtl).ifPresent(token -> send(
                new AccountMail(AccountMail.Type.EMAIL_VERIFICATION, address, locale, displayName,
                        links.withToken(AccountPaths.VERIFY_EMAIL, token), verificationTtl), userId));
    }

    private void send(AccountMail mail, String userId) {
        mailer.send(mail, userId);
    }

    private Optional<Existing> findByEmail(String email) {
        return jdbc.sql("""
                        SELECT u.id, u.display_name,
                            (u.email_verified = :no AND u.last_login_at IS NULL AND u.username IS NULL
                                AND u.password_hash IS NOT NULL AND u.status = 'ACTIVE'
                                AND NOT EXISTS (SELECT 1 FROM user_federated_identity f WHERE f.user_id = u.id))
                                AS unfinished,
                            (u.email_verified = :yes AND u.status = 'ACTIVE') AS verified_active
                        FROM app_user u WHERE LOWER(u.email) = LOWER(:email)""")
                .param("no", false).param("yes", true).param("email", email)
                .query((rs, rowNum) -> new Existing(rs.getString("id"), rs.getString("display_name"),
                        rs.getBoolean("unfinished"), rs.getBoolean("verified_active")))
                .optional();
    }

    private record Existing(String id, @Nullable String displayName, boolean unfinishedRegistration,
                            boolean verifiedAndActive) {
    }

    /**
     * The result of verifying an email address.
     * <p>
     * 驗證 Email 的結果。
     */
    public enum Verification {

        /**
         * The address is verified; the user can log in.
         * <p>
         * 地址已驗證；使用者可以登入。
         */
        VERIFIED,

        /**
         * The link is unknown, used or expired.
         * <p>
         * 連結不存在、已使用或已到期。
         */
        INVALID_LINK,

        /**
         * The password is not the one chosen when registering; the link
         * still works.
         * <p>
         * 密碼不是註冊時設定的密碼；連結仍然有效。
         */
        WRONG_PASSWORD
    }
}
