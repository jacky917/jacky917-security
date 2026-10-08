package jacky917.security.authorizationserver.consent;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.util.Arrays;
import java.util.List;

/**
 * The applications a user allowed to use their account: the consents on
 * the account page, and withdrawing them (phase 3 and 4 design §6.3).
 * <p>
 * 使用者允許使用其帳號的應用程式：帳號頁上的同意紀錄，以及撤回（第 3、4 階段
 * 設計 §6.3）。
 * <p>
 * Withdrawing deletes the consent and every authorization of that client
 * for the user, so its refresh tokens stop working at once; access tokens
 * already issued stay valid until they expire. The next authorization
 * request asks for consent again.
 * <p>
 * 撤回時刪除同意紀錄，以及該 client 對此使用者的所有授權，Refresh Token 因此
 * 立即失效；已簽發的 Access Token 仍有效至到期。下一次授權請求會再次要求
 * 同意。
 * <p>
 * It works for suspended clients too, and audits {@code CONSENT_REVOKED}.
 * <p>
 * 已停權的 client 也可以撤回，並稽核 {@code CONSENT_REVOKED}。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class AuthorizedApplicationService {

    private final JdbcClient jdbc;
    private final ScopeDescriptions scopes;
    private final ApplicationEventPublisher events;
    private final TransactionOperations transactions;
    private final Clock clock;

    /**
     * Creates the service.
     * <p>
     * 建立服務。
     *
     * @param jdbc          the JDBC client of the authorization server
     *                      database
     *                      <br>Authorization Server 資料庫的 JDBC client
     * @param scopes        describes the consented scopes
     *                      <br>描述已同意的 scope
     * @param events        publishes the audit events
     *                      <br>發布稽核事件
     * @param transactions  removes the consent and the authorizations
     *                      together
     *                      <br>在同一個交易中刪除同意紀錄與授權
     * @param clock         the clock
     *                      <br>時鐘
     */
    public AuthorizedApplicationService(JdbcClient jdbc, ScopeDescriptions scopes, ApplicationEventPublisher events,
                                        TransactionOperations transactions, Clock clock) {
        this.jdbc = jdbc;
        this.scopes = scopes;
        this.events = events;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * Returns the applications a user consented to, by name.
     * <p>
     * 回傳使用者同意過的應用程式，依名稱排序。
     *
     * @param userId  the user
     *                <br>使用者
     * @return the applications
     *         <br>應用程式
     */
    public List<AuthorizedApplication> list(String userId) {
        return jdbc.sql("""
                        SELECT r.client_id, COALESCE(p.display_name, r.client_name) AS name, p.logo_url,
                            p.homepage_url, c.authorities
                        FROM oauth2_authorization_consent c
                        JOIN oauth2_registered_client r ON r.id = c.registered_client_id
                        LEFT JOIN client_profile p ON p.registered_client_id = r.id
                        WHERE c.principal_name = :user""")
                .param("user", userId)
                .query((rs, rowNum) -> new AuthorizedApplication(rs.getString("client_id"), rs.getString("name"),
                        rs.getString("logo_url"), rs.getString("homepage_url"),
                        scopes.describe(scopeCodes(rs.getString("authorities")))))
                .list().stream()
                .sorted((a, b) -> a.name().compareToIgnoreCase(b.name()))
                .toList();
    }

    /**
     * Withdraws a user's consent to a client and deletes the client's
     * authorizations for the user.
     * <p>
     * 撤回使用者對 client 的同意，並刪除該 client 對此使用者的授權。
     *
     * @param userId    the user
     *                  <br>使用者
     * @param clientId  the client id
     *                  <br>client id
     * @param request   the current request, for the audit
     *                  <br>目前的請求，用於稽核
     * @return {@code true} if there was a consent to withdraw
     *         <br>有同意紀錄可撤回時為 {@code true}
     */
    public boolean revoke(String userId, String clientId, HttpServletRequest request) {
        String registeredClientId = transactions.execute(status -> {
            String id = jdbc.sql("SELECT id FROM oauth2_registered_client WHERE client_id = :client")
                    .param("client", clientId).query(String.class).optional().orElse(null);
            if (id == null || jdbc.sql("DELETE FROM oauth2_authorization_consent WHERE registered_client_id = :client "
                    + "AND principal_name = :user").param("client", id).param("user", userId).update() == 0) {
                return null;
            }
            // session_authorization 由外鍵 ON DELETE CASCADE 一併刪除
            int deleted = jdbc.sql("DELETE FROM oauth2_authorization WHERE registered_client_id = :client "
                            + "AND principal_name = :user")
                    .param("client", id).param("user", userId).update();
            log.info("User {} withdrew the consent to client {}; {} authorizations deleted", userId, clientId,
                    deleted);
            return id;
        });
        if (registeredClientId == null) {
            return false;
        }
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.CONSENT_REVOKED, clock.instant(), true)
                .userId(userId).registeredClientId(registeredClientId).request(request).build());
        return true;
    }

    private static List<String> scopeCodes(@Nullable String authorities) {
        if (authorities == null || authorities.isBlank()) {
            return List.of();
        }
        // JdbcOAuth2AuthorizationConsentService 以逗號分隔儲存，scope 的權限名稱為 "SCOPE_" + scope
        return Arrays.stream(authorities.split(","))
                .filter(authority -> authority.startsWith("SCOPE_"))
                .map(authority -> authority.substring("SCOPE_".length()))
                .toList();
    }

    /**
     * An application a user consented to.
     * <p>
     * 使用者同意過的應用程式。
     *
     * @param clientId     the client id
     *                     <br>client id
     * @param name         the name shown to users
     *                     <br>顯示給使用者的名稱
     * @param logoUrl      the logo, or {@code null}
     *                     <br>Logo，或 {@code null}
     * @param homepageUrl  the home page, or {@code null}
     *                     <br>首頁，或 {@code null}
     * @param scopes       the consented scopes
     *                     <br>已同意的 scope
     */
    public record AuthorizedApplication(String clientId, String name, @Nullable String logoUrl,
                                        @Nullable String homepageUrl, List<ScopeDescriptions.Scope> scopes) {
    }
}
