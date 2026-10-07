package jacky917.security.authorizationserver.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;

/**
 * Links every authorization code authorization to the login session it
 * came from (detailed design §5.2).
 * <p>
 * 將每一個授權碼流程的授權連結到其來源的登入 Session（詳細設計 §5.2）。
 * <p>
 * The login session ({@code auth_session}) is created at login, but the
 * authorization only when the code is issued. When an authorization is
 * saved for the first time, its login session id ({@code asid}) is taken
 * from the authorization server's browser session and stored in
 * {@code session_authorization}, in the same transaction. Later saves (the
 * token exchange, refreshes) come from the client, not the browser, and
 * reuse the existing link.
 * <p>
 * 登入 Session（{@code auth_session}）在登入時建立，授權則在發出授權碼時才
 * 建立。授權第一次儲存時，從 Authorization Server 的瀏覽器 Session 取得登入
 * Session ID（{@code asid}），在同一個交易中寫入 {@code session_authorization}。
 * 之後的儲存（換 Token、刷新）來自 client 而不是瀏覽器，沿用既有的連結。
 * <p>
 * A new authorization without an {@code asid}, or with one that is not an
 * active session of the same user, is rejected: it means the login did not
 * go through the success handler.
 * <p>
 * 新授權沒有 {@code asid}，或 {@code asid} 不是同一位使用者的有效 Session 時
 * 拒絕儲存：代表登入沒有經過登入成功處理。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class SessionLinkingAuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService delegate;
    private final SessionAuthorizationRepository links;
    private final TransactionTemplate transactions;
    private final Clock clock;

    /**
     * Wraps the given service.
     * <p>
     * 包裝指定的服務。
     *
     * @param delegate      the service that stores authorizations
     *                      <br>實際儲存授權的服務
     * @param links         the authorization links
     *                      <br>授權連結
     * @param transactions  saves the authorization and its link together
     *                      <br>在同一個交易中儲存授權與連結
     * @param clock         the clock for timestamps
     *                      <br>用於時間戳記的時鐘
     */
    public SessionLinkingAuthorizationService(OAuth2AuthorizationService delegate, SessionAuthorizationRepository links,
                                              TransactionTemplate transactions, Clock clock) {
        this.delegate = delegate;
        this.links = links;
        this.transactions = transactions;
        this.clock = clock;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        transactions.executeWithoutResult(status -> {
            delegate.save(authorization);
            if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorization.getAuthorizationGrantType())
                    && links.findSessionId(authorization.getId()).isEmpty()) {
                link(authorization);
            }
        });
    }

    private void link(OAuth2Authorization authorization) {
        String sessionId = currentSessionId();
        if (sessionId == null) {
            log.error("Authorization {} for client {} has no login session: the login did not go through the "
                    + "authorization server's success handler", authorization.getId(), authorization.getRegisteredClientId());
            throw new IllegalStateException("The authorization has no login session");
        }
        boolean linked = links.link(authorization.getId(), sessionId, authorization.getPrincipalName(),
                authorization.getRegisteredClientId(), clock.instant());
        if (!linked) {
            log.error("Login session {} is not an active session of the user of authorization {}", sessionId,
                    authorization.getId());
            throw new IllegalStateException("The login session is not active for this user");
        }
    }

    private static @Nullable String currentSessionId() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (!(attributes instanceof ServletRequestAttributes servlet)) {
            return null;
        }
        HttpServletRequest request = servlet.getRequest();
        HttpSession session = request.getSession(false);
        return session == null ? null : (String) session.getAttribute(AuthSessionService.SESSION_ATTRIBUTE);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        // session_authorization 由外鍵 ON DELETE CASCADE 一併刪除
        delegate.remove(authorization);
    }

    @Override
    public @Nullable OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public @Nullable OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
    }
}
