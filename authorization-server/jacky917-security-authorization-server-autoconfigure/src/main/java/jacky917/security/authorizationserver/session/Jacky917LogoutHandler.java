package jacky917.security.authorizationserver.session;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.time.Clock;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Ends the login session on logout, not only the browser login (detailed
 * design §5.5).
 * <p>
 * 登出時結束登入 Session，而不只是瀏覽器的登入（詳細設計 §5.5）。
 * <p>
 * The login session is found in two ways: the authorization server's
 * browser session, and, for RP-Initiated Logout, the authorization of the
 * {@code id_token_hint}. The second one still works after the browser
 * session has expired, and even when the ID token itself has expired, as
 * long as its authorization exists. Every session found is revoked with
 * {@link RevokeReason#LOGOUT}, which deletes its authorizations so its
 * refresh tokens stop working; a {@code LOGOUT} audit event is published
 * for each session that was still active. The browser login is then
 * ended, even when revoking a session failed: the failure is logged as an
 * error, because that session and its refresh tokens stay valid.
 * <p>
 * 登入 Session 以兩種方式找到：Authorization Server 的瀏覽器 Session，以及
 * RP-Initiated Logout 時 {@code id_token_hint} 所屬的授權。後者在瀏覽器
 * Session 已過期、甚至 ID Token 本身已過期時仍可使用，只要授權仍存在。找到的
 * Session 都以 {@code LOGOUT} 撤銷，並刪除其授權，Refresh Token 因此失效；每個
 * 原本有效的 Session 各發布一個 {@code LOGOUT} 稽核事件。最後結束瀏覽器的登入；
 * 即使撤銷 Session 失敗也會結束：失敗記錄為錯誤，因為該 Session 與其 Refresh
 * Token 仍然有效。
 * <p>
 * A session from the browser is revoked only when it belongs to the user
 * logged in to that browser.
 * <p>
 * 來自瀏覽器的 Session 只有在屬於該瀏覽器登入的使用者時才會撤銷。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class Jacky917LogoutHandler implements LogoutHandler {

    private static final OAuth2TokenType ID_TOKEN = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    private final AuthSessionService sessions;
    private final OAuth2AuthorizationService authorizations;
    private final SessionAuthorizationRepository links;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final SecurityContextLogoutHandler browserLogout = new SecurityContextLogoutHandler();

    /**
     * Creates the handler.
     * <p>
     * 建立處理器。
     *
     * @param sessions        the login sessions
     *                        <br>登入 Session
     * @param authorizations  the authorizations, to find the session of an
     *                        ID token
     *                        <br>授權，用於找出 ID Token 所屬的 Session
     * @param links           the authorization links
     *                        <br>授權連結
     * @param events          publishes the audit events
     *                        <br>發布稽核事件
     * @param clock           the clock for the audit time
     *                        <br>稽核時間所用的時鐘
     */
    public Jacky917LogoutHandler(AuthSessionService sessions, OAuth2AuthorizationService authorizations,
                                 SessionAuthorizationRepository links, ApplicationEventPublisher events, Clock clock) {
        this.sessions = sessions;
        this.authorizations = authorizations;
        this.links = links;
        this.events = events;
        this.clock = clock;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
                       @Nullable Authentication authentication) {
        // 以 Session ID 為鍵，值為登出的 client（不明時為 null）
        Map<String, String> found = new LinkedHashMap<>();
        String browserUser = browserUser(authentication);
        HttpSession httpSession = request.getSession(false);
        if (httpSession != null && browserUser != null
                && httpSession.getAttribute(AuthSessionService.SESSION_ATTRIBUTE) instanceof String asid) {
            sessions.find(asid).filter(session -> session.userId().equals(browserUser))
                    .ifPresent(session -> found.put(asid, null));
        }
        if (authentication instanceof OidcLogoutAuthenticationToken oidc && oidc.getIdToken() != null) {
            OidcIdToken idToken = oidc.getIdToken();
            OAuth2Authorization authorization = authorizations.findByToken(idToken.getTokenValue(), ID_TOKEN);
            if (authorization != null) {
                links.findSessionId(authorization.getId())
                        .ifPresent(asid -> found.put(asid, authorization.getRegisteredClientId()));
            }
        }
        try {
            found.forEach((asid, clientId) -> {
                try {
                    end(asid, RevokeReason.LOGOUT, clientId, request);
                } catch (DataAccessException ex) {
                    log.error("Cannot revoke login session {} on logout; it stays active and its refresh tokens keep "
                            + "working", asid, ex);
                }
            });
        } finally {
            // 無論撤銷是否成功，都結束瀏覽器的登入：共用電腦上按下登出後不能仍是登入狀態
            browserLogout.logout(request, response, authentication);
        }
    }

    /**
     * Revokes one login session and publishes a {@code LOGOUT} audit event
     * when it was active.
     * <p>
     * 撤銷一個登入 Session；Session 原本有效時發布 {@code LOGOUT} 稽核事件。
     *
     * @param sessionId           the session id
     *                            <br>Session ID
     * @param reason              why it ends
     *                            <br>結束原因
     * @param registeredClientId  the client that asked for it, or
     *                            {@code null}
     *                            <br>提出要求的 client，或 {@code null}
     * @param request             the current request, for the audit
     *                            <br>目前的請求，用於稽核
     * @return {@code true} if the session was active and is now revoked
     *         <br>Session 原本有效且已被撤銷時為 {@code true}
     */
    public boolean end(String sessionId, RevokeReason reason, @Nullable String registeredClientId,
                       HttpServletRequest request) {
        AuthSession session = sessions.find(sessionId).orElse(null);
        if (session == null || !sessions.revoke(sessionId, reason)) {
            return false;
        }
        audit(session, reason, registeredClientId, request);
        return true;
    }

    /**
     * Revokes every active login session of a user in one transaction, and
     * publishes a {@code LOGOUT} audit event for each one revoked.
     * <p>
     * 在同一個交易中撤銷使用者所有有效的登入 Session，並為每個被撤銷的 Session
     * 發布 {@code LOGOUT} 稽核事件。
     *
     * @param userId   the user
     *                 <br>使用者
     * @param reason   why they end
     *                 <br>結束原因
     * @param request  the current request, for the audit
     *                 <br>目前的請求，用於稽核
     * @return the number of sessions revoked
     *         <br>被撤銷的 Session 數量
     */
    public int endAll(String userId, RevokeReason reason, HttpServletRequest request) {
        List<AuthSession> active = sessions.findActive(userId);
        Set<String> revoked = new HashSet<>(sessions.revokeAll(userId, reason, null));
        // 稽核在交易提交之後發布
        active.stream().filter(session -> revoked.contains(session.sessionId()))
                .forEach(session -> audit(session, reason, null, request));
        return revoked.size();
    }

    private void audit(AuthSession session, RevokeReason reason, @Nullable String registeredClientId,
                       HttpServletRequest request) {
        log.info("Revoked login session {} of user {} ({})", session.sessionId(), session.userId(), reason);
        events.publishEvent(LoginAuditEvent.builder(LoginAuditEventType.LOGOUT, clock.instant(), true)
                .userId(session.userId())
                .login(session.loginMethod(), session.idp())
                .registeredClientId(registeredClientId)
                .sessionId(session.sessionId())
                .request(request)
                .build());
    }

    private static @Nullable String browserUser(@Nullable Authentication authentication) {
        Authentication user = authentication;
        if (authentication instanceof OidcLogoutAuthenticationToken oidc) {
            user = oidc.isPrincipalAuthenticated() ? (Authentication) oidc.getPrincipal() : null;
        }
        if (user == null || !user.isAuthenticated() || user instanceof AnonymousAuthenticationToken) {
            return null;
        }
        return user.getName();
    }
}
