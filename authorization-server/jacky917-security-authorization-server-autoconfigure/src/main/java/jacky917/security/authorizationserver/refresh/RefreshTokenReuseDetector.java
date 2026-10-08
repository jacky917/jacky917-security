package jacky917.security.authorizationserver.refresh;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.database.AuthorizationServerDialect;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.AuthSessionStatus;
import jacky917.security.authorizationserver.session.RevokeReason;
import jacky917.security.authorizationserver.session.SessionAuthorizationRepository;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Detects reuse of rotated refresh tokens and checks the login session
 * before every refresh (detailed design §5.4, D19).
 * <p>
 * 偵測已輪換 Refresh Token 的重用，並在每次刷新前檢查登入 Session（詳細設計
 * §5.4、D19）。
 * <p>
 * Each refresh runs in one transaction: the authorization row is locked,
 * Spring's refresh provider issues and stores the new tokens, and the old
 * refresh token is remembered in {@code refresh_token_history}. A second
 * concurrent refresh of the same token waits for the first and then finds
 * the token rotated.
 * <p>
 * 每次刷新在同一個交易中執行：鎖定授權列、由 Spring 的刷新 provider 簽發並儲存
 * 新 token，再把舊的 Refresh Token 記錄到 {@code refresh_token_history}。同一個
 * token 的第二個併發刷新會等待第一個完成，接著發現 token 已被輪換。
 * <p>
 * A rotated token presented again is refused with {@code invalid_grant}.
 * Within the grace period this is treated as a concurrent request; after
 * it, the login session is revoked, which also invalidates the newest
 * refresh token, and a {@link LoginAuditEventType#TOKEN_REFRESH_REUSE}
 * event is published. Every refusal returns {@code invalid_grant} without
 * the reason (detailed design §7.1).
 * <p>
 * 再次出現的已輪換 token 以 {@code invalid_grant} 拒絕：在寬限期內視為併發
 * 請求；超過寬限期則撤銷登入 Session（最新的 Refresh Token 也一併失效），並發布
 * {@code TOKEN_REFRESH_REUSE} 事件。所有拒絕一律回傳 {@code invalid_grant}，
 * 不揭露原因（詳細設計 §7.1）。
 * <p>
 * Every refusal also publishes a {@link RefreshTokenRejectedEvent} with the
 * reason, after the transaction has ended.
 * <p>
 * 每次拒絕也會在交易結束後發布帶有原因的 {@code RefreshTokenRejectedEvent}。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Slf4j
public class RefreshTokenReuseDetector {

    private final OAuth2AuthorizationService authorizations;
    private final JdbcClient jdbc;
    private final AuthorizationServerDialect dialect;
    private final SessionAuthorizationRepository links;
    private final AuthSessionService sessions;
    private final UserAccountService users;
    private final RefreshTokenHistoryRepository history;
    private final TransactionOperations transactions;
    private final ApplicationEventPublisher events;
    private final Duration gracePeriod;
    private final Duration historyRetention;
    private final Clock clock;

    /**
     * Creates the detector.
     * <p>
     * 建立偵測器。
     *
     * @param authorizations    the authorization service
     *                          <br>授權服務
     * @param jdbc              the JDBC client, for the row lock
     *                          <br>JDBC client，用於列鎖
     * @param dialect           the database dialect
     *                          <br>資料庫方言
     * @param links             the authorization links
     *                          <br>授權連結
     * @param sessions          the login sessions
     *                          <br>登入 Session
     * @param users             the user accounts
     *                          <br>使用者帳號
     * @param history           the rotated refresh tokens
     *                          <br>已輪換的 Refresh Token
     * @param transactions      runs each refresh in one transaction
     *                          <br>在同一個交易中執行每次刷新
     * @param events            publishes the audit events
     *                          <br>發布稽核事件
     * @param gracePeriod       how long a rotated token counts as a
     *                          concurrent request
     *                          <br>已輪換的 token 視為併發請求的時間
     * @param historyRetention  how long a rotated token is remembered
     *                          <br>已輪換的 token 保留多久
     * @param clock             the clock
     *                          <br>時鐘
     */
    public RefreshTokenReuseDetector(OAuth2AuthorizationService authorizations, JdbcClient jdbc,
                                     AuthorizationServerDialect dialect, SessionAuthorizationRepository links,
                                     AuthSessionService sessions, UserAccountService users,
                                     RefreshTokenHistoryRepository history, TransactionOperations transactions,
                                     ApplicationEventPublisher events, Duration gracePeriod, Duration historyRetention,
                                     Clock clock) {
        this.authorizations = authorizations;
        this.jdbc = jdbc;
        this.dialect = dialect;
        this.links = links;
        this.sessions = sessions;
        this.users = users;
        this.history = history;
        this.transactions = transactions;
        this.events = events;
        this.gracePeriod = gracePeriod;
        this.historyRetention = historyRetention;
        this.clock = clock;
    }

    /**
     * Replaces Spring's refresh provider in the given list with one that
     * goes through this detector.
     * <p>
     * 把清單中 Spring 的刷新 provider 換成經過此偵測器的 provider。
     *
     * @param providers  the token endpoint's authentication providers
     *                   <br>token 端點的 authentication provider
     */
    public void install(List<AuthenticationProvider> providers) {
        providers.replaceAll(provider -> provider instanceof OAuth2RefreshTokenAuthenticationProvider
                ? new ReuseDetectingRefreshTokenProvider(provider, this) : provider);
    }

    /**
     * Refreshes the tokens through the given provider, after the checks of
     * this detector.
     * <p>
     * 經過此偵測器的檢查後，以指定的 provider 刷新 token。
     *
     * @param request   the refresh request, with an authenticated client
     *                  <br>已驗證 client 的刷新請求
     * @param delegate  Spring's refresh provider
     *                  <br>Spring 的刷新 provider
     * @return the new tokens
     *         <br>新的 token
     * @throws OAuth2AuthenticationException {@code invalid_grant} if the
     *         token is unknown, rotated, or its session or user is no longer
     *         valid; any error of the delegate
     *         <br>token 不存在、已被輪換，或 Session、使用者已失效時為
     *         {@code invalid_grant}；以及 delegate 的任何錯誤
     */
    public Authentication authenticate(OAuth2RefreshTokenAuthenticationToken request, AuthenticationProvider delegate) {
        Outcome outcome = transactions.execute(status -> attempt(request, delegate));
        // 交易提交後才發布：稽核不描述已回滾的變更
        if (outcome != null) {
            outcome.events().forEach(events::publishEvent);
        }
        if (outcome == null || outcome.result() == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        return outcome.result();
    }

    private Outcome attempt(OAuth2RefreshTokenAuthenticationToken request, AuthenticationProvider delegate) {
        String token = request.getRefreshToken();
        Instant now = clock.instant();
        OAuth2Authorization authorization = findAndLock(token);
        if (authorization == null) {
            return rotatedOrUnknown(token, now);
        }
        AuthSession session = links.findSessionId(authorization.getId()).flatMap(sessions::find).orElse(null);
        String clientId = authorization.getRegisteredClientId();
        if (session == null) {
            log.warn("Refusing to refresh authorization {}: it has no login session", authorization.getId());
            return Outcome.refused(RefreshTokenRejectedEvent.Reason.SESSION_NOT_ACTIVE, clientId);
        }
        if (session.status() != AuthSessionStatus.ACTIVE || !session.expiresAt().isAfter(now)) {
            // 已撤銷的 Session 沒有授權可刷新；過期的由清理排程改為 EXPIRED
            log.info("Refusing to refresh: login session {} is {}", session.sessionId(),
                    session.status() == AuthSessionStatus.ACTIVE ? "expired" : session.status());
            return Outcome.refused(RefreshTokenRejectedEvent.Reason.SESSION_NOT_ACTIVE, clientId);
        }
        RevokeReason problem = userProblem(session, users.findById(session.userId()));
        if (problem != null) {
            sessions.revoke(session.sessionId(), problem);
            log.info("Refusing to refresh: revoked login session {} of user {} ({})", session.sessionId(),
                    session.userId(), problem);
            return Outcome.refused(RefreshTokenRejectedEvent.Reason.USER_NOT_ACTIVE, clientId);
        }

        Authentication result = delegate.authenticate(request);
        if (result instanceof OAuth2AccessTokenAuthenticationToken issued && issued.getRefreshToken() != null
                && !token.equals(issued.getRefreshToken().getTokenValue())) {
            remember(token, authorization, session, now);
        }
        sessions.touch(session.sessionId());
        return new Outcome(result, List.of());
    }

    /**
     * Finds the authorization and locks its row, then reads it again: a
     * concurrent refresh that held the lock may have rotated the token.
     * <p>
     * 查詢授權並鎖定該列後再讀取一次：持有鎖的併發刷新可能已經輪換了 token。
     */
    private @Nullable OAuth2Authorization findAndLock(String token) {
        OAuth2Authorization found = authorizations.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
        if (found == null) {
            return null;
        }
        jdbc.sql(dialect.lockAuthorizationSql()).param(found.getId()).query(String.class).optional();
        return authorizations.findByToken(token, OAuth2TokenType.REFRESH_TOKEN);
    }

    private Outcome rotatedOrUnknown(String token, Instant now) {
        RotatedRefreshToken rotated = history.find(RefreshTokenHistoryRepository.hash(token), now).orElse(null);
        if (rotated == null) {
            return Outcome.refused(RefreshTokenRejectedEvent.Reason.UNKNOWN_TOKEN, null);
        }
        if (!now.isAfter(rotated.rotatedAt().plus(gracePeriod))) {
            // D19：併發刷新造成，不撤銷
            log.debug("Refusing a refresh token rotated {} ago (within the grace period) for client {}",
                    Duration.between(rotated.rotatedAt(), now), rotated.registeredClientId());
            return Outcome.refused(RefreshTokenRejectedEvent.Reason.CONCURRENT, rotated.registeredClientId());
        }
        if (rotated.sessionId() != null) {
            sessions.revoke(rotated.sessionId(), RevokeReason.REUSE_DETECTED);
        }
        log.warn("Refresh token reuse detected: a token rotated at {} was used again; revoked login session {} of "
                + "user {} (client {})", rotated.rotatedAt(), rotated.sessionId(), rotated.userId(),
                rotated.registeredClientId());
        LoginAuditEvent event = LoginAuditEvent.builder(LoginAuditEventType.TOKEN_REFRESH_REUSE, now, false)
                .userId(rotated.userId())
                .registeredClientId(rotated.registeredClientId())
                .sessionId(rotated.sessionId())
                .failureReason("REUSE_DETECTED")
                .currentRequest()
                .build();
        return new Outcome(null, List.of(event, new RefreshTokenRejectedEvent(
                RefreshTokenRejectedEvent.Reason.REUSE_DETECTED, rotated.registeredClientId())));
    }

    private @Nullable RevokeReason userProblem(AuthSession session, Optional<UserAccount> found) {
        if (found.isEmpty() || found.get().status() != UserStatus.ACTIVE) {
            return RevokeReason.USER_DISABLED;
        }
        Instant passwordChangedAt = found.get().passwordChangedAt();
        if (passwordChangedAt != null && passwordChangedAt.isAfter(session.createdAt())) {
            return RevokeReason.PASSWORD_CHANGED;
        }
        // 暫時鎖定（locked_until）不在此檢查：它只阻擋密碼登入。否則任何人只要故意輸錯密碼，
        // 就能讓帳號持有人所有裝置的刷新失敗
        return null;
    }

    private void remember(String token, OAuth2Authorization authorization, AuthSession session, Instant now) {
        OAuth2Authorization.Token<OAuth2RefreshToken> old = authorization.getRefreshToken();
        Instant issuedAt = old == null || old.getToken().getIssuedAt() == null ? now : old.getToken().getIssuedAt();
        Instant expiresAt = now.plus(historyRetention);
        if (old != null && old.getToken().getExpiresAt() != null && old.getToken().getExpiresAt().isBefore(expiresAt)) {
            expiresAt = old.getToken().getExpiresAt();
        }
        history.save(new RotatedRefreshToken(RefreshTokenHistoryRepository.hash(token), authorization.getId(),
                session.sessionId(), session.userId(), authorization.getRegisteredClientId(), issuedAt, now, expiresAt));
    }

    private record Outcome(@Nullable Authentication result, List<Object> events) {
        static Outcome refused(RefreshTokenRejectedEvent.Reason reason, @Nullable String registeredClientId) {
            return new Outcome(null, List.of(new RefreshTokenRejectedEvent(reason, registeredClientId)));
        }
    }
}
