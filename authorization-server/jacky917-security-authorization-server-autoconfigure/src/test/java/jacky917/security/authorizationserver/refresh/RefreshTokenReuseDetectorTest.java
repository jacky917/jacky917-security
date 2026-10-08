package jacky917.security.authorizationserver.refresh;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.database.PostgresqlDialect;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.AuthSessionStatus;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.session.RevokeReason;
import jacky917.security.authorizationserver.session.SessionAuthorizationRepository;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.support.TransactionOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link RefreshTokenReuseDetector} 的單元測試：每個分支一個案例（詳細設計 §5.4、D19）。
 */
@DisplayName("RefreshTokenReuseDetector")
class RefreshTokenReuseDetectorTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final Duration GRACE = Duration.ofSeconds(30);
    private static final Duration RETENTION = Duration.ofHours(24);
    private static final String TOKEN = "old-refresh-token";
    private static final String NEW_TOKEN = "new-refresh-token";
    private static final String ASID = "session-1";
    private static final String USER = "user-1";

    private final RegisteredClient client = RegisteredClient.withId("client-1").clientId("web-bff")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("https://app.example.com/callback").build();

    private OAuth2AuthorizationService authorizations;
    private SessionAuthorizationRepository links;
    private AuthSessionService sessions;
    private UserAccountService users;
    private RefreshTokenHistoryRepository history;
    private ApplicationEventPublisher events;
    private AuthenticationProvider delegate;
    private RefreshTokenReuseDetector detector;

    @BeforeEach
    void setUp() {
        authorizations = mock(OAuth2AuthorizationService.class);
        links = mock(SessionAuthorizationRepository.class);
        sessions = mock(AuthSessionService.class);
        users = mock(UserAccountService.class);
        history = mock(RefreshTokenHistoryRepository.class);
        events = mock(ApplicationEventPublisher.class);
        delegate = mock(AuthenticationProvider.class);
        detector = new RefreshTokenReuseDetector(authorizations, mock(JdbcClient.class, RETURNS_DEEP_STUBS),
                new PostgresqlDialect(), links, sessions, users, history, TransactionOperations.withoutTransaction(),
                events, GRACE, RETENTION, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Nested
    @DisplayName("token 已不在授權中")
    class MissingToken {

        @Test
        @DisplayName("從未見過（或已超過保留期）：invalid_grant，不撤銷任何 Session")
        void unknownToken() {
            when(history.find(anyString(), any())).thenReturn(Optional.empty());
            assertRefused();
            verify(sessions, never()).revoke(anyString(), any());
            verify(events, never()).publishEvent(any(Object.class));
        }

        @Test
        @DisplayName("寬限期內（剛好 30 秒）：視為併發，不撤銷")
        void rotatedWithinGracePeriod() {
            rotatedAt(NOW.minus(GRACE));
            assertRefused();
            verify(sessions, never()).revoke(anyString(), any());
            verify(events, never()).publishEvent(any(Object.class));
        }

        @Test
        @DisplayName("超過寬限期：撤銷 Session（REUSE_DETECTED），發布稽核事件")
        void rotatedAfterGracePeriod() {
            rotatedAt(NOW.minus(GRACE).minusMillis(1));
            assertRefused();
            verify(sessions).revoke(ASID, RevokeReason.REUSE_DETECTED);
            ArgumentCaptor<LoginAuditEvent> event = ArgumentCaptor.forClass(LoginAuditEvent.class);
            verify(events).publishEvent(event.capture());
            assertThat(event.getValue().type()).isEqualTo(LoginAuditEventType.TOKEN_REFRESH_REUSE);
            assertThat(event.getValue().userId()).isEqualTo(USER);
            assertThat(event.getValue().sessionId()).isEqualTo(ASID);
            assertThat(event.getValue().registeredClientId()).isEqualTo("client-1");
            assertThat(event.getValue().success()).isFalse();
        }

        private void rotatedAt(Instant rotatedAt) {
            when(history.find(RefreshTokenHistoryRepository.hash(TOKEN), NOW)).thenReturn(Optional.of(new RotatedRefreshToken(
                    RefreshTokenHistoryRepository.hash(TOKEN), "authorization-1", ASID, USER, "client-1",
                    rotatedAt.minus(Duration.ofMinutes(10)), rotatedAt, NOW.plus(RETENTION))));
        }
    }

    @Nested
    @DisplayName("token 仍有效：刷新前的檢查")
    class Checks {

        @BeforeEach
        void currentToken() {
            when(authorizations.findByToken(TOKEN, OAuth2TokenType.REFRESH_TOKEN))
                    .thenReturn(authorization(NOW.plus(Duration.ofDays(14))));
            when(links.findSessionId("authorization-1")).thenReturn(Optional.of(ASID));
            when(sessions.find(ASID)).thenReturn(Optional.of(session(AuthSessionStatus.ACTIVE, NOW.plus(Duration.ofDays(1)))));
            when(users.findById(USER)).thenReturn(Optional.of(user(UserStatus.ACTIVE, null, null)));
        }

        @Test
        @DisplayName("授權沒有連結到登入 Session：invalid_grant")
        void noLoginSession() {
            when(links.findSessionId("authorization-1")).thenReturn(Optional.empty());
            assertRefused();
            verify(delegate, never()).authenticate(any());
        }

        @Test
        @DisplayName("登入 Session 已撤銷或已過期：invalid_grant，不再撤銷")
        void unusableSession() {
            when(sessions.find(ASID)).thenReturn(Optional.of(session(AuthSessionStatus.REVOKED, NOW.plusSeconds(60))));
            assertRefused();
            when(sessions.find(ASID)).thenReturn(Optional.of(session(AuthSessionStatus.ACTIVE, NOW)));
            assertRefused();
            verify(sessions, never()).revoke(anyString(), any());
            verify(delegate, never()).authenticate(any());
        }

        @Test
        @DisplayName("使用者已停用、被管理員鎖定或已刪除：撤銷 Session（USER_DISABLED）")
        void inactiveUser() {
            for (Optional<UserAccount> found : List.of(Optional.of(user(UserStatus.DISABLED, null, null)),
                    Optional.of(user(UserStatus.LOCKED, null, null)), Optional.<UserAccount>empty())) {
                when(users.findById(USER)).thenReturn(found);
                assertRefused();
            }
            verify(sessions, org.mockito.Mockito.times(3)).revoke(ASID, RevokeReason.USER_DISABLED);
            verify(delegate, never()).authenticate(any());
        }

        @Test
        @DisplayName("登入之後變更了密碼：撤銷 Session（PASSWORD_CHANGED）")
        void passwordChangedAfterLogin() {
            when(users.findById(USER)).thenReturn(Optional.of(user(UserStatus.ACTIVE, null, NOW.minusSeconds(1))));
            assertRefused();
            verify(sessions).revoke(ASID, RevokeReason.PASSWORD_CHANGED);
        }

        @Test
        @DisplayName("登入之前變更的密碼、暫時鎖定：不影響刷新")
        void passwordChangedBeforeLoginOrTemporarilyLocked() {
            when(users.findById(USER)).thenReturn(Optional.of(user(UserStatus.ACTIVE, NOW.plusSeconds(600),
                    NOW.minus(Duration.ofHours(2)))));
            rotates();
            assertThat(detector.authenticate(request(), delegate)).isNotNull();
        }

        @Test
        @DisplayName("刷新成功：記錄舊 token 的雜湊（保留 24 小時），更新 last_seen_at")
        void rememberRotatedToken() {
            rotates();
            detector.authenticate(request(), delegate);
            ArgumentCaptor<RotatedRefreshToken> saved = ArgumentCaptor.forClass(RotatedRefreshToken.class);
            verify(history).save(saved.capture());
            assertThat(saved.getValue()).isEqualTo(new RotatedRefreshToken(RefreshTokenHistoryRepository.hash(TOKEN),
                    "authorization-1", ASID, USER, "client-1", NOW.minus(Duration.ofMinutes(10)), NOW, NOW.plus(RETENTION)));
            verify(sessions).touch(ASID);
        }

        @Test
        @DisplayName("舊 token 比保留期更早到期：紀錄保留到 token 原本的到期時間")
        void historyNeverOutlivesTheToken() {
            when(authorizations.findByToken(TOKEN, OAuth2TokenType.REFRESH_TOKEN)).thenReturn(authorization(NOW.plusSeconds(60)));
            rotates();
            detector.authenticate(request(), delegate);
            ArgumentCaptor<RotatedRefreshToken> saved = ArgumentCaptor.forClass(RotatedRefreshToken.class);
            verify(history).save(saved.capture());
            assertThat(saved.getValue().expiresAt()).isEqualTo(NOW.plusSeconds(60));
        }

        @Test
        @DisplayName("client 設定沿用 Refresh Token（未輪換）：不記錄")
        void notRotated() {
            when(delegate.authenticate(any())).thenReturn(result(TOKEN));
            detector.authenticate(request(), delegate);
            verify(history, never()).save(any());
        }

        @Test
        @DisplayName("Spring 的 provider 拒絕（例如 scope 不符）：原樣拋出，不記錄")
        void delegateRefuses() {
            when(delegate.authenticate(any())).thenThrow(new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE));
            assertThatThrownBy(() -> detector.authenticate(request(), delegate))
                    .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex ->
                            assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));
            verify(history, never()).save(any());
        }

        private void rotates() {
            when(delegate.authenticate(any())).thenReturn(result(NEW_TOKEN));
        }
    }

    @Test
    @DisplayName("install：只替換 Spring 的刷新 provider")
    void installReplacesOnlyTheRefreshProvider() {
        AuthenticationProvider refresh = new OAuth2RefreshTokenAuthenticationProvider(authorizations, context -> null);
        AuthenticationProvider code = new OAuth2AuthorizationCodeAuthenticationProvider(authorizations, context -> null);
        List<AuthenticationProvider> providers = new ArrayList<>(List.of(code, refresh));
        detector.install(providers);
        assertThat(providers.get(0)).isSameAs(code);
        assertThat(providers.get(1)).isInstanceOf(ReuseDetectingRefreshTokenProvider.class);
        assertThat(providers.get(1).supports(OAuth2RefreshTokenAuthenticationToken.class)).isTrue();
    }

    private void assertRefused() {
        assertThatThrownBy(() -> detector.authenticate(request(), delegate))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex ->
                        assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
    }

    private OAuth2RefreshTokenAuthenticationToken request() {
        return new OAuth2RefreshTokenAuthenticationToken(TOKEN, clientPrincipal(), Set.of(), Map.of());
    }

    private OAuth2ClientAuthenticationToken clientPrincipal() {
        return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret");
    }

    private Authentication result(String refreshToken) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access", NOW,
                NOW.plusSeconds(600));
        return new OAuth2AccessTokenAuthenticationToken(client, clientPrincipal(), accessToken,
                new OAuth2RefreshToken(refreshToken, NOW, NOW.plus(Duration.ofDays(14))));
    }

    private OAuth2Authorization authorization(Instant refreshTokenExpiresAt) {
        return OAuth2Authorization.withRegisteredClient(client).id("authorization-1").principalName(USER)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .refreshToken(new OAuth2RefreshToken(TOKEN, NOW.minus(Duration.ofMinutes(10)), refreshTokenExpiresAt))
                .attribute(java.security.Principal.class.getName(),
                        UsernamePasswordAuthenticationToken.authenticated(USER, null, List.of()))
                .build();
    }

    private static AuthSession session(AuthSessionStatus status, Instant expiresAt) {
        return new AuthSession(ASID, USER, status, LoginMethod.PASSWORD, "local", "pwd", NOW.minus(Duration.ofHours(1)),
                NOW, expiresAt, status == AuthSessionStatus.REVOKED ? NOW : null, null, null);
    }

    private static UserAccount user(UserStatus status, Instant lockedUntil, Instant passwordChangedAt) {
        return new UserAccount(USER, "alice", null, false, "{bcrypt}hash", null, null, null, status, lockedUntil,
                passwordChangedAt, null, NOW.minus(Duration.ofDays(1)));
    }
}
