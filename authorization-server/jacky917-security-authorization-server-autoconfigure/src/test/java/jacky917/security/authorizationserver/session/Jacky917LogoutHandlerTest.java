package jacky917.security.authorizationserver.session;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link Jacky917LogoutHandler} 的單元測試：從瀏覽器與 id_token_hint 找出登入 Session 並撤銷（詳細設計 §5.5）。
 */
@DisplayName("Jacky917LogoutHandler")
class Jacky917LogoutHandlerTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private final RegisteredClient client = RegisteredClient.withId("client-1").clientId("web-bff")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://app.example.com/callback").build();
    private final OidcIdToken idToken = new OidcIdToken("id-token", NOW, NOW.plusSeconds(1800), java.util.Map.of("sub", "user-1"));

    private AuthSessionService sessions;
    private OAuth2AuthorizationService authorizations;
    private SessionAuthorizationRepository links;
    private ApplicationEventPublisher events;
    private Jacky917LogoutHandler handler;
    private MockHttpServletRequest request;
    private MockHttpSession browser;

    @BeforeEach
    void setUp() {
        sessions = mock(AuthSessionService.class);
        authorizations = mock(OAuth2AuthorizationService.class);
        links = mock(SessionAuthorizationRepository.class);
        events = mock(ApplicationEventPublisher.class);
        handler = new Jacky917LogoutHandler(sessions, authorizations, links, events, Clock.fixed(NOW, ZoneOffset.UTC));
        browser = new MockHttpSession();
        browser.setAttribute(AuthSessionService.SESSION_ATTRIBUTE, "browser-session");
        request = new MockHttpServletRequest();
        request.setSession(browser);
        when(sessions.find("browser-session")).thenReturn(Optional.of(session("browser-session", "user-1")));
        when(sessions.find("token-session")).thenReturn(Optional.of(session("token-session", "user-1")));
        when(sessions.revoke(anyString(), any())).thenReturn(true);
    }

    @Test
    @DisplayName("登入服務自己的登出：撤銷瀏覽器的 Session、結束瀏覽器登入、發布 LOGOUT")
    void browserLogout() {
        handler.logout(request, new MockHttpServletResponse(), user("user-1"));
        verify(sessions).revoke("browser-session", RevokeReason.LOGOUT);
        assertThat(browser.isInvalid()).isTrue();
        ArgumentCaptor<LoginAuditEvent> event = ArgumentCaptor.forClass(LoginAuditEvent.class);
        verify(events).publishEvent(event.capture());
        assertThat(event.getValue().type()).isEqualTo(LoginAuditEventType.LOGOUT);
        assertThat(event.getValue().userId()).isEqualTo("user-1");
        assertThat(event.getValue().sessionId()).isEqualTo("browser-session");
    }

    @Test
    @DisplayName("瀏覽器的 Session 屬於其他使用者、或瀏覽器未登入：不撤銷")
    void browserSessionOfAnotherUserIsKept() {
        handler.logout(request, new MockHttpServletResponse(), user("user-2"));
        handler.logout(request, new MockHttpServletResponse(),
                new AnonymousAuthenticationToken("key", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        verify(sessions, never()).revoke(anyString(), any());
    }

    @Test
    @DisplayName("RP-Initiated Logout：撤銷 id_token_hint 所屬的 Session（記錄 client），以及瀏覽器的 Session")
    void rpInitiatedLogout() {
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client).id("authorization-1")
                .principalName("user-1").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).build();
        when(authorizations.findByToken(any(), any())).thenReturn(authorization);
        when(links.findSessionId("authorization-1")).thenReturn(Optional.of("token-session"));
        handler.logout(request, new MockHttpServletResponse(), logout(user("user-1")));
        verify(sessions).revoke("browser-session", RevokeReason.LOGOUT);
        verify(sessions).revoke("token-session", RevokeReason.LOGOUT);
        ArgumentCaptor<LoginAuditEvent> event = ArgumentCaptor.forClass(LoginAuditEvent.class);
        verify(events, org.mockito.Mockito.times(2)).publishEvent(event.capture());
        assertThat(event.getAllValues()).extracting(LoginAuditEvent::registeredClientId).containsExactly(null, "client-1");
    }

    @Test
    @DisplayName("RP-Initiated Logout，瀏覽器未登入、授權已不存在：只結束瀏覽器 Session")
    void unknownIdToken() {
        handler.logout(request, new MockHttpServletResponse(), logout(
                new AnonymousAuthenticationToken("key", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))));
        verify(sessions, never()).revoke(anyString(), any());
        assertThat(browser.isInvalid()).isTrue();
    }

    @Test
    @DisplayName("Session 已不是有效狀態：不發布事件")
    void alreadyRevoked() {
        when(sessions.revoke(anyString(), any())).thenReturn(false);
        assertThat(handler.end("browser-session", RevokeReason.LOGOUT, null, request)).isFalse();
        verify(events, never()).publishEvent(any(Object.class));
    }

    private OidcLogoutAuthenticationToken logout(Authentication principal) {
        return new OidcLogoutAuthenticationToken(idToken, principal, "http-session", "web-bff",
                "https://app.example.com/logged-out", null);
    }

    private static Authentication user(String userId) {
        return UsernamePasswordAuthenticationToken.authenticated(userId, null, AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    private static AuthSession session(String sessionId, String userId) {
        return new AuthSession(sessionId, userId, AuthSessionStatus.ACTIVE, LoginMethod.PASSWORD, "local", "pwd",
                NOW.minus(Duration.ofHours(1)), NOW, NOW.plus(Duration.ofDays(1)), null, "127.0.0.1", "test");
    }
}
