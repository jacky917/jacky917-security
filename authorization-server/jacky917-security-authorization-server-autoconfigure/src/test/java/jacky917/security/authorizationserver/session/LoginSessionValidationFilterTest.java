package jacky917.security.authorizationserver.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link LoginSessionValidationFilter} 的單元測試：只有在登入 Session 仍可使用時才保留瀏覽器登入。
 */
@DisplayName("LoginSessionValidationFilter")
class LoginSessionValidationFilterTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private AuthSessionService sessions;
    private LoginSessionValidationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpSession httpSession;
    private MockFilterChain chain;

    @BeforeEach
    void setUp() {
        sessions = mock(AuthSessionService.class);
        filter = new LoginSessionValidationFilter(sessions, Clock.fixed(NOW, ZoneOffset.UTC));
        httpSession = new MockHttpSession();
        httpSession.setAttribute(AuthSessionService.SESSION_ATTRIBUTE, "session-1");
        request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setSession(httpSession);
        chain = new MockFilterChain();
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "user-1", null, AuthorityUtils.createAuthorityList("ROLE_USER")));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("登入 Session 有效：不影響請求")
    void activeSessionPasses() throws Exception {
        when(sessions.find("session-1")).thenReturn(Optional.of(session("user-1", AuthSessionStatus.ACTIVE, NOW.plusSeconds(60))));
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertKeptLogin();
    }

    @Test
    @DisplayName("已撤銷、已過期、屬於其他使用者、不存在：結束瀏覽器登入")
    void unusableSessionEndsTheLogin() throws Exception {
        for (Optional<AuthSession> found : java.util.List.of(
                Optional.of(session("user-1", AuthSessionStatus.REVOKED, NOW.plusSeconds(60))),
                Optional.of(session("user-1", AuthSessionStatus.ACTIVE, NOW)),
                Optional.of(session("user-2", AuthSessionStatus.ACTIVE, NOW.plusSeconds(60))),
                Optional.<AuthSession>empty())) {
            setUp();
            when(sessions.find("session-1")).thenReturn(found);
            filter.doFilter(request, new MockHttpServletResponse(), chain);
            assertEndedLogin();
        }
    }

    @Test
    @DisplayName("已登入但瀏覽器 Session 沒有 asid：結束瀏覽器登入")
    void missingAsidEndsTheLogin() throws Exception {
        httpSession.removeAttribute(AuthSessionService.SESSION_ATTRIBUTE);
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertEndedLogin();
    }

    @Test
    @DisplayName("匿名使用者或沒有瀏覽器 Session（例如 token 端點）：不查詢、不影響")
    void anonymousAndSessionlessRequestsAreIgnored() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertThat(httpSession.isInvalid()).isFalse();

        setUp();
        MockHttpServletRequest tokenRequest = new MockHttpServletRequest("POST", "/oauth2/token");
        filter.doFilter(tokenRequest, new MockHttpServletResponse(), new MockFilterChain());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verifyNoInteractions(sessions);
    }

    private void assertKeptLogin() {
        assertThat(httpSession.isInvalid()).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(chain.getRequest()).as("請求繼續往下傳").isNotNull();
    }

    private void assertEndedLogin() {
        assertThat(httpSession.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).as("請求繼續往下傳，由後續的授權檢查導向登入頁").isNotNull();
    }

    private static AuthSession session(String userId, AuthSessionStatus status, Instant expiresAt) {
        return new AuthSession("session-1", userId, status, LoginMethod.PASSWORD, "local", "pwd",
                NOW.minus(Duration.ofHours(1)), NOW, expiresAt, status == AuthSessionStatus.REVOKED ? NOW : null, null, null);
    }
}
