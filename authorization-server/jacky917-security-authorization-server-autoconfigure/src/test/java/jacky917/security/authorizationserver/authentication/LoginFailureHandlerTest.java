package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link LoginFailureHandler} 的單元測試：每個失敗原因一個案例；所有失敗都導向同一個網址。
 */
@DisplayName("LoginFailureHandler")
class LoginFailureHandlerTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final Duration LOCK = Duration.ofMinutes(15);

    private UserAccountService users;
    private ApplicationEventPublisher events;
    private LoginFailureHandler handler;

    @BeforeEach
    void setUp() {
        users = mock(UserAccountService.class);
        events = mock(ApplicationEventPublisher.class);
        handler = new LoginFailureHandler(users, events, 5, LOCK, Clock.fixed(NOW, ZoneOffset.UTC));
        when(users.findByLogin("alice")).thenReturn(Optional.of(new UserAccount("user-1", "alice", null, false,
                "{bcrypt}hash", null, null, null, UserStatus.ACTIVE, null, null, null, NOW)));
    }

    @Test
    @DisplayName("密碼錯誤：計數，未達上限時不鎖定")
    void wrongPassword() throws Exception {
        assertThat(fail("alice", new BadCredentialsException("bad"))).isEqualTo("/login?error");
        verify(users).recordLoginFailure("user-1", NOW, 5, LOCK);
        assertThat(published()).extracting(LoginAuditEvent::failureReason).containsExactly("BAD_CREDENTIALS");
    }

    @Test
    @DisplayName("密碼錯誤且達到上限：另外發布 ACCOUNT_LOCKED")
    void wrongPasswordLocks() throws Exception {
        when(users.recordLoginFailure("user-1", NOW, 5, LOCK)).thenReturn(true);
        fail("alice", new BadCredentialsException("bad"));
        assertThat(published()).extracting(LoginAuditEvent::type)
                .containsExactly(LoginAuditEventType.LOGIN, LoginAuditEventType.ACCOUNT_LOCKED);
    }

    @Test
    @DisplayName("不存在的帳號：UNKNOWN_USER，記錄輸入的帳號，不計數")
    void unknownUser() throws Exception {
        assertThat(fail("ghost", new BadCredentialsException("bad"))).isEqualTo("/login?error");
        verify(users, never()).recordLoginFailure(anyString(), any(), anyInt(), any());
        LoginAuditEvent event = published().get(0);
        assertThat(event.failureReason()).isEqualTo("UNKNOWN_USER");
        assertThat(event.userId()).isNull();
        assertThat(event.usernameAttempted()).isEqualTo("ghost");
    }

    @Test
    @DisplayName("已鎖定、已停用：記錄原因，不計數（不延長鎖定）")
    void lockedOrDisabled() throws Exception {
        assertThat(fail("alice", new LockedException("locked"))).isEqualTo("/login?error");
        assertThat(fail("alice", new DisabledException("disabled"))).isEqualTo("/login?error");
        verify(users, never()).recordLoginFailure(anyString(), any(), anyInt(), any());
        assertThat(published()).extracting(LoginAuditEvent::failureReason).containsExactly("LOCKED", "DISABLED");
    }

    @Test
    @DisplayName("沒有帳號欄位：UNKNOWN_USER")
    void missingUsername() throws Exception {
        fail(null, new BadCredentialsException("bad"));
        assertThat(published()).extracting(LoginAuditEvent::failureReason).containsExactly("UNKNOWN_USER");
    }

    private String fail(String username, AuthenticationException exception) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        if (username != null) {
            request.setParameter("username", username);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, exception);
        return response.getRedirectedUrl();
    }

    private List<LoginAuditEvent> published() {
        ArgumentCaptor<LoginAuditEvent> events = ArgumentCaptor.forClass(LoginAuditEvent.class);
        verify(this.events, atLeastOnce()).publishEvent(events.capture());
        return events.getAllValues();
    }
}
