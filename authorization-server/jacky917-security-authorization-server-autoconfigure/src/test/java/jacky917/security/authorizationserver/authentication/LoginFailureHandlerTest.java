package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditEventType;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import jacky917.security.authorizationserver.user.LockoutPolicy;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link LoginFailureHandler} 的單元測試：每個失敗原因一個案例；只有密碼錯誤計入鎖定；所有失敗都導向同一個網址。
 */
@DisplayName("LoginFailureHandler")
class LoginFailureHandlerTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final LockoutPolicy POLICY = new LockoutPolicy(5, Duration.ofMinutes(15));

    private UserAccountService users;
    private ApplicationEventPublisher events;
    private LoginFailureHandler handler;

    @BeforeEach
    void setUp() {
        users = mock(UserAccountService.class);
        events = mock(ApplicationEventPublisher.class);
        handler = new LoginFailureHandler(users, new AccountLockout(users, events, POLICY), events,
                Clock.fixed(NOW, ZoneOffset.UTC));
        when(users.findByLogin("alice")).thenReturn(Optional.of(user("user-1", "{bcrypt}hash", UserStatus.ACTIVE)));
    }

    @Test
    @DisplayName("密碼錯誤：計數，未達上限時不鎖定")
    void wrongPassword() throws Exception {
        assertThat(fail("alice", new BadCredentialsException("bad"))).isEqualTo("/login?error");
        verify(users).recordLoginFailure("user-1", NOW, POLICY);
        assertThat(published()).extracting(LoginAuditEvent::failureReason)
                .containsExactly(LoginFailureReason.BAD_CREDENTIALS);
    }

    @Test
    @DisplayName("密碼錯誤且達到上限：另外發布 ACCOUNT_LOCKED")
    void wrongPasswordLocks() throws Exception {
        when(users.recordLoginFailure("user-1", NOW, POLICY)).thenReturn(true);
        fail("alice", new BadCredentialsException("bad"));
        assertThat(published()).extracting(LoginAuditEvent::type)
                .containsExactly(LoginAuditEventType.LOGIN, LoginAuditEventType.ACCOUNT_LOCKED);
    }

    @Test
    @DisplayName("不存在的帳號：UNKNOWN_USER，記錄輸入的帳號，不計數")
    void unknownUser() throws Exception {
        assertThat(fail("ghost", new BadCredentialsException("bad"))).isEqualTo("/login?error");
        verify(users, never()).recordLoginFailure(anyString(), any(), any());
        LoginAuditEvent event = published().get(0);
        assertThat(event.failureReason()).isEqualTo(LoginFailureReason.UNKNOWN_USER);
        assertThat(event.userId()).isNull();
        assertThat(event.usernameAttempted()).isEqualTo("ghost");
    }

    @Test
    @DisplayName("已鎖定、已停用、密碼過期：記錄原因，不計數（不延長鎖定）")
    void lockedOrDisabled() throws Exception {
        assertThat(fail("alice", new LockedException("locked"))).isEqualTo("/login?error");
        assertThat(fail("alice", new DisabledException("disabled"))).isEqualTo("/login?error");
        assertThat(fail("alice", new CredentialsExpiredException("expired"))).isEqualTo("/login?error");
        verify(users, never()).recordLoginFailure(anyString(), any(), any());
        assertThat(published()).extracting(LoginAuditEvent::failureReason).containsExactly(LoginFailureReason.LOCKED,
                LoginFailureReason.DISABLED, LoginFailureReason.DISABLED);
    }

    @Test
    @DisplayName("沒有密碼的帳號（只用第三方登入）：NO_PASSWORD，不計數")
    void accountWithoutPassword() throws Exception {
        when(users.findByLogin("fed")).thenReturn(Optional.of(user("user-2", null, UserStatus.ACTIVE)));
        fail("fed", new BadCredentialsException("bad"));
        verify(users, never()).recordLoginFailure(anyString(), any(), any());
        assertThat(published()).extracting(LoginAuditEvent::failureReason)
                .containsExactly(LoginFailureReason.NO_PASSWORD);
    }

    @Test
    @DisplayName("已刪除的帳號：DISABLED，不計數")
    void deletedAccount() throws Exception {
        when(users.findByLogin("gone")).thenReturn(Optional.of(user("user-3", "{bcrypt}hash", UserStatus.DELETED)));
        fail("gone", new BadCredentialsException("bad"));
        verify(users, never()).recordLoginFailure(anyString(), any(), any());
        assertThat(published()).extracting(LoginAuditEvent::failureReason).containsExactly(LoginFailureReason.DISABLED);
    }

    @Test
    @DisplayName("非預期的錯誤（例如資料庫無法使用）：ERROR，不計數，即使帳號存在")
    void unexpectedErrorsAreNotCounted() throws Exception {
        assertThat(fail("alice", new InternalAuthenticationServiceException("database is down")))
                .isEqualTo("/login?error");
        fail("alice", new AuthenticationServiceException("provider failed"));
        verify(users, never()).recordLoginFailure(anyString(), any(), any());
        assertThat(published()).extracting(LoginAuditEvent::failureReason)
                .containsExactly(LoginFailureReason.ERROR, LoginFailureReason.ERROR);
        assertThat(published().get(0).userId()).isEqualTo("user-1");
    }

    @Test
    @DisplayName("查詢帳號時資料庫錯誤：ERROR，不計數，仍導向登入頁")
    void lookupFailure() throws Exception {
        when(users.findByLogin("alice")).thenThrow(new DataAccessResourceFailureException("database is down"));
        assertThat(fail("alice", new BadCredentialsException("bad"))).isEqualTo("/login?error");
        verify(users, never()).recordLoginFailure(anyString(), any(), any());
        assertThat(published()).extracting(LoginAuditEvent::failureReason).containsExactly(LoginFailureReason.ERROR);
    }

    @Test
    @DisplayName("沒有帳號欄位：UNKNOWN_USER")
    void missingUsername() throws Exception {
        fail(null, new BadCredentialsException("bad"));
        assertThat(published()).extracting(LoginAuditEvent::failureReason)
                .containsExactly(LoginFailureReason.UNKNOWN_USER);
    }

    private static UserAccount user(String id, String passwordHash, UserStatus status) {
        return new UserAccount(id, "alice", null, false, passwordHash, null, null, null, status, null, null, null, NOW, false);
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
