package jacky917.security.authorizationserver.authentication;

import jacky917.security.authorizationserver.audit.LoginAuditEvent;
import jacky917.security.authorizationserver.audit.LoginAuditRepository;
import jacky917.security.authorizationserver.audit.LoginFailureReason;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link LoginAttemptGuard} 的單元測試：只檢查兩個密碼表單（POST /login 與 POST /jacky917/link-account），
 * 以解碼後的路徑比對；最近一分鐘的失敗次數達上限時拒絕。
 */
@DisplayName("LoginAttemptGuard")
class LoginAttemptGuardTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private LoginAuditRepository audits;
    private ApplicationEventPublisher events;
    private LoginAttemptGuard guard;

    @BeforeEach
    void setUp() {
        audits = mock(LoginAuditRepository.class);
        events = mock(ApplicationEventPublisher.class);
        guard = new LoginAttemptGuard(audits, events, 3, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("未達上限：繼續處理登入")
    void belowTheLimit() throws Exception {
        when(audits.countFailedLogins("10.0.0.1", NOW.minusSeconds(60))).thenReturn(2);
        MockFilterChain chain = new MockFilterChain();
        guard.doFilter(login("10.0.0.1"), new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest()).isNotNull();
        verify(events, never()).publishEvent(any(Object.class));
    }

    @Test
    @DisplayName("達到上限：導向 /login?error=rate_limited，記錄 RATE_LIMITED，不檢查密碼")
    void atTheLimit() throws Exception {
        when(audits.countFailedLogins("10.0.0.1", NOW.minusSeconds(60))).thenReturn(3);
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        guard.doFilter(login("10.0.0.1"), response, chain);
        assertThat(chain.getRequest()).as("不交給下一個 filter").isNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=rate_limited");
        ArgumentCaptor<LoginAuditEvent> event = ArgumentCaptor.forClass(LoginAuditEvent.class);
        verify(events).publishEvent(event.capture());
        assertThat(event.getValue().success()).isFalse();
        assertThat(event.getValue().failureReason()).isEqualTo(LoginFailureReason.RATE_LIMITED);
        assertThat(event.getValue().usernameAttempted()).isEqualTo("alice");
        assertThat(event.getValue().ipAddress()).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("GET /login 與其他路徑：不檢查")
    void otherRequestsPass() throws Exception {
        for (MockHttpServletRequest request : new MockHttpServletRequest[]{
                new MockHttpServletRequest("GET", "/login"), new MockHttpServletRequest("POST", "/logout")}) {
            MockFilterChain chain = new MockFilterChain();
            guard.doFilter(request, new MockHttpServletResponse(), chain);
            assertThat(chain.getRequest()).isNotNull();
        }
        verify(audits, never()).countFailedLogins(anyString(), any());
        verifyNoInteractions(events);
    }

    @Test
    @DisplayName("帳號連結確認頁也是密碼表單：達到上限時同樣拒絕")
    void linkAccountFormIsGuarded() throws Exception {
        when(audits.countFailedLogins("10.0.0.1", NOW.minusSeconds(60))).thenReturn(3);
        MockHttpServletRequest request = post("/jacky917/link-account", "10.0.0.1");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        guard.doFilter(request, response, chain);
        assertThat(chain.getRequest()).isNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=rate_limited");
    }

    @Test
    @DisplayName("編碼過的路徑（/%6Cogin = /login）不能略過檢查")
    void encodedPathIsGuarded() throws Exception {
        when(audits.countFailedLogins("10.0.0.1", NOW.minusSeconds(60))).thenReturn(3);
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        guard.doFilter(post("/%6Cogin", "10.0.0.1"), response, chain);
        assertThat(chain.getRequest()).as("不交給下一個 filter").isNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=rate_limited");
    }

    @Test
    @DisplayName("部署在 context path 之下：比對 context path 之後的路徑，重導也帶 context path")
    void contextPath() throws Exception {
        when(audits.countFailedLogins("10.0.0.1", NOW.minusSeconds(60))).thenReturn(3);
        MockHttpServletRequest request = post("/auth/login", "10.0.0.1");
        request.setContextPath("/auth");
        MockHttpServletResponse response = new MockHttpServletResponse();
        guard.doFilter(request, response, new MockFilterChain());
        assertThat(response.getRedirectedUrl()).isEqualTo("/auth/login?error=rate_limited");
    }

    private static MockHttpServletRequest login(String ip) {
        return post("/login", ip);
    }

    private static MockHttpServletRequest post(String uri, String ip) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", uri);
        request.setRemoteAddr(ip);
        request.setParameter("username", "alice");
        return request;
    }
}
