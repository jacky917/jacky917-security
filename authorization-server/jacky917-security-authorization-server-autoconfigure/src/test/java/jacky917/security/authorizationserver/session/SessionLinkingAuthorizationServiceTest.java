package jacky917.security.authorizationserver.session;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link SessionLinkingAuthorizationService} 的單元測試：何時建立連結、何時拒絕，以及拒絕時交易回滾。
 */
@DisplayName("SessionLinkingAuthorizationService")
class SessionLinkingAuthorizationServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");

    private final RegisteredClient client = RegisteredClient.withId("client-1").clientId("web-bff")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("https://app.example.com/callback").build();

    private OAuth2AuthorizationService delegate;
    private SessionAuthorizationRepository links;
    private PlatformTransactionManager transactionManager;
    private SessionLinkingAuthorizationService service;

    @BeforeEach
    void setUp() {
        delegate = mock(OAuth2AuthorizationService.class);
        links = mock(SessionAuthorizationRepository.class);
        transactionManager = mock(PlatformTransactionManager.class);
        when(transactionManager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        service = new SessionLinkingAuthorizationService(delegate, links, new TransactionTemplate(transactionManager),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("第一次儲存：以瀏覽器 Session 中的 asid 建立連結")
    void firstSaveLinksTheBrowserSession() {
        browserWithAsid("session-1");
        when(links.findSessionId("authorization-1")).thenReturn(Optional.empty());
        when(links.link("authorization-1", "session-1", "user-1", "client-1", NOW)).thenReturn(true);

        service.save(authorization(AuthorizationGrantType.AUTHORIZATION_CODE));

        verify(delegate).save(any());
        verify(links).link("authorization-1", "session-1", "user-1", "client-1", NOW);
        verify(transactionManager).commit(any(TransactionStatus.class));
    }

    @Test
    @DisplayName("已有連結（換 Token、刷新）：不需要瀏覽器 Session")
    void laterSavesReuseTheLink() {
        when(links.findSessionId("authorization-1")).thenReturn(Optional.of("session-1"));
        service.save(authorization(AuthorizationGrantType.AUTHORIZATION_CODE));
        verify(links, never()).link(anyString(), anyString(), anyString(), anyString(), any());
    }

    @Test
    @DisplayName("client_credentials：不建立連結")
    void clientCredentialsAreNotLinked() {
        service.save(authorization(AuthorizationGrantType.CLIENT_CREDENTIALS));
        verify(links, never()).findSessionId(anyString());
    }

    @Test
    @DisplayName("沒有請求、沒有瀏覽器 Session 或沒有 asid：拒絕並回滾")
    void missingLoginSessionIsRejected() {
        when(links.findSessionId("authorization-1")).thenReturn(Optional.empty());
        assertRejectedAndRolledBack();

        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        assertRejectedAndRolledBack();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        assertRejectedAndRolledBack();
    }

    @Test
    @DisplayName("asid 不是同一位使用者的有效 Session（link 回傳 false）：拒絕並回滾")
    void inactiveOrForeignSessionIsRejected() {
        browserWithAsid("session-of-someone-else");
        when(links.findSessionId("authorization-1")).thenReturn(Optional.empty());
        when(links.link(anyString(), anyString(), anyString(), anyString(), any())).thenReturn(false);
        assertRejectedAndRolledBack();
    }

    private void assertRejectedAndRolledBack() {
        org.mockito.Mockito.clearInvocations(transactionManager);
        assertThatThrownBy(() -> service.save(authorization(AuthorizationGrantType.AUTHORIZATION_CODE)))
                .isInstanceOf(IllegalStateException.class);
        verify(transactionManager).rollback(any(TransactionStatus.class));
        verify(transactionManager, never()).commit(any(TransactionStatus.class));
    }

    private void browserWithAsid(String asid) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute(AuthSessionService.SESSION_ATTRIBUTE, asid);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private OAuth2Authorization authorization(AuthorizationGrantType grantType) {
        return OAuth2Authorization.withRegisteredClient(client).id("authorization-1").principalName("user-1")
                .authorizationGrantType(grantType).build();
    }
}
