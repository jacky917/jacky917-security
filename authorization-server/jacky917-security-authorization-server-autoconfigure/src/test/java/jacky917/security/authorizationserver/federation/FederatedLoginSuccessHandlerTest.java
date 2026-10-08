package jacky917.security.authorizationserver.federation;

import jacky917.security.authorizationserver.authentication.PrincipalNormalizer;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.user.UserAccountService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.time.Clock;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link FederatedLoginSuccessHandler} 的失敗路徑：任何無法處理的第三方登入都回到登入頁並登出，
 * 不建立登入 Session，提供者的 token 一律移除。
 */
@DisplayName("FederatedLoginSuccessHandler 的失敗路徑")
class FederatedLoginSuccessHandlerTest {

    private FederatedIdentityService identities;
    private AuthSessionService sessions;
    private OAuth2AuthorizedClientRepository authorizedClients;
    private final OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
            new DefaultOAuth2User(AuthorityUtils.createAuthorityList("OAUTH2_USER"), Map.of("id", "1"), "id"),
            AuthorityUtils.createAuthorityList("OAUTH2_USER"), "github");

    @BeforeEach
    void setUp() {
        identities = mock(FederatedIdentityService.class);
        sessions = mock(AuthSessionService.class);
        authorizedClients = mock(OAuth2AuthorizedClientRepository.class);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("沒有支援此提供者的 mapper：/login?error=federation（不是錯誤頁）")
    void noMapper() throws Exception {
        MockHttpServletResponse response = handle(List.of());
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=federation");
        assertLoggedOutWithoutSession();
    }

    @Test
    @DisplayName("Email 屬於既有帳號：/login?error=account_exists")
    void accountExists() throws Exception {
        when(identities.login(any())).thenThrow(new FederatedLoginRejectedException(
                FederatedLoginRejectedException.Reason.ACCOUNT_EXISTS, "exists"));
        assertThat(handle(List.of(new AcceptingMapper())).getRedirectedUrl()).isEqualTo("/login?error=account_exists");
        assertLoggedOutWithoutSession();
    }

    @Test
    @DisplayName("使用者無法登入：/login?error=federation")
    void userCannotLogIn() throws Exception {
        when(identities.login(any())).thenThrow(new FederatedLoginRejectedException(
                FederatedLoginRejectedException.Reason.USER_CANNOT_LOG_IN, "disabled"));
        assertThat(handle(List.of(new AcceptingMapper())).getRedirectedUrl()).isEqualTo("/login?error=federation");
        assertLoggedOutWithoutSession();
    }

    private MockHttpServletResponse handle(List<FederatedUserInfoMapper> mappers) throws Exception {
        FederatedLoginSuccessHandler handler = new FederatedLoginSuccessHandler(mappers, identities,
                mock(UserAccountService.class), sessions, mock(PrincipalNormalizer.class), authorizedClients,
                Clock.systemUTC());
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authentication);
        return response;
    }

    private void assertLoggedOutWithoutSession() {
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(sessions);
        verify(authorizedClients).removeAuthorizedClient(eq("github"), eq(authentication), any(), any());
    }

    private static final class AcceptingMapper implements FederatedUserInfoMapper {
        @Override
        public boolean supports(String registrationId) {
            return true;
        }

        @Override
        public FederatedUserInfo map(String registrationId, org.springframework.security.oauth2.core.user.OAuth2User user,
                                     org.springframework.security.oauth2.core.OAuth2AccessToken accessToken) {
            return new FederatedUserInfo(registrationId, "1", null, false, null, null, null, Map.of());
        }
    }
}
