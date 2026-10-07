package jacky917.security.authorizationserver.token;

import jacky917.security.authorizationserver.client.ClientProfile;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.client.ClientStatus;
import jacky917.security.authorizationserver.session.AuthSession;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.AuthSessionStatus;
import jacky917.security.authorizationserver.session.LoginMethod;
import jacky917.security.authorizationserver.session.SessionAuthorizationRepository;
import jacky917.security.authorizationserver.user.UserAccount;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.user.UserStatus;
import jacky917.security.core.TrustLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@link Jacky917TokenCustomizer} 的單元測試：以真正的 {@link JwtEncodingContext} 執行，相依元件以 Mockito 替換，
 * 時間固定，每個分支各一個案例。
 */
@DisplayName("Jacky917TokenCustomizer")
class Jacky917TokenCustomizerTest {

    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final String USER = "user-1";
    private static final String ASID = "session-1";

    private final RegisteredClient client = RegisteredClient.withId("client-1").clientId("web-bff")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://app.example.com/callback").scope("openid").build();
    private final OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client).id("authorization-1")
            .principalName(USER).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).build();

    private AuthorityResolver authorities;
    private ClientProfileRepository profiles;
    private SessionAuthorizationRepository links;
    private AuthSessionService sessions;
    private UserAccountService users;
    private final List<TokenClaimsContributor> contributors = new ArrayList<>();

    @BeforeEach
    void setUp() {
        authorities = mock(AuthorityResolver.class);
        profiles = mock(ClientProfileRepository.class);
        links = mock(SessionAuthorizationRepository.class);
        sessions = mock(AuthSessionService.class);
        users = mock(UserAccountService.class);
        when(profiles.find("client-1")).thenReturn(Optional.of(
                new ClientProfile("client-1", TrustLevel.FIRST_PARTY, "BFF", ClientStatus.ACTIVE)));
        when(links.findSessionId("authorization-1")).thenReturn(Optional.of(ASID));
        when(sessions.find(ASID)).thenReturn(Optional.of(session(AuthSessionStatus.ACTIVE, NOW.plus(Duration.ofDays(1)))));
        when(users.findById(USER)).thenReturn(Optional.of(user(UserStatus.ACTIVE, null, true)));
        when(authorities.resolve(eq(USER), any(), any(), any()))
                .thenReturn(new ResolvedAuthorities(Set.of("USER", "ADMIN"), Set.of("order:read")));
    }

    @Nested
    @DisplayName("Access Token")
    class AccessTokens {

        @Test
        @SuppressWarnings("unchecked")
        @DisplayName("第一方：aud、client_id、asid、idp、roles、permissions")
        void firstParty() {
            Map<String, Object> claims = customize(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE);
            assertThat(claims).containsEntry("aud", List.of("jacky917-api")).containsEntry("client_id", "web-bff")
                    .containsEntry("asid", ASID).containsEntry("idp", "local");
            assertThat((List<Object>) claims.get("roles")).containsExactlyInAnyOrder("USER", "ADMIN");
            assertThat(claims.get("permissions")).isEqualTo(List.of("order:read"));
        }

        @Test
        @DisplayName("第三方：沒有 roles；沒有 client_profile 的 client 視為第三方")
        void thirdPartyAndUnknownClientsGetNoRoles() {
            when(profiles.find("client-1")).thenReturn(Optional.empty());
            Map<String, Object> claims = customize(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE);
            assertThat(claims).doesNotContainKey("roles").containsKey("permissions");
        }

        @Test
        @DisplayName("client_credentials：只有 aud 與 client_id，不查使用者與 Session")
        void clientCredentials() {
            Map<String, Object> claims = customize(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.CLIENT_CREDENTIALS);
            assertThat(claims).containsEntry("client_id", "web-bff").doesNotContainKeys("asid", "idp", "roles", "permissions");
            verifyNoInteractions(users, sessions, authorities);
        }
    }

    @Nested
    @DisplayName("ID Token")
    class IdTokens {

        @Test
        @DisplayName("amr、profile 與已驗證的 email；沒有角色、權限、asid")
        void claims() {
            Map<String, Object> claims = customizeIdToken(Set.of("openid", "profile", "email"));
            assertThat(claims).containsEntry("amr", List.of("pwd")).containsEntry("name", "Alice")
                    .containsEntry("email", "alice@example.com").containsEntry("email_verified", true)
                    .doesNotContainKeys("roles", "permissions", "asid", "aud");
        }

        @Test
        @DisplayName("Email 未驗證或沒有 email scope 時不放 email")
        void emailOnlyWhenVerifiedAndRequested() {
            assertThat(customizeIdToken(Set.of("openid", "profile"))).doesNotContainKey("email");
            when(users.findById(USER)).thenReturn(Optional.of(user(UserStatus.ACTIVE, null, false)));
            assertThat(customizeIdToken(Set.of("openid", "email"))).doesNotContainKeys("email", "email_verified");
        }
    }

    @Nested
    @DisplayName("拒絕簽發（invalid_grant）")
    class Refusals {

        @Test
        @DisplayName("使用者已停用")
        void disabledUser() {
            when(users.findById(USER)).thenReturn(Optional.of(user(UserStatus.DISABLED, null, true)));
            assertRefused();
        }

        @Test
        @DisplayName("使用者被暫時鎖定")
        void temporarilyLockedUser() {
            when(users.findById(USER)).thenReturn(Optional.of(user(UserStatus.ACTIVE, NOW.plusSeconds(60), true)));
            assertRefused();
        }

        @Test
        @DisplayName("登入 Session 已撤銷、已過期、或授權沒有連結")
        void unusableSession() {
            when(sessions.find(ASID)).thenReturn(Optional.of(session(AuthSessionStatus.REVOKED, NOW.plusSeconds(60))));
            assertRefused();
            when(sessions.find(ASID)).thenReturn(Optional.of(session(AuthSessionStatus.ACTIVE, NOW)));
            assertRefused();
            when(links.findSessionId("authorization-1")).thenReturn(Optional.empty());
            assertRefused();
        }

        private void assertRefused() {
            assertThatThrownBy(() -> customize(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.REFRESH_TOKEN))
                    .isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex ->
                            assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
        }
    }

    @Test
    @DisplayName("TokenClaimsContributor 加入的不可變集合（含巢狀）轉為 ArrayList／LinkedHashMap，刷新時才能讀回")
    void contributedCollectionsAreMadeSerializable() {
        contributors.add((context, user) -> {
            context.getClaims().claim("tenants", Set.of("a"));
            context.getClaims().claim("profile", Map.of("tags", List.of("x"), "level", 3));
        });
        Map<String, Object> claims = customize(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(claims.get("tenants")).isExactlyInstanceOf(ArrayList.class).isEqualTo(List.of("a"));
        assertThat(claims.get("profile")).isExactlyInstanceOf(LinkedHashMap.class);
        assertThat(((Map<?, ?>) claims.get("profile")).get("tags")).isExactlyInstanceOf(ArrayList.class);
        assertThat(claims.get("roles")).isExactlyInstanceOf(ArrayList.class);
    }

    private Map<String, Object> customize(OAuth2TokenType type, AuthorizationGrantType grantType) {
        return customize(type, grantType, Set.of("openid"));
    }

    private Map<String, Object> customizeIdToken(Set<String> scopes) {
        return customize(new OAuth2TokenType(OidcParameterNames.ID_TOKEN), AuthorizationGrantType.AUTHORIZATION_CODE, scopes);
    }

    private Map<String, Object> customize(OAuth2TokenType type, AuthorizationGrantType grantType, Set<String> scopes) {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder().subject(USER);
        JwtEncodingContext context = JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256), claims)
                .registeredClient(client)
                .principal(new TestingAuthenticationToken(USER, null, "ROLE_USER"))
                .authorization(authorization)
                .authorizedScopes(scopes)
                .tokenType(type)
                .authorizationGrantType(grantType)
                .build();
        new Jacky917TokenCustomizer(new ConfiguredAudienceResolver(List.of("jacky917-api")), authorities, profiles, links,
                sessions, users, contributors, Clock.fixed(NOW, ZoneOffset.UTC)).customize(context);
        return claims.build().getClaims();
    }

    private static AuthSession session(AuthSessionStatus status, Instant expiresAt) {
        return new AuthSession(ASID, USER, status, LoginMethod.PASSWORD, "local", "pwd", NOW.minus(Duration.ofHours(1)),
                NOW, expiresAt, status == AuthSessionStatus.REVOKED ? NOW : null);
    }

    private static UserAccount user(UserStatus status, Instant lockedUntil, boolean emailVerified) {
        return new UserAccount(USER, "alice", "alice@example.com", emailVerified, null, "Alice", null, null, status,
                lockedUntil, null, null, NOW.minus(Duration.ofDays(1)));
    }
}
