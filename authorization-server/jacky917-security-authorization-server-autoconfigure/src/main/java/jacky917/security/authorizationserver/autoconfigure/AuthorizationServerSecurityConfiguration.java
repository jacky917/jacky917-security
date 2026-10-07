package jacky917.security.authorizationserver.autoconfigure;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jacky917.security.authorizationserver.authentication.LoginSuccessHandler;
import jacky917.security.authorizationserver.authentication.PrincipalNormalizer;
import jacky917.security.authorizationserver.federation.FederatedIdentityService;
import jacky917.security.authorizationserver.federation.FederatedLoginSuccessHandler;
import jacky917.security.authorizationserver.federation.FederatedUserInfoMapper;
import jacky917.security.authorizationserver.federation.OidcFederatedUserInfoMapper;
import jacky917.security.authorizationserver.client.ClientProfileRepository;
import jacky917.security.authorizationserver.token.AudienceResolver;
import jacky917.security.authorizationserver.token.AuthorityResolver;
import jacky917.security.authorizationserver.token.ConfiguredAudienceResolver;
import jacky917.security.authorizationserver.token.DefaultAuthorityResolver;
import jacky917.security.authorizationserver.token.Jacky917TokenCustomizer;
import jacky917.security.authorizationserver.token.TokenClaimsContributor;
import jacky917.security.authorizationserver.properties.AuthorizationServerProperties;
import jacky917.security.authorizationserver.session.AuthSessionService;
import jacky917.security.authorizationserver.session.SessionAuthorizationRepository;
import jacky917.security.authorizationserver.session.SessionLinkingAuthorizationService;
import jacky917.security.authorizationserver.user.UserAccountService;
import jacky917.security.authorizationserver.web.LoginController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;

/**
 * Web security of the authorization server (detailed design §3): the
 * OAuth 2.0 / OIDC endpoints and the login pages.
 * <p>
 * Authorization Server 的 Web 安全設定（詳細設計 §3）：OAuth 2.0／OIDC 端點與
 * 登入頁。
 * <ul>
 *   <li>Order 1 handles only Spring Authorization Server's endpoints
 *       ({@code /oauth2/**}, {@code /.well-known/**}, {@code /userinfo},
 *       {@code /connect/**}); a browser without a login is sent to
 *       {@code /login}.
 *       <br>Order 1 只處理 Spring Authorization Server 的端點；未登入的瀏覽器
 *       會被導向 {@code /login}。</li>
 *   <li>Order 3 handles everything else: the login form with CSRF
 *       protection, a new session id after login, and headers that forbid
 *       framing.
 *       <br>Order 3 處理其餘請求：有 CSRF 保護的登入表單、登入後更換 Session
 *       ID，以及禁止被嵌入 iframe 的標頭。</li>
 * </ul>
 * Each chain backs off when the application defines a bean with the same
 * name.
 * <p>
 * 應用程式定義同名的 bean 時，對應的 filter chain 不會建立。
 *
 * @author Jacky
 * @since 2.1.0
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
class AuthorizationServerSecurityConfiguration {

    private static final String CONTENT_SECURITY_POLICY =
            "default-src 'self'; img-src 'self' https: data:; frame-ancestors 'none'; form-action 'self'";

    @Bean
    @Order(1)
    @ConditionalOnMissingBean(name = "authorizationServerSecurityFilterChain")
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 已查證：Spring Security 7.1.1 的 OAuth2AuthorizationServerConfigurer 只有公開建構子
        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        http.securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, server -> server.oidc(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // /userinfo 以 Access Token 存取
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    @Bean
    @Order(3)
    @ConditionalOnMissingBean(name = "loginSecurityFilterChain")
    SecurityFilterChain loginSecurityFilterChain(HttpSecurity http, LoginSuccessHandler loginSuccessHandler,
                                                 ObjectProvider<ClientRegistrationRepository> clientRegistrations,
                                                 ObjectProvider<FederatedLoginSuccessHandler> federatedLoginSuccessHandler)
            throws Exception {
        // 有設定第三方登入（spring.security.oauth2.client.registration.*）時才啟用
        if (clientRegistrations.getIfAvailable() != null) {
            http.oauth2Login(oauth2 -> oauth2
                    .loginPage("/login")
                    .successHandler(federatedLoginSuccessHandler.getObject())
                    .failureUrl("/login?error=federation"));
        }
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/error", "/jacky917/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(loginSuccessHandler)
                        // 所有失敗原因導向同一個網址，頁面顯示相同的訊息（詳細設計 §7.2）
                        .failureUrl("/login?error"))
                .sessionManagement(session -> session.sessionFixation(fixation -> fixation.changeSessionId()))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentSecurityPolicy(csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY)));
        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean
    AuthorizationServerSettings authorizationServerSettings(AuthorizationServerProperties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.getIssuer().toString()).build();
    }

    /**
     * The official JDBC authorization service, linking each new
     * authorization to its login session (detailed design §5.2).
     * <p>
     * 官方 JDBC 授權服務，並把每一個新授權連結到其登入 Session（詳細設計 §5.2）。
     *
     * @param jdbcOperations      the JDBC operations of the authorization server database
     *                            <br>Authorization Server 資料庫的 JDBC operations
     * @param clients             the client repository
     *                            <br>client repository
     * @param links               the authorization links
     *                            <br>授權連結
     * @param transactionManager  saves an authorization and its link together
     *                            <br>在同一個交易中儲存授權與連結
     * @param clock               the clock for timestamps
     *                            <br>用於時間戳記的時鐘
     * @return the authorization service
     *         <br>授權服務
     */
    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository clients,
                                                    SessionAuthorizationRepository links,
                                                    PlatformTransactionManager transactionManager, Clock clock) {
        return new SessionLinkingAuthorizationService(new JdbcOAuth2AuthorizationService(jdbcOperations, clients), links,
                new TransactionTemplate(transactionManager), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    SessionAuthorizationRepository sessionAuthorizationRepository(JdbcClient jdbcClient) {
        return new SessionAuthorizationRepository(jdbcClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
                                                                  RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, clients);
    }

    /**
     * Validates access tokens at {@code /userinfo} with the published keys.
     * <p>
     * 以公開的金鑰驗證 {@code /userinfo} 收到的 Access Token。
     *
     * @param jwkSource  the published keys
     *                   <br>公開的金鑰
     * @return the decoder
     *         <br>decoder
     */
    @Bean
    @ConditionalOnMissingBean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    AuthSessionService authSessionService(JdbcClient jdbcClient, AuthorizationServerProperties properties, Clock clock) {
        return new AuthSessionService(jdbcClient, properties.getToken().getSessionMaxAge(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    AudienceResolver audienceResolver(AuthorizationServerProperties properties) {
        return new ConfiguredAudienceResolver(properties.getToken().getAudience());
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    AuthorityResolver authorityResolver(UserAccountService users, JdbcClient jdbcClient, Clock clock) {
        return new DefaultAuthorityResolver(users, jdbcClient, clock);
    }

    /**
     * Adds the jacky917 claims to access tokens and ID tokens.
     * <p>
     * 在 Access Token 與 ID Token 中加入 jacky917 的 claim。
     *
     * @return the token customizer
     *         <br>token customizer
     */
    @Bean
    @ConditionalOnMissingBean
    OAuth2TokenCustomizer<JwtEncodingContext> jacky917TokenCustomizer(
            AudienceResolver audienceResolver, AuthorityResolver authorityResolver,
            ClientProfileRepository clientProfiles, SessionAuthorizationRepository links, AuthSessionService sessions,
            UserAccountService users, ObjectProvider<TokenClaimsContributor> contributors, Clock clock) {
        return new Jacky917TokenCustomizer(audienceResolver, authorityResolver, clientProfiles, links, sessions, users,
                contributors.orderedStream().toList(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginSuccessHandler loginSuccessHandler(AuthSessionService sessions, UserAccountService users, Clock clock) {
        return new LoginSuccessHandler(sessions, users, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    LoginController jacky917LoginController(AuthorizationServerProperties properties,
                                            ObjectProvider<ClientRegistrationRepository> clientRegistrations) {
        return new LoginController(properties, clientRegistrations.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    PrincipalNormalizer principalNormalizer(UserAccountService users, Clock clock) {
        return new PrincipalNormalizer(users, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @DependsOnDatabaseInitialization
    FederatedIdentityService federatedIdentityService(JdbcClient jdbcClient, UserAccountService users,
                                                      PlatformTransactionManager transactionManager, Clock clock) {
        return new FederatedIdentityService(jdbcClient, users, new TransactionTemplate(transactionManager), clock);
    }

    /**
     * The fallback mapper for OpenID Connect providers such as Google.
     * Application mappers come first.
     * <p>
     * OpenID Connect 提供者（例如 Google）的預設 mapper；應用程式的 mapper 優先。
     *
     * @return the mapper
     *         <br>mapper
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    OidcFederatedUserInfoMapper oidcFederatedUserInfoMapper() {
        return new OidcFederatedUserInfoMapper();
    }

    @Bean
    @ConditionalOnMissingBean
    FederatedLoginSuccessHandler federatedLoginSuccessHandler(
            ObjectProvider<FederatedUserInfoMapper> mappers, FederatedIdentityService identities, UserAccountService users,
            AuthSessionService sessions, PrincipalNormalizer normalizer,
            ObjectProvider<OAuth2AuthorizedClientRepository> authorizedClients, Clock clock) {
        return new FederatedLoginSuccessHandler(mappers.orderedStream().toList(), identities, users, sessions, normalizer,
                authorizedClients.getIfAvailable(), clock);
    }
}
